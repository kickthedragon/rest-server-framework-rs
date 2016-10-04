//! This module is the oAuth interface for the rest api server

use std::io::Read;
use std::collections::HashMap;

use iron::prelude::*;
use iron::status;
use iron::headers::{Authorization, Basic};

use rand::{Rng, thread_rng};
use rustc_serialize::base64::{FromBase64, ToBase64, STANDARD};
use rustc_serialize::json;
use chrono::{Duration, DateTime, UTC, NaiveDateTime};
use dto::{TokenTypeDTO as TokenType, ScopeDTO as Scope, AccessTokenDTO, ResponseDTO,
          CreateClientDTO, ClientInfoDTO};

use DATABASES;
use utils::ENCRYPTION_CLIENT;
use error::Result;

/// Access Token Struct
#[derive(Clone, Debug)]
pub struct AccessToken {
    app_id: String,
    scopes: Vec<Scope>,
    token_type: TokenType,
    expiration: DateTime<UTC>,
}

impl AccessToken {
    /// Creates a new access token.
    pub fn new<S: AsRef<str>>(app_id: S,
                              scopes: &[Scope],
                              token_type: TokenType,
                              expiration: Duration)
                              -> AccessToken {
        AccessToken {
            app_id: String::from(app_id.as_ref()),
            scopes: Vec::from(scopes),
            token_type: token_type,
            expiration: UTC::now() + expiration,
        }
    }

    /// Returns the app id.
    pub fn get_app_id(&self) -> &str {
        &self.app_id
    }

    /// Returns the permissions of the token.
    pub fn get_scopes(&self) -> &Vec<Scope> {
        &self.scopes
    }

    /// Check if the token is an admin token.
    pub fn is_admin(&self) -> bool {
        self.scopes.contains(&Scope::Admin)
    }

    /// Check if the token is a public token.
    pub fn is_public(&self) -> bool {
        self.scopes.contains(&Scope::Public)
    }

    /// Check if the given user's token.
    pub fn is_user(&self, user_id: u64) -> bool {
        self.scopes.contains(&Scope::User(user_id))
    }

    /// Gets the user ID if the token is a user token.
    pub fn get_user_id(&self) -> Option<u64> {
        for scope in &self.scopes {
            match scope {
                &Scope::User(id) => return Some(id),
                _ => {}
            }
        }
        None
    }

    /// Returns the expiration time.
    pub fn get_expiration(&self) -> &DateTime<UTC> {
        &self.expiration
    }

    /// Returns wether the token has already expired or not.
    pub fn has_expired(&self) -> bool {
        self.expiration <= UTC::now()
    }

    /// returns a token from the stream and json.
    pub fn from_token<S: AsRef<str>>(token: S) -> Result<AccessToken> {
        let bytes = try!(ENCRYPTION_CLIENT.aes_decrypt(&try!(token.as_ref().from_base64())))
            .into_vec();
        let json = try!(String::from_utf8(bytes));
        let decoded: HashMap<String, String> = json::decode(&json).unwrap();
        let mut token = AccessToken {
            app_id: String::new(),
            scopes: Vec::new(),
            token_type: TokenType::Bearer,
            expiration: UTC::now(),
        };
        for (key, value) in decoded {
            match key.as_str() {
                "app_id" => token.app_id = value,
                "scopes" => token.scopes = json::decode(&value).unwrap(),
                "token_type" => {}
                "expiration" => {
                    token.expiration =
                        DateTime::from_utc(NaiveDateTime::from_timestamp(value.parse().unwrap(), 0),
                                           UTC)
                }
                _ => unreachable!(),
            }
        }

        Ok(token)
    }

    /// Converts the token into a DTO.
    pub fn into_dto(self) -> Result<AccessTokenDTO> {
        let mut enc_hm = HashMap::new();
        let _ = enc_hm.insert("app_id", self.app_id.clone());

        let scopes = json::encode(&self.scopes).unwrap();
        let _ = enc_hm.insert("scopes", scopes.clone());
        let _ = enc_hm.insert("token_type", format!("{}", self.token_type));
        let _ = enc_hm.insert("expiration", format!("{}", self.expiration.timestamp()));
        let json_to_encrypt = json::encode(&enc_hm).unwrap();
        let encrypted = try!(ENCRYPTION_CLIENT.aes_encrypt(&json_to_encrypt.into_bytes()));

        Ok(AccessTokenDTO {
            app_id: self.app_id,
            scopes: scopes,
            access_token: encrypted.to_base64(STANDARD),
            token_type: self.token_type,
            expiration: (self.expiration - UTC::now()).num_seconds(),
        })
    }
}

/// Gets the token for the provided client.
///
/// - Method: `GET`
/// - URL: `/token`
/// - Returns: the token, if the authentication was successful or an `Forbidden` status code if
///   it wasn't. It requires a valid `CLIENT-ID:CLIENT-SECRET` as an `Authentication<Basic>` header.
pub fn token(req: &mut Request) -> IronResult<Response> {
    let mut res = Response::new();
    match req.headers.get::<Authorization<Basic>>() {
        Some(basic) if basic.password.is_some() => {
            let db = thread_rng().choose(&DATABASES[..]).unwrap();
            match itry!(db.get_client(&basic.username)) {
                Some(ref client) if basic.password.as_ref().unwrap() ==
                                    &client.get_secret().to_base64(STANDARD) => {
                    let new_token = AccessToken::new(client.get_id(),
                                                     client.get_scopes(),
                                                     TokenType::Bearer,
                                                     Duration::seconds(28800));
                    let dto = itry!(new_token.into_dto());
                    let _ = res.set_mut(itry!(json::encode(&dto)))
                        .set_mut(status::Ok);
                }
                _ => {
                    let _ =
                        res.set_mut(json::encode(&ResponseDTO::new("unauthorized client or \
                                                                     secret"))
                                .unwrap())
                            .set_mut(status::Forbidden);
                }
            }
        }
        _ => {
            let _ = res.set_mut(status::BadRequest);
        }
    }

    Ok(res)
}

/// Creates a new OAuth client.
///
/// - Method: `POST`
/// - URL: `/create_client`
/// - Returns: the `ClientInfoDTO` object with information about the created client, if successful.
///
/// Requires an `Admin` scoped token.
pub fn create_client(req: &mut Request) -> IronResult<Response> {
    let token = get_token!(req);

    let mut res = Response::new();
    if !token.is_admin() {
        let _ = res.set_mut(json::encode(&ResponseDTO::new("unauthorized token")).unwrap())
            .set_mut(status::Forbidden);
        return Ok(res);
    }

    let mut body = String::new();
    let _ = itry!(req.body.read_to_string(&mut body));

    let dto = itry!(json::decode::<CreateClientDTO>(&body), status::BadRequest);

    let db = thread_rng().choose(&DATABASES[..]).unwrap();
    match db.create_developer_client(&dto.name, dto.scopes.as_slice(), dto.request_limit) {
        Ok((id, secret)) => {
            let res_dto = ClientInfoDTO {
                id: id,
                name: dto.name,
                secret: secret.to_base64(STANDARD),
                scopes: dto.scopes,
                request_limit: dto.request_limit,
            };
            let _ = res.set_mut(json::encode(&res_dto).unwrap()).set_mut(status::Ok);
        }
        Err(e) => {
            println!("Error: {:?}, file: {}, line: {}", e, file!(), line!());
            itry!(Err(e));
        }
    }

    Ok(res)
}
