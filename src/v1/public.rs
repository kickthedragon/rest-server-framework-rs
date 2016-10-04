//! This module is the public interface for the rest api server. It contains the login,
//! registration, start reset password, and reset password methods for iron to route to.
use iron::prelude::*;
use iron::status;
use std::io::Read;

use rand::{Rng, thread_rng};
use rustc_serialize::json;
use rustc_serialize::base64::{ToBase64, URL_SAFE};
use chrono::Duration;
use dto::{RegisterDTO, LoginDTO, ResetPasswordDTO, NewPasswordDTO, ResponseDTO, ScopeDTO as Scope,
          TokenTypeDTO as TokenType};

use {DATABASES, EMAILS, CONFIG};
use utils::{EmailStruct, EmailType};
use super::oauth::AccessToken;

/// Registers the given user.
///
/// - Method: `POST`
/// - URL: `/register`
/// - Scopes: `Public`
/// - Returns: a successfully registered response. If an error occurred, such as an already
///   existing username or email, an `Accepted` status code will be returned, with the error message
///   in a `ResponseDTO` object.
pub fn register(req: &mut Request) -> IronResult<Response> {
    let token = get_token!(req);

    let mut register_str = String::new();
    let _ = req.body.read_to_string(&mut register_str);
    let register = itry!(json::decode::<RegisterDTO>(&register_str),
                         status::BadRequest);

    let mut res = Response::new();

    if token.is_public() {
        let db = thread_rng().choose(&DATABASES[..]).unwrap();
        let user_exists = itry!(db.check_username_exists(&register.username));
        if user_exists {
            let _ =
                res.set_mut(json::encode(&ResponseDTO::new("user with that username already \
                                                             exists"))
                        .unwrap())
                    .set_mut(status::Accepted);
        } else {
            let email_exists = itry!(db.check_email_exists(&register.email));
            if email_exists {
                let _ = res.set_mut(json::encode(&ResponseDTO::new("user with that email already \
                                                             exists"))
                        .unwrap())
                    .set_mut(status::Accepted);
            } else {
                let mut email_key = [0u8; 5];
                thread_rng().fill_bytes(&mut email_key[0..]);
                let email_str = email_key.to_base64(URL_SAFE);
                let _ = itry!(db.create_user_simple(&register.username,
                                                    &register.password,
                                                    &register.email,
                                                    &email_str));
                let email = EmailStruct {
                    email: register.email,
                    email_key: email_str,
                    email_type: EmailType::Email,
                };
                EMAILS.lock().unwrap().push(email);
                let _ =
                    res.set_mut(json::encode(&ResponseDTO::new("successfully registered!"))
                            .unwrap())
                        .set_mut(status::Ok);
            }
        }
    } else {
        let _ =
            res.set_mut(json::encode(&ResponseDTO::new("token does not have correct \
                                                         permissions"))
                    .unwrap())
                .set_mut(status::Forbidden);
    }

    Ok(res)
}

/// Logs in the given user.
///
/// - Method: `POST`
/// - URL: `/login`
/// - Scopes: `Public`
/// - Returns: A `User` scoped token, for the logged in user if the user provided the succesful
///   credentials, or an `Accepted` status code if username/email or password were not correct.
///
/// It will return an `Accepted` response code if the user was successfully authenticated but a new
/// error was found, such a banned or disabled user. The `ResponseDTO` in the response body will
/// contain the error in the `message` parameter.
pub fn login(req: &mut Request) -> IronResult<Response> {
    let token = get_token!(req);
    let mut login_str = String::new();
    let _ = req.body.read_to_string(&mut login_str);
    let login = itry!(json::decode::<LoginDTO>(&login_str), status::BadRequest);
    let mut res = Response::new();
    if token.is_public() {
        let db = thread_rng().choose(&DATABASES[..]).unwrap();

        let user = if let Some(user) = itry!(db.get_user_by_email(&login.user_email)) {
            Some(user)
        } else if let Some(user) = itry!(db.get_user_by_username(&login.user_email)) {
            Some(user)
        } else {
            None
        };

        match user {
            Some(mut user) => {
                if user.is_banned() {
                    let _ =
                        res.set_mut(json::encode(&ResponseDTO::new(format!("user is banned \
                                                                             until {}",
                                                                            user.get_banned()
                                                                                .unwrap())))
                                .unwrap())
                            .set_mut(status::Accepted);
                } else if !user.is_enabled() {
                    let _ =
                        res.set_mut(json::encode(&ResponseDTO::new("user is disabled")).unwrap())
                            .set_mut(status::Accepted);
                } else {
                    let is_correct_pass = itry!(user.check_password(login.password));
                    if is_correct_pass {
                        let new_token = AccessToken::new(token.get_app_id(),
                                                         &[Scope::User(user.get_id())],
                                                         TokenType::Bearer,
                                                         if login.remember_me {
                                                             Duration::seconds(
                                                                 CONFIG.get_session_remember()
                                                                    .num_seconds())
                                                         } else {
                                                             Duration::seconds(60 * 60)
                                                         });
                        let token_result = itry!(new_token.into_dto());
                        let _ = user.set_last_activity_time();
                        let _ = res.set_mut(json::encode(&token_result).unwrap())
                            .set_mut(status::Ok);

                    } else {
                        let _ =
                            res.set_mut(json::encode(&ResponseDTO::new("incorrect username, \
                                                                         email or password"))
                                    .unwrap())
                                .set_mut(status::Accepted);
                    }
                }
            }
            None => {
                let _ = res.set_mut(json::encode(&ResponseDTO::new("incorrect username, email or \
                                                             password"))
                        .unwrap())
                    .set_mut(status::Accepted);
            }
        }

    } else {
        let _ =
            res.set_mut(json::encode(&ResponseDTO::new("token does not have correct \
                                                         permissions"))
                    .unwrap())
                .set_mut(status::Forbidden);
    }
    Ok(res)
}


/// Begins the reset password process.
///
/// - Method: `POST`
/// - URL: `/start_reset_password`
/// - Scopes: `Public`
/// - Returns: An `OK` status code if the reset was successfully started, or a `Forbidden` status
//    code if the token is not authorized or if the credentials were not correct. The `ResponseDTO`
///   in the response body will contain the error in the `message` parameter.
pub fn start_reset_password(req: &mut Request) -> IronResult<Response> {
    let token = get_token!(req);
    let mut start_reset_pass_str = String::new();
    let _ = req.body.read_to_string(&mut start_reset_pass_str);
    let start_reset_pass = itry!(json::decode::<ResetPasswordDTO>(&start_reset_pass_str),
                                 status::BadRequest);
    let mut res = Response::new();
    if token.is_public() {
        let db = thread_rng().choose(&DATABASES[..]).unwrap();
        let exists = itry!(db.check_username_exists(&start_reset_pass.username));
        if exists {
            let user = itry!(db.get_user_by_username(&start_reset_pass.username));
            match user {
                Some(user) => {
                    if user.get_email().to_lowercase() == start_reset_pass.email.to_lowercase() {
                        let mut reset_password_key = [0u8; 10];
                        thread_rng().fill_bytes(&mut reset_password_key[0..]);
                        let reset_password_str = reset_password_key.to_base64(URL_SAFE);
                        let email = EmailStruct {
                            email: start_reset_pass.email,
                            email_key: reset_password_str,
                            email_type: EmailType::Password,
                        };
                        EMAILS.lock().unwrap().push(email);
                        let _ = res.set_mut(json::encode(&ResponseDTO::new("began reset password \
                                                                     process"))
                                .unwrap())
                            .set_mut(status::Ok);
                    } else {
                        let _ = res.set_mut(json::encode(&ResponseDTO::new("incorrect username or \
                                                                     email"))
                                .unwrap())
                            .set_mut(status::Forbidden);
                    }
                }
                None => {
                    let _ =
                        res.set_mut(json::encode(&ResponseDTO::new("incorrect username or \
                                                                     email"))
                                .unwrap())
                            .set_mut(status::Forbidden);
                }
            }
        } else {
            let _ =
                res.set_mut(json::encode(&ResponseDTO::new("incorrect username or email"))
                        .unwrap())
                    .set_mut(status::Forbidden);
        }
    } else {
        let _ =
            res.set_mut(json::encode(&ResponseDTO::new("token does not have correct \
                                                         permissions"))
                    .unwrap())
                .set_mut(status::Forbidden);
    }
    Ok(res)
}

/// Resets the users password.
///
/// - Method: `POST`
/// - URL: `/reset_password/:pass_key`
/// - Scopes: `Public`
/// - Returns: A succesfful response, or failed response or unauthorized.
///
/// It requires a `Public` scoped token
pub fn reset_password(req: &mut Request) -> IronResult<Response> {
    let token = get_token!(req);

    let mut new_pass_str = String::new();
    let _ = req.body.read_to_string(&mut new_pass_str);
    let new_password = itry!(json::decode::<NewPasswordDTO>(&new_pass_str),
                             status::BadRequest);

    let mut res = Response::new();
    let pass_key = param!(req, "pass_key");

    if token.is_public() {
        let db = thread_rng().choose(&DATABASES[..]).unwrap();
        let _ = itry!(db.confirm_password_reset(pass_key, new_password.new_password));
        let _ =
            res.set_mut(json::encode(&ResponseDTO::new("successfully reset your password"))
                    .unwrap())
                .set_mut(status::Ok);
    } else {
        let _ =
            res.set_mut(json::encode(&ResponseDTO::new("token does not have correct \
                                                         permissions"))
                    .unwrap())
                .set_mut(status::Forbidden);
    }

    Ok(res)
}


/// Confirms the users email address
///
/// - Method: `POST`
/// - URL: `/confirm_email/:email_key`
/// - Scopes: `Public`
/// - Returns: A succesfful response, or failed response or unauthorized.
///
/// It requires a `Public` scoped token
pub fn confirm_email(req: &mut Request) -> IronResult<Response> {
    let token = get_token!(req);
    let mut res = Response::new();
    let email_key = param!(req, "email_key");

    if token.is_public() {
        let db = thread_rng().choose(&DATABASES[..]).unwrap();
        let _ = itry!(db.try_confirm_email(email_key));
        let _ =
            res.set_mut(json::encode(&ResponseDTO::new("successfully confirmed email")).unwrap())
                .set_mut(status::Ok);
    } else {
        let _ =
            res.set_mut(json::encode(&ResponseDTO::new("token does not have correct \
                                                         permissions"))
                    .unwrap())
                .set_mut(status::Forbidden);
    }
    Ok(res)
}
