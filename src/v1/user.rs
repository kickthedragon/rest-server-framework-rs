//! User module.
use std::io::Read;

use iron::prelude::*;
use iron::status;

use rand::{thread_rng, Rng};
use rustc_serialize::json;
use rustc_serialize::base64::{ToBase64, URL_SAFE};
use dto::{AuthenticationCodeDTO, ResponseDTO, UpdateUserDTO, ScopeDTO as Scope, UserDTO};

use {DATABASES, EMAILS};
use super::{QRCODES_PATH, create_barcode};
use utils::{EmailStruct, EmailType};


/// Gets resends the email confirmation.
///
/// - Method: `GET`
/// - URL: `/resend_email_confirmation/`
/// - Returns: Successful response if it successfully sent the new email verification.
///
/// Requires `User` scoped token. It will take the id from the user scope and send an email to that
/// user.
pub fn resend_email_confirmation(req: &mut Request) -> IronResult<Response> {
    let token = get_token!(req);
    let mut res = Response::new();

    let mut user_id = None;
    for scope in token.get_scopes() {
        match scope {
            &Scope::User(id) => user_id = Some(id),
            _ => {}
        }
    }

    if let Some(user_id) = user_id {
        let db = thread_rng().choose(&DATABASES[..]).unwrap();
        let mut email_key = [0u8; 5];
        thread_rng().fill_bytes(&mut email_key[0..]);
        let email_str = email_key.to_base64(URL_SAFE);
        let _ = itry!(db.start_confirm_email(user_id, &email_str));
        if let Some(user) = itry!(db.get_user_by_id(user_id)) {
            let email = EmailStruct {
                email: String::from(user.get_email()),
                email_key: email_str,
                email_type: EmailType::Email,
            };
            EMAILS.lock().unwrap().push(email);
            let _ =
                res.set_mut(json::encode(&ResponseDTO::new("successfully resent confirmation \
                                                             email"))
                        .unwrap())
                    .set_mut(status::Ok);
        } else {
            let _ = res.set_mut(json::encode(&ResponseDTO::new("the user was deleted")).unwrap())
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

/// Authenticates the user with two factor authentication.
///
/// - Method: `POST`
/// - URL: `/authenticate
/// - Scopes: `User`
/// - Returns: a successfully response. If the user posts the correct code within the given 30 sec
///   time frame using TOTP
pub fn authenticate(req: &mut Request) -> IronResult<Response> {
    let token = get_token!(req);
    let mut user_id = None;
    for scope in token.get_scopes() {
        match scope {
            &Scope::User(id) => user_id = Some(id),
            _ => {}
        }
    }
    let mut res = Response::new();
    if let Some(user_id) = user_id {
        let mut authentication_str = String::new();
        let _ = req.body.read_to_string(&mut authentication_str);
        let code_dto = itry!(json::decode::<AuthenticationCodeDTO>(&authentication_str),
                             status::BadRequest);

        let db = thread_rng().choose(&DATABASES[..]).unwrap();

        if let Some(user) = itry!(db.get_user_by_id(user_id)) {
            if user.check_authenticator_code(code_dto.code) {

                let _ = res.set_mut(json::encode(&ResponseDTO::new("successfully authenticated"))
                        .unwrap())
                    .set_mut(status::Ok);
            } else {
                let _ =
                    res.set_mut(json::encode(&ResponseDTO::new("Unsuccessful authentication \
                                                                 code"))
                            .unwrap())
                        .set_mut(status::Accepted);
            }
        } else {
            let _ = res.set_mut(json::encode(&ResponseDTO::new("the user was deleted")).unwrap())
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


/// Gets the authenticator QR code.
///
/// - Method: `GET`
/// - URL: `/generate_authenticator_code
/// - Returns: URL to the QR code.
///
/// Requires `User` scoped token. It will take the id from the user scope and send an email to that
/// user.
pub fn generate_authenticator_code(req: &mut Request) -> IronResult<Response> {
    let token = get_token!(req);
    let mut user_id = None;
    for scope in token.get_scopes() {
        match scope {
            &Scope::User(id) => user_id = Some(id),
            _ => {}
        }
    }
    let mut res = Response::new();
    if let Some(user_id) = user_id {
        let db = thread_rng().choose(&DATABASES[..]).unwrap();
        if let Some(mut user) = itry!(db.get_user_by_id(user_id)) {
            let secret = itry!(user.get_authenticator_secret());
            let _ = itry!(create_barcode(&secret,
                                         user.get_email(),
                                         format!("{}{}.png", QRCODES_PATH, &secret[..10])));
            let _ = res.set_mut(json::encode(&ResponseDTO::new(format!("http://www.mydomain.\
                                                                 com/qrcodes/{}.png",
                                                                &secret[..10])))
                    .unwrap())
                .set_mut(status::Ok);
        } else {
            let _ = res.set_mut(json::encode(&ResponseDTO::new("the user was deleted")).unwrap())
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

/// Gets the given user.
///
/// - Method: `GET`
/// - URL: `/user/:user_id`
/// - Scopes: `Admin`, `User`
/// - Returns: the `UserDTO` object with all the information about the user if successful, or an
///   `Accepted` status code with the error response if the user does not exist.
///
/// In the case of using a `User` token, it will need to have the same ID as the user being
/// requested.
pub fn get_user(req: &mut Request) -> IronResult<Response> {
    let token = get_token!(req);
    let user_id = itry!(param!(req, "user_id").parse::<u64>(), status::BadRequest);

    let mut res = Response::new();
    if !token.is_admin() && !token.is_user(user_id) {
        let _ = res.set_mut(json::encode(&ResponseDTO::new("unauthorized scope")).unwrap())
            .set_mut(status::Forbidden);
        return Ok(res);
    }

    let db = thread_rng().choose(&DATABASES[..]).unwrap();
    match db.get_user_by_id(user_id) {
        Ok(Some(user)) => {
            let _ = res.set_mut(json::encode::<UserDTO>(&user.into()).unwrap()).set_mut(status::Ok);
        }
        Ok(None) => {
            let _ = res.set_mut(json::encode(&ResponseDTO::new("deleted user")).unwrap())
                .set_mut(status::Accepted);
            return Ok(res);
        }
        Err(e) => {
            println!("Error: {:?}, file: {}, line: {}", e, file!(), line!());
            itry!(Err(e));
        }
    }

    Ok(res)
}

/// Gets all users in the database.
///
/// - Method: `GET`
/// - URL: `/all_users`
/// - Scopes: `Admin`
/// - Returns: a list of `UserDTO` objects with all the information about the users if successful.
pub fn get_all_users(req: &mut Request) -> IronResult<Response> {
    let token = get_token!(req);

    let mut res = Response::new();
    if !token.is_admin() {
        let _ = res.set_mut(json::encode(&ResponseDTO::new("unauthorized scope")).unwrap())
            .set_mut(status::Forbidden);
        return Ok(res);
    }

    let db = thread_rng().choose(&DATABASES[..]).unwrap();
    let users = match db.get_all_user_ids() {
        Ok(ids) => {
            ids.into_iter()
                .filter_map(|id| match db.get_user_by_id(id) {
                    Ok(Some(user)) => Some(user.into()),
                    Ok(None) => None,
                    Err(e) => {
                        println!("Error: {:?}, file: {}, line: {}", e, file!(), line!());
                        None
                    }
                })
                .collect::<Vec<UserDTO>>()
        }
        Err(e) => {
            println!("Error: {:?}, file: {}, line: {}", e, file!(), line!());
            return itry!(Err(e));
        }
    };

    let _ = res.set_mut(json::encode(&users).unwrap()).set_mut(status::Ok);

    Ok(res)
}

/// Deletes the given user from the database.
///
/// - Method: `DELETE`
/// - URL: `/user/:user_id`
/// - Scopes: `Admin`
/// - Returns: an `OK` status code if the removal is successful, or a `NotFound` status code if the
///   a user with the given ID was not found.
pub fn delete_user(req: &mut Request) -> IronResult<Response> {
    let token = get_token!(req);
    let mut res = Response::new();
    if !token.is_admin() {
        let _ = res.set_mut(json::encode(&ResponseDTO::new("unauthorized scope")).unwrap())
            .set_mut(status::Forbidden);
        return Ok(res);
    }

    let user_id = itry!(param!(req, "user_id").parse::<u64>(), status::BadRequest);

    let db = thread_rng().choose(&DATABASES[..]).unwrap();
    match db.get_user_by_id(user_id) {
        Ok(Some(user)) => {
            match user.delete() {
                Ok(_) => {
                    let _ = res.set_mut(json::encode(&ResponseDTO::new("user deleted")).unwrap())
                        .set_mut(status::Ok);
                }
                Err(e) => {
                    println!("Error: {:?}, file: {}, line: {}", e, file!(), line!());
                    itry!(Err(e));
                }
            }
        }
        Ok(None) => {
            let _ = res.set_mut(json::encode(&ResponseDTO::new("user not found")).unwrap())
                .set_mut(status::NotFound);
        }
        Err(e) => {
            println!("Error: {:?}, file: {}, line: {}", e, file!(), line!());
            itry!(Err(e));
        }
    }

    Ok(res)
}

/// Updates the given user with the provided information
///
/// - Method: `POST`
/// - URL: `/update_user/:user_id`
/// - Scopes: `Admin`, `User`
/// - Returns: an `OK` status code if the removal is successful.
pub fn update_user(req: &mut Request) -> IronResult<Response> {
    let token = get_token!(req);
    let user_id = itry!(param!(req, "user_id").parse::<u64>(), status::BadRequest);
    let mut res = Response::new();
    if !token.is_admin() && !token.is_user(user_id) {
        let _ = res.set_mut(json::encode(&ResponseDTO::new("unauthorized scope")).unwrap())
            .set_mut(status::Forbidden);
        return Ok(res);
    }

    let mut body = String::new();
    let _ = itry!(req.body.read_to_string(&mut body));

    let dto = itry!(json::decode::<UpdateUserDTO>(&body), status::BadRequest);
    let db = thread_rng().choose(&DATABASES[..]).unwrap();
    match db.get_user_by_id(user_id) {
        Ok(Some(mut user)) => {
            let _ =
                res.set_mut(json::encode(&ResponseDTO::new("succesffuly updated user")).unwrap())
                    .set_mut(status::Ok);
            if let Some(new_username) = dto.new_username {
                if itry!(db.check_username_exists(&new_username)) {
                    if user.get_username().to_lowercase() != new_username.to_lowercase() {
                        let _ = res.set_mut(json::encode(&ResponseDTO::new(" a user with that \
                                                                     username already exists"))
                                .unwrap())
                            .set_mut(status::Accepted);
                    } else {
                        itry!(user.set_username(new_username));
                    }
                } else {
                    itry!(user.set_username(new_username));
                }

            }
            if let Some(new_password) = dto.new_password {
                if !token.is_admin() && dto.old_password.is_some() &&
                   itry!(user.check_password(dto.old_password.unwrap())) {
                    itry!(user.set_password(new_password));
                }
            }
            if let Some(new_first) = dto.new_first {
                if !user.is_first_name_confirmed() || token.is_admin() {
                    itry!(user.set_first_name(new_first));
                } else {
                    let _ = res.set_mut(json::encode(&ResponseDTO::new("users cannot change an \
                                                                 already confirmed first name, \
                                                                 please contact support if the \
                                                                 change is needed"))
                            .unwrap())
                        .set_mut(status::Accepted);
                    return Ok(res);
                }
            }
            if let Some(new_last) = dto.new_last {
                if !user.is_last_name_confirmed() || token.is_admin() {
                    itry!(user.set_last_name(new_last));
                } else {
                    let _ = res.set_mut(json::encode(&ResponseDTO::new("users cannot change an \
                                                                 already confirmed last name, \
                                                                 please contact support if the \
                                                                 change is needed"))
                            .unwrap())
                        .set_mut(status::Accepted);
                    return Ok(res);
                }
            }
            if let Some(new_address) = dto.new_address {
                itry!(user.set_address(Some(new_address)));
            }
            if let Some(new_birthday) = dto.new_birthday {
                if !user.is_birthday_confirmed() || token.is_admin() {
                    itry!(user.set_birthday(Some(new_birthday)));
                } else {
                    let _ = res.set_mut(json::encode(&ResponseDTO::new("users cannot change an \
                                                                 already confirmed birthday, \
                                                                 please contact support if the \
                                                                 change is needed"))
                            .unwrap())
                        .set_mut(status::Accepted);
                    return Ok(res);
                }
            }
            if let Some(new_phone) = dto.new_phone {
                itry!(user.set_phone(Some(new_phone)));
            }
            if let Some(new_email) = dto.new_email {
                if itry!(db.check_email_exists(new_email.to_lowercase())) {
                    let _ =
                        res.set_mut(json::encode(&ResponseDTO::new("user with that email \
                                                                     already exists"))
                                .unwrap())
                            .set_mut(status::Accepted);
                } else {
                    itry!(user.set_email(&new_email));
                    let db = thread_rng().choose(&DATABASES[..]).unwrap();
                    let mut email_key = [0u8; 5];
                    thread_rng().fill_bytes(&mut email_key[0..]);
                    let email_str = email_key.to_base64(URL_SAFE);
                    let _ = itry!(db.start_confirm_email(user_id, &email_str));
                    let email = EmailStruct {
                        email: new_email,
                        email_key: email_str,
                        email_type: EmailType::Email,
                    };
                    EMAILS.lock().unwrap().push(email);
                }
            }
            if let Some(new_image) = dto.new_image {
                itry!(user.set_image(Some(new_image)));
            }
        }
        Ok(None) => {}
        Err(e) => {
            println!("Error: {:?}, file: {}, line: {}", e, file!(), line!());
            itry!(Err(e));
        }
    }

    Ok(res)
}
