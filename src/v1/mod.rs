//! The first version module of the API

use std::path::Path;

use iron::prelude::*;
use mount::Mount;
use router::Router;
use staticfile::Static;

use image;
use data_encoding::base32;
use qrcode::QrCode;

use error::Result;

#[macro_use]
pub mod macros;
pub mod oauth;
pub mod public;
pub mod user;

use self::oauth::*;
use self::public::*;
use self::user::*;

/// where the Qrcodes are stored
pub const QRCODES_PATH: &'static str = "qrcodes/";

/// Routes the server.
pub fn route_server() -> Iron<Mount> {
    let mut router = Router::new();

    // OAuth
    let _ = router.get("/v1/token", token)
                  .post("/v1/create_client", create_client)
                  // Public
                  .post("/v1/register", register)
                  .post("/v1/login", login)
                  .post("/v1/start_reset_password", start_reset_password)
                  .post("/v1/reset_password/:pass_key", reset_password)
                  .post("/v1/confirm_email/:email_key", confirm_email)
                  // User
                  .get("/v1/user/:user_id", get_user)
                  .post("/v1/update_user/:user_id", update_user)
                  .get("/v1/resend_email_confirmation", resend_email_confirmation)
                  .get("/v1/generate_authenticator_code", generate_authenticator_code)
                  .post("/v1/authenticate", authenticate);

    let mut mount = Mount::new();
    let _ = mount.mount("/", router)
        .mount("/qrcodes", Static::new(QRCODES_PATH));

    Iron::new(mount)
}

/// Creates the barcode for the given secret.
///
/// It will save it in the given path, and it will contain the TOTP data for the given email.
pub fn create_barcode<S: AsRef<str>, E: AsRef<str>, P: AsRef<Path>>(secret: S,
                                                                    user_email: E,
                                                                    path: P)
                                                                    -> Result<()> {
    let info = format!("otpauth://totp/{}?secret={}&issuer=%20Auth%20Example&digits=6&period=30",
                       user_email.as_ref(),
                       base32::encode(secret.as_ref().as_bytes()));
    let code = QrCode::new(info.as_bytes()).unwrap(); // TODO NO UNWRAP
    Ok(try!(code.render::<image::Rgba<u8>>().min_width(100).to_image().save(path)))
}
