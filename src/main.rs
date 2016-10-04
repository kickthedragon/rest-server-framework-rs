#![doc(html_logo_url = "",
       html_favicon_url = "",
       html_root_url = "")]
//! This is the an example rest api server framework that uses a redis database
//!
//!
//! To run without SSL support:
//!
//! ```text
//! cargo run --no-default-features
//! ```
//!
//! To run with SSL support:
//!
//! ```text
//! cargo run
//! ```
//!
//! A configuration file can be added, named `Config.toml` with all the required configuration
//! options, that can be seen in the [`config`](config/index.html) module.

// #![forbid(missing_docs, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused, unused_extern_crates,
        unused_import_braces, unused_qualifications, unused_results, variant_size_differences)]
#![warn(missing_docs)]

#[macro_use]
extern crate iron;
extern crate router;
extern crate staticfile;
extern crate mount;
#[macro_use]
extern crate lazy_static;
extern crate toml;
extern crate redis;
extern crate rustc_serialize;
extern crate rand;
extern crate chrono;
extern crate byteorder;
extern crate lettre;
extern crate crypto;
extern crate otpauth;
extern crate qrcode;
extern crate image;
extern crate data_encoding;

extern crate rest_api_data_utils as public_utils;
extern crate rest_api_data_types as dto;

use std::sync::{Arc, Mutex};
use std::{thread, fs};
use std::time::Duration;
use std::path::Path;

use lettre::transport::smtp::{SecurityLevel, SmtpTransportBuilder};
use lettre::transport::smtp::authentication::Mechanism;
use lettre::email::EmailBuilder;
use lettre::transport::EmailTransport;

pub mod config;
pub mod error;
pub mod utils;
pub mod database;
pub mod v1;

use v1::*;
use config::Config;
use utils::{EmailStruct, EmailType};
use database::Database;

const REDIS_URLS: [&'static str; 1] = ["redis://127.0.0.1/"];
const ENCRYPTION_SERVERS: [&'static str; 1] = ["127.0.0.1:33384"];

#[cfg(feature = "ssl")]
const WEB_URL: &'static str = "0.0.0.0:443";
#[cfg(not(feature = "ssl"))]
const WEB_URL: &'static str = "0.0.0.0:2323";

lazy_static! {
    static ref CONFIG: Config = Config::from_file().unwrap();
    static ref DATABASES: [Database; 1] = [
        Database::new(REDIS_URLS[0 % REDIS_URLS.len()]).unwrap()];
    static ref EMAILS: Arc<Mutex<Vec<EmailStruct>>> = Arc::new(Mutex::new(Vec::new()));
}

#[cfg(feature = "ssl")]
fn main() {
    let server = route_server();

    if !Path::new(QRCODES_PATH).exists() {
        fs::create_dir(QRCODES_PATH).unwrap();
    }

    let _ = thread::spawn(email_thread);
    let _ = thread::spawn(clear_qrcode_directory);

    println!("Server running at https://{}/", WEB_URL);
    let _ = server.https(WEB_URL, CONFIG.get_ssl_cert(), CONFIG.get_ssl_key()).unwrap();
}

#[cfg(not(feature = "ssl"))]
fn main() {
    let server = route_server();

    if !Path::new(QRCODES_PATH).exists() {
        fs::create_dir(QRCODES_PATH).unwrap();
    }

    let _ = thread::spawn(email_thread);
    let _ = thread::spawn(clear_qrcode_directory);

    println!("Server running at http://{}/", WEB_URL);
    let _ = server.http(WEB_URL).unwrap();
}

/// Sends the emails every minute
fn email_thread() {
    let mut mailer = SmtpTransportBuilder::new(("smtp.mymaildomain.com", 587))
        .unwrap()
        .hello_name("no-reply@mydomain.com")
        .credentials("no-reply@mydomain.com", "PASSWORD")
        .security_level(SecurityLevel::AlwaysEncrypt)
        .smtp_utf8(true)
        .authentication_mechanism(Mechanism::Plain)
        .connection_reuse(true)
        .build();

    loop {
        thread::sleep(Duration::from_secs(60));
        let mut ems = EMAILS.lock().unwrap();
        while let Some(email) = ems.pop() {

            let email_type = match email.email_type {
                EmailType::Email => "confirm_email",
                EmailType::Password => "reset_password",
            };

            let subject = match email.email_type {
                EmailType::Email => "Email Confirmation",
                EmailType::Password => "Password Reset",
            };

            let new_email = EmailBuilder::new()
                .to(email.email.as_str())
                .from("no-reply@mydomain.com")
                .body(&format!("http://my.domain.com/{}/{}", email_type, email.email_key))
                .subject(subject)
                .build()
                .unwrap();

            if let Err(e) = mailer.send(new_email) {
                println!("{:?}", e);
            }
        }
    }
}

/// Deletes the qrcodes in the qrcode directory
fn clear_qrcode_directory() {
    loop {
        thread::sleep(Duration::from_secs(10 * 60));

        match fs::read_dir(QRCODES_PATH) {
            Ok(dir) => {
                for entry in dir {
                    if let Ok(entry) = entry {
                        if let Ok(metadata) = entry.metadata() {
                            if let Ok(created) = metadata.created() {
                                if created.elapsed().unwrap().as_secs() > 60 * 60 {
                                    if let Err(e) = fs::remove_file(entry.path()) {
                                        println!("Error removing QR code: {:?}", e);
                                    }
                                }
                            }
                        }
                    }

                }
            }
            Err(e) => {
                println!("Error reading qrcode directory {:?}", e);
            }
        }
    }
}
