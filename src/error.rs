//! This module is the error interface
//!
//! To use it include the following in your crate:
//!
//! ```
//! mod error;
//! ```
use std::convert::From;
use std::error::Error as StdErr;
use std::{io, fmt, str, string};
use std::result;


use redis::RedisError;
use rustc_serialize::base64;

/// Result Type.
pub type Result<T> = result::Result<T, Error>;

/// Error type.
#[derive(Debug)]
pub enum Error {
    /// Writing and Reading error
    IO(io::Error),
    /// String UTF8 parsing error
    StringUTF8(string::FromUtf8Error),
    /// Str UTF8 error
    StrUTF8(str::Utf8Error),
    /// Base 64 error
    Base64(base64::FromBase64Error),
    /// Redis database error
    Redis(RedisError),
    /// Password Check Error
    PasswordError(&'static str),
    /// Request error
    RequestError,
    /// Client Request limit reached
    RequestLimitReached,
    /// No scopes supplied for client
    NoScopes,
    /// Client does not exist
    ClientDoesNotExist,
    /// Connection Exists
    ConnectionExists,
    /// Client Already Exists
    ClientExists,
    /// Incorrect Key
    IncorrectKey,
    /// Failed to Create Png
    FailedCreatePNG,
    /// User does not exist
    UserDoesNotExist,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IO(err)
    }
}

impl From<RedisError> for Error {
    fn from(error: RedisError) -> Error {
        Error::Redis(error)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(err: string::FromUtf8Error) -> Error {
        Error::StringUTF8(err)
    }
}

impl From<str::Utf8Error> for Error {
    fn from(err: str::Utf8Error) -> Error {
        Error::StrUTF8(err)
    }
}

impl From<base64::FromBase64Error> for Error {
    fn from(err: base64::FromBase64Error) -> Error {
        Error::Base64(err)
    }
}

impl StdErr for Error {
    fn description(&self) -> &str {
        match *self {
            Error::IO(ref e) => e.description(),
            Error::StringUTF8(ref e) => e.description(),
            Error::StrUTF8(ref e) => e.description(),
            Error::Base64(ref e) => e.description(),
            Error::Redis(ref e) => e.description(),
            Error::PasswordError(ref e) => e,
            Error::RequestError => "the request did not return OK",
            Error::NoScopes => "No scopes were supplied to create the client",
            Error::RequestLimitReached => "The client reached his request limit",
            Error::ConnectionExists => "Connection already exists",
            Error::ClientDoesNotExist => "The client does not exist",
            Error::ClientExists => "This client already exists",
            Error::IncorrectKey => "Incorrect key",
            Error::FailedCreatePNG => "Failed to create png",
            Error::UserDoesNotExist => "User does not exist",
        }
    }

    fn cause(&self) -> Option<&StdErr> {
        match self {
            &Error::IO(ref e) => Some(e),
            &Error::StringUTF8(ref e) => Some(e),
            &Error::StrUTF8(ref e) => Some(e),
            &Error::Base64(ref e) => Some(e),
            &Error::Redis(ref e) => Some(e),
            _ => None,
        }
    }
}
