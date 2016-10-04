//! This module is the API interface for the redis database

use std::sync::{Arc, Mutex};

use redis::{Connection, Commands, IntoConnectionInfo, Client};

use error::{Error, Result};


pub mod oauth;
pub mod user;


pub use self::user::*;
pub use self::oauth::*;


/// Application's secret length.
pub const SECRET_LEN: usize = 20;

/// The TOTP secret length
pub const TOTP_SECRET_LEN: usize = 20;


/// The object used to handle our connection to the database
#[derive(Clone)]
pub struct Database {
    /// The inner actual database connection
    inner: Arc<Mutex<InnerDatabase>>,
}

/// The inner database object
struct InnerDatabase {
    /// The actual connection to the redis database
    connection: Connection,
}

///  Methods for creating a new databse connection object
impl Database {
    /// Creates a new database connection
    pub fn new<T: IntoConnectionInfo>(params: T) -> Result<Database> {
        let client = try!(Client::open(params));
        let connection = try!(client.get_connection());

        if !try!(connection.exists("next_user_id")) {
            try!(connection.set_nx("next_user_id", 0));
        }

        if !try!(connection.exists("next_client_id")) {
            try!(connection.set_nx("next_client_id", 0));
        }

        if !try!(connection.exists("next_transaction_id")) {
            try!(connection.set_nx("next_transaction_id", 0));
        }

        Ok(Database { inner: Arc::new(Mutex::new(InnerDatabase { connection: connection })) })
    }


    /// Sets the new request client request count
    fn set_request_count(&self, client_id: &str, count: u32) -> Result<()> {
        let key = format!("clients:{}", client_id);
        Ok(try!(self.inner.lock().unwrap().connection.hset(key, "request_count", count)))
    }

    /// Increments the user ID in the database
    fn increment_user_id(&self) -> Result<u64> {
        match self.inner.lock().unwrap().connection.incr("next_user_id", 1) {
            Ok(r) => Ok(r),
            Err(e) => Err(Error::from(e)),
        }
    }

    /// Increments the client ID in the database
    fn increment_client_id(&self) -> Result<u64> {
        match self.inner.lock().unwrap().connection.incr("next_client_id", 1) {
            Ok(r) => Ok(r),
            Err(e) => Err(Error::from(e)),
        }
    }
}
