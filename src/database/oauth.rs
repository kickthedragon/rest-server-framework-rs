//! This module is hold the methods and structs relatied to oAuth for the redis database

use super::{Database, SECRET_LEN};

use dto::ScopeDTO as Scope;

use std::collections::HashMap;

use rustc_serialize::json;

use redis::{FromRedisValue, Value, Commands};

use rand::{thread_rng, Rng};

use rustc_serialize::base64::{FromBase64, STANDARD, ToBase64};

use error::{Error, Result};

/// Methods working with oAuth
impl Database {
    /// Creates a Developer Client in the database
    pub fn create_developer_client<S: AsRef<str>>(&self,
                                                  name: S,
                                                  scopes: &[Scope],
                                                  request_limit: usize)
                                                  -> Result<(String, [u8; SECRET_LEN])> {
        // Check if this client alrady exists
        if let Ok(true) = self.check_client_exists_name(name.as_ref()) {
            return Err(Error::ClientExists);
        }

        let next_id = try!(self.increment_client_id());
        let id = format!("{}-{}",
                         next_id,
                         thread_rng().gen_ascii_chars().take(10).collect::<String>());
        let key = format!("clients:{}", &id);

        let scopes_str = if scopes.len() > 0 {
            json::encode(&scopes).unwrap()

        } else {
            return Err(Error::NoScopes);
        };

        let mut secret = [0u8; SECRET_LEN];
        thread_rng().fill_bytes(&mut secret[..]);

        let data = [("name", name.as_ref()),
                    ("scopes", scopes_str.as_str()),
                    ("secret", &secret.to_base64(STANDARD)),
                    ("request_count", "0"),
                    ("request_limit", &format!("{}", request_limit))];

        let db = self.inner.lock().unwrap();
        try!(db.connection.hset_multiple(&key, &data));
        try!(db.connection.hset_nx("clientkeys", name.as_ref(), next_id));
        Ok((id, secret))
    }

    /// Resets the request count for the client
    pub fn reset_request_count(&self, client_id: &str) -> Result<()> {
        let key = format!("clients:{}", client_id);
        Ok(try!(self.inner.lock().unwrap().connection.hset(key, "request_count", "0")))
    }


    /// Creates a developer barcode
    pub fn create_client_barcode(&self, id: u64, barcode: String) -> Result<()> {
        let key = format!("clients:{}:barcodes:{}", id, barcode);
        try!(self.inner.lock().unwrap().connection.set_ex(key, 0, 28800));
        Ok(())
    }

    /// Removes a developer barcode
    pub fn client_remove_barcode(&self, id: u64, barcode: String) -> Result<()> {
        let key = format!("clients:{}:barcodes:{}", id, barcode);
        Ok(try!(self.inner.lock().unwrap().connection.del(key)))
    }

    /// Checks if barcode exists
    pub fn client_barcode_exists(&self, id: u64, barcode: String) -> Result<bool> {
        let key = format!("clients:{}:barcodes:{}", id, barcode);
        Ok(try!(self.inner.lock().unwrap().connection.exists(key)))
    }


    /// Changes the clients secret
    pub fn change_client_secret<S: AsRef<str>>(&self, id: S, secret: &[u8]) -> Result<()> {
        let key = format!("clients:{}", id.as_ref());
        try!(self.inner.lock().unwrap().connection.hset(key, "secret", secret));
        Ok(())
    }

    /// Changes the clients name
    pub fn change_client_name(&self, id: u64, name: String) -> Result<()> {
        let key = format!("clients:{}", id);
        try!(self.inner.lock().unwrap().connection.hset(key, "name", name));
        Ok(())
    }

    /// Returns a client
    pub fn get_client<S: AsRef<str>>(&self, id: S) -> Result<Option<DeveloperClient>> {
        let key = format!("clients:{}", id.as_ref());
        let data: HashMap<String, Value> = try!(self.inner.lock().unwrap().connection.hgetall(key));
        if data.len() == 0 {
            Ok(None)
        } else {
            Ok(Some(try!(DeveloperClient::from_db_data(self.clone(), id, data))))
        }
    }

    /// Deletes the developer client
    pub fn delete_client(&self, client: &DeveloperClient) -> Result<()> {
        let key = format!("clients:{}", client.get_id());

        let db = self.inner.lock().unwrap();
        try!(db.connection.hdel("clientkeys", client.get_name().as_str()));
        Ok(try!(db.connection.del(key)))
    }

    /// Checks if the client exists by id
    pub fn check_client_exists_id(&self, id: u64) -> Result<bool> {
        let key = format!("clients:{}", id);
        Ok(try!(self.inner.lock().unwrap().connection.hexists(key, "name")))
    }

    /// Checks if the client exists by name
    pub fn check_client_exists_name(&self, name: &str) -> Result<bool> {
        Ok(try!(self.inner.lock().unwrap().connection.hexists("clientkeys", name)))
    }

    /// Gets the client ID by name
    pub fn get_client_id_by_name<S: AsRef<str>>(&self, name: S) -> Result<String> {
        match self.inner.lock().unwrap().connection.hget("clientkeys", name.as_ref()) {
            Ok(res) => Ok(res),
            Err(e) => Err(Error::from(e)),
        }
    }

    /// Returns all the client ids
    pub fn get_all_client_ids(&self) -> Result<Vec<String>> {
        let ids: Vec<String> = try!(self.inner.lock().unwrap().connection.hvals("clientkeys"));
        Ok(ids)
    }
}


/// Struct that holds the clients developer information
#[derive(Clone)]
pub struct DeveloperClient {
    database: Database,
    /// The unique id of the Client
    id: String,
    /// The unique secret of for the client
    secret: [u8; SECRET_LEN],
    /// The clients descriptive identifier
    name: String,
    /// The permissions the client has
    scopes: Vec<Scope>,
    /// The amount of requests done today
    request_count: u32,
    /// The limit of the requests allowed
    request_limit: u32,
}

impl DeveloperClient {
    /// Cretaes a developer client from the db data
    pub fn from_db_data<S: AsRef<str>>(database: Database,
                                       id: S,
                                       data: HashMap<String, Value>)
                                       -> Result<DeveloperClient> {

        let id = String::from(id.as_ref());
        let mut secret = String::new();
        let mut name = String::new();
        let mut scopes_str = String::new();
        let mut request_count = 0u32;
        let mut request_limit = 032;

        for (key, value) in data.iter() {
            match key.as_ref() {
                "name" => name = try!(String::from_redis_value(value)),
                "secret" => secret = try!(String::from_redis_value(value)),
                "scopes" => scopes_str = try!(String::from_redis_value(value)),
                "request_count" => request_count = try!(u32::from_redis_value(value)),
                "request_limit" => request_limit = try!(u32::from_redis_value(value)),
                _ => unreachable!(),
            }
        }

        let scopes: Vec<Scope> = json::decode(&scopes_str).unwrap();

        let mut secret_value = [0u8; SECRET_LEN];
        secret_value.clone_from_slice(secret.from_base64().unwrap().as_slice());

        Ok(DeveloperClient {
            database: database,
            id: id,
            secret: secret_value,
            name: name,
            scopes: scopes,
            request_count: request_count,
            request_limit: request_limit,
        })
    }

    /// Gets the client ID
    pub fn get_id(&self) -> &str {
        &self.id
    }

    /// Returns the permissions of the client
    pub fn get_scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// Gets the client name
    pub fn get_name(&self) -> &String {
        &self.name
    }

    /// Gets the client secret
    pub fn get_secret(&self) -> &[u8] {
        &self.secret
    }

    /// Sets the clients secret
    pub fn set_secret(&mut self, secret: &[u8]) -> Result<()> {
        try!(self.database.change_client_secret(self.get_id(), secret));
        let mut secret_value = [0u8; SECRET_LEN];
        secret_value.clone_from_slice(secret);
        self.secret = secret_value;
        Ok(())
    }

    /// Deletes the client
    pub fn delete(self) -> Result<()> {
        self.database.delete_client(&self)
    }

    /// Returns the request count
    pub fn get_request_count(&self) -> u32 {
        self.request_count
    }

    /// Increases the request count by one
    pub fn increment_request_count(&mut self) -> Result<(u32)> {
        if self.request_count + 1 > self.request_limit || self.request_limit != 0 {
            Err(Error::RequestLimitReached)
        } else {
            self.request_count += 1;
            try!(self.database.set_request_count(&self.id, self.request_count));
            Ok(self.request_count)
        }
    }

    /// Resets the request count
    pub fn reset_request_count(&mut self) -> Result<()> {
        try!(self.database.reset_request_count(&self.id));
        self.request_count = 0u32;
        Ok(())
    }
}
