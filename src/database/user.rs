//! This module is hold the methods and structs relatied to users in the redis database

use std::collections::HashMap;
use std::{fmt, u8};


use chrono::{DateTime, UTC, NaiveDateTime, NaiveDate};
use rand::{thread_rng, Rng};
use crypto::pbkdf2;
use otpauth::TOTP;
use redis::{FromRedisValue, Value, Commands};

use dto::{UserDTO, ProfileDTO};
use public_utils::Address;

use error::{Error, Result};
use super::{Database, TOTP_SECRET_LEN};

/// Methods working with user
impl Database {
    /// Creates a user in the database with just username, password and email and returns the id
    pub fn create_user_simple<S: AsRef<str>>(&self,
                                             username: S,
                                             password: S,
                                             email: S,
                                             email_key: S)
                                             -> Result<u64> {


        // Create the user in the 'users' hashTable
        let id = try!(self.increment_user_id());
        let key = format!("users:{}", id);
        let verify_email_key = format!("verify_emails:{}", email_key.as_ref());
        let hash = pbkdf2::pbkdf2_simple(password.as_ref(), 5).unwrap();
        let name_lowercase = username.as_ref().to_lowercase();
        let email_lowercase = email.as_ref().to_lowercase();
        let authenticator_data =
            thread_rng().gen_ascii_chars().take(TOTP_SECRET_LEN).collect::<String>();

        let user_data = [("username", name_lowercase.as_str()),
                         ("password", hash.as_ref()),
                         ("display_name", username.as_ref()),
                         ("first_name", ""),
                         ("first_name_confirmed", "0"),
                         ("last_name", ""),
                         ("last_name_confirmed", "0"),
                         ("email", email_lowercase.as_str()),
                         ("email_confirmed", "0"),
                         ("birthday_confirmed", "0"),
                         ("authenticator_secret", authenticator_data.as_str()),
                         ("address_confirmed", "0"),
                         ("phone_confirmed", "0"),
                         ("image_url", ""),
                         ("enabled", "1"),
                         ("registration_time", &format!("{}", UTC::now().timestamp())),
                         ("last_activity", &format!("{}", UTC::now().timestamp())),
                         ("banned", "")];


        // TODO: if something fails, delete what has been created before returning Result
        {
            let db = self.inner.lock().unwrap();
            try!(db.connection.hset_nx("userkeys", name_lowercase.as_str(), id));
            try!(db.connection.hset_nx("emailkeys", email_lowercase.as_str(), id));
            try!(db.connection.set_ex(verify_email_key, id, 60 * 60 * 24));
            try!(db.connection.hset_multiple(key.as_str(), &user_data));
        }
        Ok(id)
    }

    /// Creates a user in the database and returns the ID
    pub fn create_user<S: AsRef<str>>(&self,
                                      username: S,
                                      password: S,
                                      email: S,
                                      first: Option<String>,
                                      last: Option<String>,
                                      birthday: Option<NaiveDate>,
                                      phone: Option<String>,
                                      image: Option<String>,
                                      address: Option<Address>,
                                      email_key: S)
                                      -> Result<u64> {


        // Create the user in the 'users' hashTable
        let id = try!(self.increment_user_id());
        let key = format!("users:{}", id);

        let verify_email_key = format!("verify_emails:{}", email_key.as_ref());

        let hash = pbkdf2::pbkdf2_simple(password.as_ref(), 5).unwrap();

        let name_lowercase = username.as_ref().to_lowercase();

        let email_lowercase = email.as_ref().to_lowercase();

        let first_name = match first {
            Some(name) => name,
            None => String::from(""),
        };

        let last_name = match last {
            Some(name) => name,
            None => String::from(""),
        };

        let phone_data = match phone {
            Some(a) => a,
            None => String::from(""),
        };


        let dob_data = match birthday {
            Some(a) => format!("{:?}", a),
            None => String::from(""),
        };

        let image_data = match image {
            Some(a) => a,
            None => String::from(""),
        };

        let user_data = [("username", name_lowercase.as_str()),
                         ("password", hash.as_str()),
                         ("display_name", username.as_ref()),
                         ("first_name", first_name.as_str()),
                         ("first_name_confirmed", "0"),
                         ("last_name", last_name.as_str()),
                         ("last_name_confirmed", "0"),
                         ("email", email_lowercase.as_str()),
                         ("email_confirmed", "0"),
                         ("birthday", dob_data.as_str()),
                         ("birthday_confirmed", "0"),
                         ("address_confirmed", "0"),
                         ("phone", phone_data.as_str()),
                         ("phone_confirmed", "0"),
                         ("image_url", image_data.as_str()),
                         ("enabled", "1"),
                         ("registration_time", &format!("{}", UTC::now().timestamp())),
                         ("last_activity", &format!("{}", UTC::now().timestamp())),
                         ("banned", "")];

        // Link the username to the user_id in the 'userkeys' hashSet

        // TODO: if something fails, delete what has been created before returning Result
        {
            let db = self.inner.lock().unwrap();
            try!(db.connection.hset_nx("userkeys", name_lowercase.as_str(), id));
            try!(db.connection.hset_nx("emailkeys", email_lowercase.as_str(), id));
            try!(db.connection.hset_multiple(key.as_str(), &user_data));
            try!(db.connection.set_ex(verify_email_key, id, 60 * 60 * 24));
        }
        try!(self.set_user_address(id, address.as_ref()));
        Ok(id)
    }

    /// Sets the users first name
    fn set_user_first_name<S: AsRef<str>>(&self, user_id: u64, name: S) -> Result<()> {
        let key = format!("users:{}", user_id);
        let data = [("first_name", name.as_ref()), ("first_name_confirmed", "0")];
        try!(self.inner.lock().unwrap().connection.hset_multiple(key, &data));
        Ok(())
    }

    /// Sets the users last name
    fn set_user_last_name<S: AsRef<str>>(&self, user_id: u64, name: S) -> Result<()> {
        let key = format!("users:{}", user_id);
        let data = [("last_name", name.as_ref()), ("last_name_confirmed", "0")];
        try!(self.inner.lock().unwrap().connection.hset_multiple(key, &data));
        Ok(())
    }

    /// Creates a new authenticator secret, stores it in the database, and returns it
    fn create_new_user_authenticator_secret(&self, user_id: u64) -> Result<String> {
        let key = format!("users:{}", user_id);
        let secret = thread_rng().gen_ascii_chars().take(TOTP_SECRET_LEN).collect::<String>();
        try!(self.inner.lock().unwrap().connection.hset(key, "authenticator_secret", &secret));
        Ok(secret)
    }

    /// Sets the users last activity time
    fn set_last_activity_time(&self, user_id: u64) -> Result<()> {
        let key = format!("users:{}", user_id);
        try!(self.inner
            .lock()
            .unwrap()
            .connection
            .hset(key, "last_activity", UTC::now().timestamp()));
        Ok(())
    }

    /// Bannes the user until the provided date
    fn ban_user(&self, user_id: u64, until: DateTime<UTC>) -> Result<()> {
        let key = format!("users:{}", user_id);
        let data = [("enabled", format!("{}", 0)), ("banned", format!("{}", until.timestamp()))];
        try!(self.inner.lock().unwrap().connection.hset_multiple(key, &data));
        Ok(())
    }

    /// Starts to reset the users password
    fn start_reset_password<S: AsRef<str>>(&self, user_id: u64, password_key: S) -> Result<()> {
        let reset_password_key = format!("reset_passwords:{}", password_key.as_ref());
        try!(self.inner
            .lock()
            .unwrap()
            .connection
            .set_ex(reset_password_key, user_id, 60 * 60 * 24));
        Ok(())
    }

    /// Start confirm email address
    pub fn start_confirm_email<S: AsRef<str>>(&self, user_id: u64, email_key: S) -> Result<()> {
        let verify_email_key = format!("verify_emails:{}", email_key.as_ref());
        try!(self.inner
            .lock()
            .unwrap()
            .connection
            .set_ex(verify_email_key, user_id, 60 * 60 * 24 * 7));
        Ok(())
    }

    /// Confirms the password reset
    pub fn confirm_password_reset<S: AsRef<str>>(&self,
                                                 password_key: S,
                                                 new_password: S)
                                                 -> Result<()> {
        let reset_password_key = format!("reset_passwords:{}", password_key.as_ref());
        let id_opt: Option<u64> =
            try!(self.inner.lock().unwrap().connection.get(&reset_password_key));
        match id_opt {
            Some(id) => {
                let mut user = try!(self.get_user_by_id(id)).unwrap();
                try!(self.inner.lock().unwrap().connection.del(reset_password_key));
                user.set_password(new_password.as_ref())
            }
            None => Err(Error::IncorrectKey),
        }
    }

    /// trys to confirms the users email
    pub fn try_confirm_email<S: AsRef<str>>(&self, email_key: S) -> Result<()> {
        let verify_email_key = format!("verify_emails:{}", email_key.as_ref());
        let id_opt: Option<u64> =
            try!(self.inner.lock().unwrap().connection.get(&verify_email_key));
        match id_opt {
            Some(id) => {
                let user = try!(self.get_user_by_id(id));
                if user.is_some() {
                    try!(self.inner.lock().unwrap().connection.del(verify_email_key));
                    user.unwrap().confirm_email()
                } else {
                    Err(Error::UserDoesNotExist)
                }
            }
            None => Err(Error::IncorrectKey),
        }
    }

    /// Confirms the users email
    fn confrim_email(&self, user_id: u64) -> Result<()> {
        let key = format!("users:{}", user_id);
        Ok(try!(self.inner.lock().unwrap().connection.hset(key, "email_confirmed", "1")))
    }

    /// Enables the given user
    fn enable_user(&self, user_id: u64) -> Result<()> {
        let key = format!("users:{}", user_id);
        try!(self.inner.lock().unwrap().connection.hset(key, "enabled", "1"));
        Ok(())
    }

    /// Disables the given user
    fn disable_user(&self, user_id: u64) -> Result<()> {
        let key = format!("users:{}", user_id);
        try!(self.inner.lock().unwrap().connection.hset(key, "enabled", "0"));
        Ok(())
    }

    /// Sets a user address in the database
    fn set_user_address(&self, user_id: u64, address: Option<&Address>) -> Result<()> {
        let key = format!("users:{}:addr", user_id);

        match address {
            Some(addr) => {
                let data = [("address1", addr.get_address1()),
                            ("address2",
                             match addr.get_address2() {
                                Some(a) => a,
                                None => "",
                            }),
                            ("city", addr.get_city()),
                            ("state", addr.get_state()),
                            ("zip", addr.get_zip()),
                            ("country", addr.get_country())];

                try!(self.inner.lock().unwrap().connection.hset_multiple(key, &data));
            }
            None => try!(self.delete_address(user_id)),
        };
        Ok(())
    }

    /// Deletes a user address in the database
    fn delete_address(&self, user_id: u64) -> Result<()> {
        let key = format!("users:{}:addr", user_id);
        Ok(try!(self.inner.lock().unwrap().connection.del(key)))
    }



    /// Sets the users profile image in the database
    fn set_user_image<S: AsRef<str>>(&self, user_id: u64, image: Option<S>) -> Result<()> {
        let key = format!("users:{}", user_id);

        let img = match image {
            Some(a) => a.as_ref().to_owned(),
            None => String::from(""),
        };

        try!(self.inner.lock().unwrap().connection.hset(key, "image_url", img.as_str()));
        Ok(())
    }

    /// Sets the users birthday
    fn set_user_birthday(&self, user_id: u64, date: Option<NaiveDate>) -> Result<()> {
        let key = format!("users:{}", user_id);
        match date {
            Some(d) => {
                let data = [("birthday", format!("{}", d)),
                            ("birthday_confirmed", String::from("0"))];
                try!(self.inner.lock().unwrap().connection.hset_multiple(key, &data));
            }
            None => {
                let data = [("birthday", String::from("")),
                            ("birthday_confirmed", String::from("0"))];
                try!(self.inner.lock().unwrap().connection.hset_multiple(key, &data));
            }
        }
        Ok(())
    }

    /// Sets the user password in the database
    fn set_user_password<S: AsRef<str>>(&self, user_id: u64, pass: S) -> Result<()> {
        let key = format!("users:{}", user_id);
        try!(self.inner.lock().unwrap().connection.hset(key, "password", pass.as_ref()));
        Ok(())
    }

    /// Sets the users phone number in the database
    fn set_user_phone<S: AsRef<str>>(&self, user_id: u64, phone: Option<S>) -> Result<()> {
        let key = format!("users:{}", user_id);

        let ph = match phone {
            Some(a) => a.as_ref().to_owned(),
            None => String::from(""),
        };

        let data = [("phone", ph.as_str()), ("phone_confirmed", "0")];
        try!(self.inner.lock().unwrap().connection.hset_multiple(key, &data));
        Ok(())
    }

    /// Sets the users email in the database
    fn set_user_email<S: AsRef<str>>(&self,
                                     user_id: u64,
                                     old_email: S,
                                     new_email: S)
                                     -> Result<()> {
        let key = format!("users:{}", user_id);
        let data = [("email", new_email.as_ref().to_lowercase()),
                    ("email_confirmed", String::from("0"))];
        {
            let db = self.inner.lock().unwrap();
            try!(db.connection.hset_multiple(key, &data));
            try!(db.connection.hset("emailkeys", new_email.as_ref().to_lowercase(), user_id));
            try!(db.connection.hdel("emailkeys", old_email.as_ref().to_lowercase()));
        }
        Ok(())
    }

    /// Changes the users username in the database
    fn set_username<S: AsRef<str>>(&self,
                                   user_id: u64,
                                   old_username: S,
                                   new_username: S)
                                   -> Result<()> {
        let key = format!("users:{}", user_id);

        let data = [("username", new_username.as_ref().to_lowercase()),
                    ("display_name", String::from(new_username.as_ref()))];
        {
            let db = self.inner.lock().unwrap();
            try!(db.connection.hset_multiple(key, &data));
            try!(db.connection.hset("userkeys", new_username.as_ref().to_lowercase(), user_id));
            try!(db.connection.hdel("userkeys", old_username.as_ref().to_lowercase()));
        }
        Ok(())
    }

    /// Deletes a user from the database
    fn delete_user(&self, user: &User) -> Result<()> {
        let key = format!("users:{}", user.get_id());
        let sign_key = format!("users:{}:sign_keys", user.get_id());
        let enc_key = format!("users:{}:enc_keys", user.get_id());
        let addr_key = format!("users:{}:addr", user.get_id());
        // let wallet_key = format!("users:{}:wallet_addresses", user.get_id());
        {
            let db = self.inner.lock().unwrap();
            try!(db.connection.del(key));
            try!(db.connection.del(sign_key));
            try!(db.connection.del(enc_key));
            try!(db.connection.del(addr_key));
        }


        Ok(try!(self.inner
            .lock()
            .unwrap()
            .connection
            .hdel("userkeys", user.get_username().to_lowercase())))
    }

    /// Checks if a user exists in the database
    pub fn check_user_exists(&self, id: u64) -> Result<bool> {
        let key = format!("users:{}", id);
        Ok(try!(self.inner.lock().unwrap().connection.hexists(key, "username")))
    }

    /// Checks if a user with a given username already exists
    pub fn check_username_exists<S: AsRef<str>>(&self, username: S) -> Result<bool> {
        Ok(try!(self.inner
            .lock()
            .unwrap()
            .connection
            .hexists("userkeys", username.as_ref().to_lowercase())))
    }

    /// Checks if a user with a given username already exists
    pub fn check_email_exists<S: AsRef<str>>(&self, email: S) -> Result<bool> {
        Ok(try!(self.inner
            .lock()
            .unwrap()
            .connection
            .hexists("emailkeys", email.as_ref().to_lowercase())))
    }

    /// Returns the user based on email
    pub fn get_user_by_email<S: AsRef<str>>(&self, email: S) -> Result<Option<User>> {
        if !email.as_ref().contains('@') {
            return Ok(None);
        }
        Ok(match try!(self.get_user_id_by_email(email)) {
            Some(id) => try!(self.get_user_by_id(id)),
            None => None,
        })
    }

    /// Returns the user id based on the email
    fn get_user_id_by_email<S: AsRef<str>>(&self, email: S) -> Result<Option<u64>> {
        use redis::ErrorKind;
        match self.inner
            .lock()
            .unwrap()
            .connection
            .hget("emailkeys", email.as_ref().to_lowercase()) {
            Ok(id) => Ok(Some(id)),
            Err(ref e) if e.kind() == ErrorKind::TypeError => Ok(None),
            Err(e) => {
                println!("{:?}", e);
                Err(e.into())
            }
        }
    }

    /// Returns the user based on username
    pub fn get_user_by_username<S: AsRef<str>>(&self, username: S) -> Result<Option<User>> {
        Ok(match try!(self.get_user_id_by_username(username)) {
            Some(id) => try!(self.get_user_by_id(id)),
            None => None,
        })
    }

    /// Returns a user ID taking the username as a parameter
    fn get_user_id_by_username<S: AsRef<str>>(&self, username: S) -> Result<Option<u64>> {
        use redis::ErrorKind;
        match self.inner
            .lock()
            .unwrap()
            .connection
            .hget("userkeys", username.as_ref().to_lowercase()) {
            Ok(id) => Ok(Some(id)),
            Err(ref e) if e.kind() == ErrorKind::TypeError => Ok(None),
            Err(e) => {
                println!("{:?}", e);
                Err(e.into())
            }
        }
    }

    /// Returns a user by ID
    pub fn get_user_by_id(&self, id: u64) -> Result<Option<User>> {
        let key = format!("users:{}", id);
        let addr_key = format!("users:{}:addr", id);

        let (data, addr_data): (_, _) = {
            let db = self.inner.lock().unwrap();
            (try!(db.connection.hgetall(key)), try!(db.connection.hgetall(addr_key)))
        };


        Ok(Some(try!(User::from_db_data(self.clone(), id, data, addr_data))))
    }

    /// Returns all the user ids
    pub fn get_all_user_ids(&self) -> Result<Vec<u64>> {
        let ids: Vec<u64> = try!(self.inner.lock().unwrap().connection.hvals("userkeys"));
        Ok(ids)
    }
}




/// Struct that holds all personal information for the user
#[derive(Clone)]
pub struct User {
    database: Database,
    /// The unique ID of the user
    user_id: u64,
    /// The unique username of the user
    username: String,
    /// The Users password
    password: String,
    /// The users display name
    display_name: String,
    /// The users email
    email: (String, bool),
    /// The users first name
    first_name: Option<(String, bool)>,
    /// The users last name
    last_name: Option<(String, bool)>,
    /// The authenticator secret
    authenticator_secret: String,
    /// the users date of birth
    birthday: Option<(NaiveDate, bool)>,
    /// the user's phone #
    phone: Option<(String, bool)>,
    /// The users profile images
    image_url: Option<String>,
    /// The users Address
    address: Option<(Address, bool)>,
    /// Whether the user account is enabled
    enabled: bool,
    /// The `DateTime` the user registered
    registration_time: DateTime<UTC>,
    /// The time the user was last seen doing an activity
    last_activity: DateTime<UTC>,
    /// Whether the user is banned
    banned: Option<DateTime<UTC>>,
}

impl User {
    /// Creates a new `User`
    pub fn from_db_data(database: Database,
                        user_id: u64,
                        data: HashMap<String, Value>,
                        address_data: HashMap<String, Value>)
                        -> Result<User> {
        let mut data_username = String::new();
        let mut data_display_name = String::new();
        let mut data_password = String::new();
        let mut authenticator_secret = String::new();
        let mut dob_str = String::new();
        let mut dob_confirmed = 0u8;
        let mut phone = String::new();
        let mut phone_confirmed = 0u8;
        let mut email = String::new();
        let mut email_confirmed = 0u8;
        let mut first_name = String::new();
        let mut first_name_confirmed = 0u8;
        let mut last_name = String::new();
        let mut last_name_confirmed = 0u8;
        let mut image_url = String::new();
        let mut addr1 = String::new();
        let mut addr2 = String::new();
        let mut city = String::new();
        let mut state = String::new();
        let mut zip = String::new();
        let mut country = String::new();
        let mut address_confirmed = 0u8;
        let mut registration_time = UTC::now();
        let mut last_activity = UTC::now();
        let mut enabled = 0u8;
        let mut banned = None;

        for (key, value) in data.iter() {
            match key.as_ref() {
                "username" => data_username = try!(String::from_redis_value(value)),
                "password" => data_password = try!(String::from_redis_value(value)),
                "display_name" => data_display_name = try!(String::from_redis_value(value)),
                "email" => email = try!(String::from_redis_value(value)),
                "email_confirmed" => email_confirmed = try!(u8::from_redis_value(value)),
                "authenticator_secret" => {
                    authenticator_secret = try!(String::from_redis_value(value))
                }
                "first_name" => first_name = try!(String::from_redis_value(value)),
                "first_name_confirmed" => first_name_confirmed = try!(u8::from_redis_value(value)),
                "last_name" => last_name = try!(String::from_redis_value(value)),
                "last_name_confirmed" => last_name_confirmed = try!(u8::from_redis_value(value)),
                "birthday" => dob_str = try!(String::from_redis_value(value)),
                "birthday_confirmed" => dob_confirmed = try!(u8::from_redis_value(value)),
                "address_confirmed" => address_confirmed = try!(u8::from_redis_value(value)),
                "phone" => phone = try!(String::from_redis_value(value)),
                "phone_confirmed" => phone_confirmed = try!(u8::from_redis_value(value)),
                "image_url" => image_url = try!(String::from_redis_value(value)),
                "enabled" => enabled = try!(u8::from_redis_value(value)),
                "registration_time" => {
                    registration_time =
                        match String::from_redis_value(value) {
                            Ok(b) => DateTime::<UTC>::from_utc(
                                NaiveDateTime::from_timestamp(b.parse().unwrap(), 0), UTC),
                            Err(_) => unreachable!(),
                        };
                }
                "last_activity" => {
                    last_activity =
                        match String::from_redis_value(value) {
                            Ok(b) => DateTime::<UTC>::from_utc(
                                NaiveDateTime::from_timestamp(b.parse().unwrap(), 0), UTC),
                            Err(_) => unreachable!(),
                        };
                }
                "banned" => {
                    banned = match String::from_redis_value(value) {
                        Ok(b) => {
                            if b.len() > 0 {
                                Some(DateTime::<UTC>::from_utc(
                                    NaiveDateTime::from_timestamp(b.parse().unwrap(), 0), UTC))
                            } else {
                                None
                            }
                        }
                        Err(_) => unreachable!(),
                    };

                }
                _ => unreachable!(),
            }
        }

        let address = if address_data.len() > 0 {
            for (key, value) in address_data.iter() {
                match key.as_ref() {
                    "address1" => addr1 = try!(String::from_redis_value(value)),
                    "address2" => addr2 = try!(String::from_redis_value(value)),
                    "city" => city = try!(String::from_redis_value(value)),
                    "state" => state = try!(String::from_redis_value(value)),
                    "zip" => zip = try!(String::from_redis_value(value)),
                    "country" => country = try!(String::from_redis_value(value)),
                    _ => unreachable!(),
                }
            }

            let addr2_opt = if addr2.len() == 0 { None } else { Some(addr2) };
            Some((Address::new(addr1, addr2_opt, city, state, zip, country),
                  address_confirmed == 1))
        } else {
            None
        };
        let phone_opt = if phone.len() > 0 {
            Some((phone, phone_confirmed == 1))
        } else {
            None
        };
        let img_opt = if image_url.len() > 0 {
            Some(image_url)
        } else {
            None
        };

        let first_opt = if first_name.len() > 0 {
            Some((first_name, first_name_confirmed == 1))
        } else {
            None
        };

        let last_opt = if last_name.len() > 0 {
            Some((last_name, last_name_confirmed == 1))
        } else {
            None
        };

        let dob = if dob_str != String::from("") {
            match NaiveDate::parse_from_str(dob_str.as_str(), "%Y-%m-%d") {
                Ok(a) => Some((a, dob_confirmed == 1)),
                Err(e) => {
                    println!("{}", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(User {
            database: database,
            user_id: user_id,
            username: data_username,
            password: data_password,
            display_name: data_display_name,
            email: (email, email_confirmed == 1),
            first_name: first_opt,
            last_name: last_opt,
            authenticator_secret: authenticator_secret,
            birthday: dob,
            phone: phone_opt,
            image_url: img_opt,
            address: address,
            registration_time: registration_time,
            last_activity: last_activity,
            enabled: enabled == 1,
            banned: banned,
        })
    }

    /// Gets the profile object of the user.
    pub fn get_profile(&self) -> Profile {
        Profile {
            user_id: self.user_id,
            display_name: self.display_name.clone(),
            first_name: match self.first_name {
                Some((ref f, _c)) => Some(f.clone()),
                None => None,
            },
            last_name: match self.last_name {
                Some((ref l, _c)) => Some(l.clone()),
                None => None,
            },
            image_url: self.image_url.clone(),
            age: self.get_age(),
            address: match self.address {
                Some((ref a, _c)) => {
                    Some(format!("{}, {}, {}", a.get_city(), a.get_state(), a.get_country()))
                }
                None => None,
            },
        }
    }

    /// Returns the user ID
    pub fn get_id(&self) -> u64 {
        self.user_id
    }

    /// Returns the username
    pub fn get_username(&self) -> &str {
        &self.username
    }

    ///  Returns the users display name
    pub fn get_display_name(&self) -> &str {
        &self.display_name
    }

    /// Returns the authenticator secret
    pub fn get_authenticator_secret(&mut self) -> Result<String> {
        let secret = try!(self.database.create_new_user_authenticator_secret(self.user_id));
        self.authenticator_secret = secret;
        Ok(self.authenticator_secret.clone())
    }

    /// Checks if the provided authenticator code is valid.
    pub fn check_authenticator_code(&self, code: u32) -> bool {
        let auth = TOTP::new(self.authenticator_secret.as_str());
        auth.verify(code, 30, UTC::now().timestamp() as usize)
    }

    /// Returns the users first name and whether its been confirmed
    pub fn get_first_name(&self) -> Option<&str> {
        match self.first_name {
            Some((ref f, _c)) => Some(f),
            None => None,
        }
    }

    /// Returns wether the first name is confirmed or not.
    pub fn is_first_name_confirmed(&self) -> bool {
        match self.first_name {
            Some((ref _f, c)) => c,
            None => false,
        }
    }

    /// Sets the users first name
    pub fn set_first_name<S: AsRef<str>>(&mut self, name: S) -> Result<()> {
        try!(self.database.set_user_first_name(self.user_id, name.as_ref()));
        self.first_name = Some((String::from(name.as_ref()), false));
        Ok(())
    }


    /// Returns the users first name and whether its been confirmed.
    pub fn get_last_name(&self) -> Option<&str> {
        match self.last_name {
            Some((ref l, _c)) => Some(l),
            None => None,
        }
    }

    /// Returns wether the last name is confirmed or not.
    pub fn is_last_name_confirmed(&self) -> bool {
        match self.last_name {
            Some((ref _l, c)) => c,
            None => false,
        }
    }

    /// Sets the users last name
    pub fn set_last_name<S: AsRef<str>>(&mut self, name: S) -> Result<()> {
        try!(self.database.set_user_last_name(self.user_id, name.as_ref()));
        self.last_name = Some((String::from(name.as_ref()), false));
        Ok(())
    }

    /// Changes the users username
    pub fn set_username<S: AsRef<str>>(&mut self, username: S) -> Result<()> {
        try!(self.database.set_username(self.get_id(), self.get_username(), username.as_ref()));
        self.username = String::from(username.as_ref());
        self.display_name = String::from(username.as_ref());
        Ok(())
    }

    /// checks the password against the users password
    pub fn check_password<S: AsRef<str>>(&self, pass: S) -> Result<bool> {
        match pbkdf2::pbkdf2_check(pass.as_ref(), &self.password.as_str()) {
            Ok(b) => Ok(b),
            Err(e) => return Err(Error::PasswordError(e)),
        }

    }

    /// Sets the user password
    pub fn set_password<S: AsRef<str>>(&mut self, pass: S) -> Result<()> {
        match pbkdf2::pbkdf2_simple(pass.as_ref(), 5) {
            Ok(k) => {
                try!(self.database.set_user_password(self.get_id(), &k));
                self.password = k;
                Ok(())
            }
            Err(e) => Err(Error::IO(e)),
        }
    }

    /// Sets the users email
    pub fn set_email<S: AsRef<str>>(&mut self, email: S) -> Result<()> {
        try!(self.database.set_user_email(self.get_id(), self.email.0.as_str(), email.as_ref()));
        self.email = (String::from(email.as_ref()), false);
        Ok(())
    }

    /// Returns the users email address
    pub fn get_email(&self) -> &str {
        &self.email.0
    }

    /// Returns whether the users email has been confirmed
    pub fn is_email_confirmed(&self) -> bool {
        self.email.1
    }

    /// Returns the users date of birth
    pub fn get_birthday(&self) -> Option<NaiveDate> {
        match self.birthday {
            Some((bd, _c)) => Some(bd),
            None => None,
        }
    }

    /// Returns wether the first name is confirmed or not.
    pub fn is_birthday_confirmed(&self) -> bool {
        match self.birthday {
            Some((_bd, c)) => c,
            None => false,
        }
    }

    /// Gets the age of the user.
    pub fn get_age(&self) -> Option<u8> {
        match self.birthday {
            Some((bd, _c)) => {
                debug_assert!(bd < UTC::today().naive_utc());
                use chrono::Datelike;

                let now = UTC::today().naive_utc();
                let years = (now.year() - bd.year()) as u8;
                if (now.month(), now.day()) < (bd.month(), bd.day()) {
                    Some(years - 1)
                } else {
                    Some(years)
                }
            }
            None => None,
        }
    }

    /// Sets the users birthday
    pub fn set_birthday(&mut self, date: Option<NaiveDate>) -> Result<()> {
        try!(self.database.set_user_birthday(self.get_id(), date));
        match date {
            Some(a) => self.birthday = Some((a, false)),
            None => self.birthday = None,
        };
        Ok(())
    }

    /// Returns the users phone #
    pub fn get_phone(&self) -> Option<&(String, bool)> {
        self.phone.as_ref()
    }

    /// Sets the users phone #
    pub fn set_phone<S: AsRef<str>>(&mut self, phonenum: Option<S>) -> Result<()> {
        let phonenum = match phonenum {
            Some(p) => Some(String::from(p.as_ref())),
            None => None,
        };
        try!(self.database.set_user_phone(self.get_id(), phonenum.as_ref()));
        self.phone = match phonenum {
            Some(a) => Some((a, false)),
            None => None,
        };
        Ok(())
    }

    /// Returns the profile image
    pub fn get_image_url(&self) -> Option<&str> {
        match self.image_url {
            Some(ref img) => Some(img),
            None => None,
        }
    }

    /// Sets the profile image
    pub fn set_image<S: AsRef<str>>(&mut self, image_url: Option<S>) -> Result<()> {
        try!(self.database.set_user_image(self.get_id(), image_url.as_ref()));
        self.image_url = match image_url {
            Some(i) => Some(String::from(i.as_ref())),
            None => None,
        };
        Ok(())
    }

    /// Returns the users address
    pub fn get_address(&self) -> Option<&Address> {
        match self.address {
            Some((ref addr, _c)) => Some(addr),
            None => None,
        }
    }

    /// Returns wether the user's address has been confirmed.
    pub fn is_address_confirmed(&self) -> bool {
        match self.address {
            Some((ref _addr, c)) => c,
            None => false,
        }
    }

    /// Sets the address for the user
    pub fn set_address(&mut self, address: Option<Address>) -> Result<()> {
        try!(self.database.set_user_address(self.user_id, address.as_ref()));
        self.address = match address {
            Some(a) => Some((a, false)),
            None => None,
        };
        Ok(())
    }


    /// Confirms the users email
    pub fn confirm_email(&mut self) -> Result<()> {
        try!(self.database.confrim_email(self.user_id));
        self.email.1 = true;
        Ok(())
    }

    /// Bans the user until the specified time
    pub fn ban(&mut self, until: DateTime<UTC>) -> Result<()> {
        match self.database.ban_user(self.user_id, until) {
            Ok(_) => {
                self.enabled = false;
                self.banned = Some(until);
                Ok(())
            }
            Err(e) => Err(Error::from(e)),
        }

    }

    /// Returns when the user registered
    pub fn get_registration_time(&self) -> &DateTime<UTC> {
        &self.registration_time
    }

    /// Returns the last activity time of the user
    pub fn get_last_activity_time(&self) -> &DateTime<UTC> {
        &self.last_activity
    }

    /// Sets the last activity time of the user
    pub fn set_last_activity_time(&mut self) -> Result<()> {
        try!(self.database.set_last_activity_time(self.user_id));
        self.last_activity = UTC::now();
        Ok(())
    }

    /// Returns DateTime if the user is banned
    pub fn get_banned(&self) -> Option<&DateTime<UTC>> {
        self.banned.as_ref()
    }

    /// Checks if the user is currently banned
    pub fn is_banned(&self) -> bool {
        match self.banned {
            Some(b) => b > UTC::now(),
            None => false,
        }
    }

    /// Begins the reset password proccess
    pub fn start_reset_password<S: AsRef<str>>(&self, key: S) -> Result<()> {
        self.database.start_reset_password(self.user_id, key)
    }

    /// Disables the users account
    pub fn disable(&mut self) -> Result<()> {
        try!(self.database.disable_user(self.user_id));
        self.enabled = false;
        Ok(())
    }

    /// Returns whether the user account is enabled or not
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enables the users account
    pub fn enable(&mut self) -> Result<()> {
        try!(self.database.enable_user(self.user_id));
        self.enabled = true;
        Ok(())
    }

    /// Deletes the `User` from the database
    ///
    /// Note: the `User` is moved out of scope so that it cannot be used again.
    pub fn delete(self) -> Result<()> {
        self.database.delete_user(&self)
    }
}

impl Into<UserDTO> for User {
    fn into(self) -> UserDTO {
        UserDTO {
            user_id: self.user_id,
            username: self.username,
            display_name: self.display_name,
            email: self.email.0,
            email_confirmed: self.email.1,
            first_name: match self.first_name {
                Some((ref f, _c)) => Some(f.clone()),
                None => None,
            },
            first_name_confirmed: match self.first_name {
                Some((ref _f, c)) => c,
                None => false,
            },
            last_name: match self.last_name {
                Some((ref l, _c)) => Some(l.clone()),
                None => None,
            },
            last_name_confirmed: match self.last_name {
                Some((ref _l, c)) => c,
                None => false,
            },

            birthday: match self.birthday {
                Some((b, _c)) => Some(b),
                None => None,
            },
            birthday_confirmed: match self.birthday {
                Some((_b, c)) => c,
                None => false,
            },
            phone: match self.phone {
                Some((ref p, _c)) => Some(p.clone()),
                None => None,
            },
            phone_confirmed: match self.phone {
                Some((ref _p, c)) => c,
                None => false,
            },
            image_url: self.image_url,
            address: match self.address {
                Some((ref a, _c)) => Some(a.clone()),
                None => None,
            },
            address_confirmed: match self.address {
                Some((ref _a, c)) => c,
                None => false,
            },
            enabled: self.enabled,
            registration_time: self.registration_time,
            last_activity: self.last_activity,
            banned: self.banned,
        }
    }
}

impl fmt::Debug for User {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "User {{ID: {}, Username: {}}}",
               self.user_id,
               self.username)
    }
}

impl PartialEq for User {
    fn eq(&self, other: &User) -> bool {
        self.user_id == other.user_id
    }
}

/// Struct for profiles
#[derive(Debug, Clone)]
pub struct Profile {
    /// User's ID.
    user_id: u64,
    /// Display name of the user.
    display_name: String,
    /// First name of the user.
    first_name: Option<String>,
    /// Last name of the user.
    last_name: Option<String>,
    /// Link to the user's profile image.
    image_url: Option<String>,
    /// Age of the user.
    age: Option<u8>,
    /// Address of the user.
    address: Option<String>,
}

impl Into<ProfileDTO> for Profile {
    fn into(self) -> ProfileDTO {
        ProfileDTO {
            user_id: self.user_id,
            display_name: self.display_name,
            first_name: self.first_name,
            last_name: self.last_name,
            image_url: self.image_url,
            age: self.age,
            address: self.address,
        }
    }
}
