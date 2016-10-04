//! This module is the utils interface for rest api server

use std::net::TcpStream;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use byteorder::{NetworkEndian, ByteOrder};

use ENCRYPTION_SERVERS;
use error::{Error, Result};

const CODE_OK: u8 = 0x00;
const HEAD_AES_ENCRYPT: u8 = 146;
const HEAD_AES_DECRYPT: u8 = 1;


const POOL_PER_CLIENT: usize = 20;

lazy_static! {
    /// Encryption client.
    pub static ref ENCRYPTION_CLIENT: EncryptionClient = EncryptionClient::new();
}

/// Encryption client
pub struct EncryptionClient {
    pool: Vec<Arc<Mutex<TcpStream>>>,
}

impl EncryptionClient {
    /// Creates a new encryption client.
    fn new() -> EncryptionClient {
        let mut pool = Vec::with_capacity(ENCRYPTION_SERVERS.len() * POOL_PER_CLIENT);
        for server in ENCRYPTION_SERVERS.iter() {
            for _ in 0..POOL_PER_CLIENT {
                pool.push(Arc::new(Mutex::new(TcpStream::connect(server).unwrap())));
            }
        }
        EncryptionClient { pool: pool }
    }

    /// Function to encrypt a stream in AES
    pub fn aes_encrypt(&self, message: &[u8]) -> Result<Box<[u8]>> {
        if message.is_empty() {
            return Ok(Box::new([]));
        }
        let (head, response) = try!(self.send_request(HEAD_AES_ENCRYPT, message));

        if head != CODE_OK {
            Err(Error::RequestError)
        } else {
            Ok(response)
        }
    }

    /// Function to decrypt a stream in AES
    pub fn aes_decrypt(&self, message: &[u8]) -> Result<Box<[u8]>> {
        if message.is_empty() {
            return Ok(Box::new([]));
        }
        let (head, response) = try!(self.send_request(HEAD_AES_DECRYPT, message));

        if head != CODE_OK {
            Err(Error::RequestError)
        } else {
            Ok(response)
        }
    }

    /// Sends a request to with the stream and header
    fn send_request(&self, header: u8, message: &[u8]) -> Result<(u8, Box<[u8]>)> {
        let mut head_buf = [header, 0, 0, 0, 0];
        NetworkEndian::write_u32(&mut head_buf[1..], message.len() as u32);

        for stream in self.pool.iter().cycle() {
            if let Ok(mut stream) = stream.try_lock() {
                try!(stream.write_all(&head_buf));
                try!(stream.write_all(message));
                try!(stream.flush());

                let mut response_header = [0u8; 5];
                try!(stream.read_exact(&mut response_header));
                let head = response_header[0];
                if head == CODE_OK {
                    let size = NetworkEndian::read_u32(&response_header[1..]) as usize;

                    let mut response = vec![0u8; size];
                    try!(stream.read_exact(&mut response));

                    return Ok((head, response.into_boxed_slice()));
                } else {
                    return Err(Error::RequestError);
                }
            }
        }
        return Err(Error::RequestError);
    }
}

/// Whether the email being sent is a password reset or email confirmation email
pub enum EmailType {
    /// An email confirmation email
    Email,
    /// A password reset email
    Password,
}

/// The basics needed to generate an email and send it to the user
pub struct EmailStruct {
    /// the email address the email is being sent to
    pub email: String,
    /// The key for the email
    pub email_key: String,
    /// The type of email being generated and sent
    pub email_type: EmailType,
}
