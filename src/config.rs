//! This module is the config interface for the rest api server
use std::{io, fs};
use std::io::Read;
use std::path::Path;
#[cfg(feature = "ssl")]
use std::path::PathBuf;
use std::collections::BTreeMap;

use toml::{Parser, Value};
use chrono::Duration;

const CONFIG_FILE: &'static str = "config.toml";

/// The config struct.
#[cfg(feature = "ssl")]
pub struct Config {
    session_remember: Duration,
    ssl_cert: PathBuf,
    ssl_key: PathBuf,
}

/// The config struct.
#[cfg(not(feature = "ssl"))]
pub struct Config {
    session_remember: Duration,
}

impl Config {
    /// Gets the configuration from file.
    #[cfg(feature = "ssl")]
    pub fn from_file() -> Result<Config, io::Error> {
        let mut config: Config = Default::default();

        if let Some(parser) = try!(Config::get_config_file_parser()) {
            for (key, value) in parser {
                match key.as_str() {
                    "session_remember" => {
                        config.session_remember = Duration::seconds(value.as_integer().unwrap())
                    }
                    "ssl_cert" => config.ssl_cert = PathBuf::from(value.as_str().unwrap()),
                    "ssl_key" => config.ssl_key = PathBuf::from(value.as_str().unwrap()),
                    _ => unreachable!(),
                }
            }
        }
        Ok(config)
    }

    /// Gets the configuration from file.
    #[cfg(not(feature = "ssl"))]
    pub fn from_file() -> Result<Config, io::Error> {
        let mut config: Config = Default::default();

        if let Some(parser) = try!(Config::get_config_file_parser()) {
            for (key, value) in parser {
                match key.as_str() {
                    "session_remember" => {
                        config.session_remember = Duration::seconds(value.as_integer().unwrap())
                    }
                    "ssl_cert" | "ssl_key" => {}
                    _ => unreachable!(),
                }
            }
        }

        Ok(config)
    }

    /// Gets the config file parser.
    fn get_config_file_parser() -> Result<Option<BTreeMap<String, Value>>, io::Error> {
        Ok(if Path::new(CONFIG_FILE).exists() {
            let mut f = try!(fs::File::open(CONFIG_FILE));
            let mut toml = String::new();
            let _ = try!(f.read_to_string(&mut toml));
            Some(Parser::new(&toml).parse().unwrap())
        } else {
            None
        })
    }

    /// Gets the session remembering time for users that checked the `remember` checkbox.
    pub fn get_session_remember(&self) -> Duration {
        self.session_remember
    }

    /// Gets the SSL certificate path.
    #[cfg(feature = "ssl")]
    pub fn get_ssl_cert(&self) -> PathBuf {
        self.ssl_cert.clone()
    }

    /// Gets the SSL key path.
    #[cfg(feature = "ssl")]
    pub fn get_ssl_key(&self) -> PathBuf {
        self.ssl_key.clone()
    }
}

#[cfg(feature = "ssl")]
impl Default for Config {
    fn default() -> Config {
        Config {
            session_remember: Duration::weeks(2),
            ssl_cert: PathBuf::from("my.domain.com.crt"),
            ssl_key: PathBuf::from("my.domain.com.pem"),
        }
    }
}

#[cfg(not(feature = "ssl"))]
impl Default for Config {
    fn default() -> Config {
        Config { session_remember: Duration::weeks(2) }
    }
}
