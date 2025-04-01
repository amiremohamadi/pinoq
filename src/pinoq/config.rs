use crate::pinoq::error::{PinoqError, Result};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    pub disk: String,
    pub mount: String,
    pub current: Current,
}

#[derive(Deserialize)]
pub struct Current {
    pub aspect: u32,
    pub password: String,
}

impl Config {
    pub fn new(config: &str) -> Result<Self> {
        match toml::from_str(config) {
            Ok(c) => Ok(c),
            Err(_) => Err(PinoqError::InvalidConfig),
        }
    }
}
