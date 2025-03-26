use anyhow::{anyhow, Result};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    pub disk: String,
    pub mount: String,
    pub current_aspect: u32,
}

impl Config {
    pub fn new(config: &str) -> Result<Self> {
        match toml::from_str(config) {
            Ok(c) => Ok(c),
            Err(e) => Err(anyhow!("Couldn't parse config file: {}", e)),
        }
    }
}
