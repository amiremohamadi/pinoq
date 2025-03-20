use anyhow::Result;
use std::env;
use std::str::FromStr;

#[derive(Debug)]
pub enum Backend {
    Gz,
}

impl FromStr for Backend {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "gz" => Ok(Self::Gz),
            _ => Err(anyhow::anyhow!("invalid backend {}", s)),
        }
    }
}

impl Default for Backend {
    fn default() -> Self {
        Self::Gz
    }
}

pub struct Config {
    pub mountpoint: String,
    pub disk: String,
    pub backend: Backend,
    pub aspects: u32,
    pub block_size: u32,
}

pub struct PinoqFs {
    config: Config,
}

impl PinoqFs {
    pub fn new(config: Config) -> Self {
        PinoqFs { config }
    }
}

fn mount_pinoq(config: Config) {
    let fs = PinoqFs::new(config);
}

fn main() {
    pretty_env_logger::formatted_builder()
        .parse_filters("INFO")
        .init();

    let mountpoint = env::var("PINOQ_MOUNT").unwrap_or_default();
    let disk = env::var("PINOQ_DISK").unwrap_or_default();
    let backend = env::var("PINOQ_BACKEND")
        .ok()
        .and_then(|x| x.parse::<Backend>().ok())
        .unwrap_or_default();
    let aspects = env::var("PINOQ_ASPECTS")
        .ok()
        .and_then(|x| x.parse::<u32>().ok())
        .unwrap_or(8);
    let block_size = env::var("PINOQ_BLOCK_SIZE")
        .ok()
        .and_then(|x| x.parse::<u32>().ok())
        .unwrap_or(2048);

    mount_pinoq(Config {
        mountpoint,
        disk,
        backend,
        aspects,
        block_size,
    });
}
