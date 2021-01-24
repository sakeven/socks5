use serde::{Deserialize, Serialize};
use serde_yaml;
use std::fs;
use std::io::Result;
use std::io::{Error, ErrorKind};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Server {
    pub address: String,
    pub port: i32,
    #[serde(default)]
    pub timeout: i32,
    pub password: String,
    pub method: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Local {
    pub address: String,
    pub port: i32,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub server: Vec<Server>,
    pub local: Vec<Local>,
}

pub fn parse_conf() -> Result<Config> {
    let s = fs::read_to_string("mika.cfg")?;
    let cfg: Config = match serde_yaml::from_str(&s) {
        Ok(_cfg) => _cfg,
        Err(_err) => return Err(Error::new(ErrorKind::Other, _err)),
    };
    return Ok(cfg);
}
