use std::fs;
use std::io::Result;
use std::io::{Error, ErrorKind};

use serde::{Deserialize, Serialize};
use serde_yaml;

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Server {
    pub address: String,
    pub port: i32,
    #[serde(default)]
    pub timeout: i32,
    #[serde(default)]
    pub obfs_url: String,
    pub password: String,
    #[serde(skip)]
    pub key: Vec<u8>,
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
    #[serde(rename = "acl")]
    pub acl_cfg: ACLConfig,
}

pub fn parse_conf(path: String) -> Result<Config> {
    let s = fs::read_to_string(path)?;
    let cfg: Config = match serde_yaml::from_str(&s) {
        Ok(_cfg) => _cfg,
        Err(_err) => return Err(Error::new(ErrorKind::Other, _err)),
    };
    return Ok(cfg);
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum MatchMode {
    DomainSuffix,
    DomainKeyword,
    Domain,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Policy {
    Direct,
    Proxy,
    Reject,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ACLConfig {
    pub rules: Vec<ProxyRule>,
    #[serde(rename = "final")]
    pub fnl: Policy,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ProxyRule {
    pub pattern: Vec<String>,
    pub mode: MatchMode,
    pub policy: Policy,
}
