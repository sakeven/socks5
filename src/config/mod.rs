use std::fs;
use std::io::Result;
use std::io::{Error, ErrorKind};

use serde::{Deserialize, Serialize};
use serde_yaml;

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Server {
    #[serde(default)]
    pub id: String,
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
    #[serde(default)]
    pub proxy_group: Vec<ProxyGroup>,
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

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Policy {
    Direct,
    Proxy,
    Reject,
    ProxyGroup(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxyGroup {
    pub id: String,
    pub proxy_list: Vec<String>,
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

use std::fmt;

use serde::de::{self, Deserializer, Visitor};

struct PolicyVisitor;

impl<'de> Visitor<'de> for PolicyVisitor {
    type Value = Policy;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an policy in string")
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        match value {
            "Proxy" => Ok(Policy::Proxy),
            "Direct" => Ok(Policy::Direct),
            "Reject" => Ok(Policy::Reject),
            a => Ok(Policy::ProxyGroup(a.to_string())),
        }
    }
}

impl<'de> Deserialize<'de> for Policy {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Policy, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_i32(PolicyVisitor)
    }
}
