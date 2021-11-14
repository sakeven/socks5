use crate::address;
use crate::config::{ACLConfig, MatchMode, Policy};
use std::str::FromStr;
use std::sync::RwLock;

use log::debug;

pub struct ACLManager {
    rules: RwLock<ACLConfig>,
}

impl ACLManager {
    pub fn new(rules: ACLConfig) -> Self {
        ACLManager {
            rules: RwLock::new(rules),
        }
    }

    fn domain_keyword(x: &str, addr: &address::Address) -> bool {
        addr.is_domain() && addr.domain().contains(x)
    }

    fn domain_suffix(x: &str, addr: &address::Address) -> bool {
        addr.is_domain() && addr.domain().ends_with(x)
    }

    fn domain(x: &str, addr: &address::Address) -> bool {
        addr.is_domain() && addr.domain() == x
    }

    fn ip_cidr(x: &str, addr: &address::Address) -> bool {
        if addr.is_domain() {
            return false;
        }
        let ip_cidr = cidr::IpInet::from_str(x).unwrap();
        ip_cidr.contains(&addr.ip_addr())
    }

    fn get_match_fn(mode: &MatchMode) -> fn(&str, &address::Address) -> bool {
        match mode {
            MatchMode::DomainKeyword => ACLManager::domain_keyword,
            MatchMode::DomainSuffix => ACLManager::domain_suffix,
            MatchMode::Domain => ACLManager::domain,
            MatchMode::IpCidr => ACLManager::ip_cidr,
        }
    }

    pub fn acl(&self, _addr: &address::Address) -> Policy {
        let rules = &self.rules.read().unwrap();

        for rule in rules.rules.iter() {
            let match_fn = ACLManager::get_match_fn(&rule.mode);
            for pattern in rule.pattern.iter() {
                if match_fn(pattern, _addr) {
                    return rule.policy.clone();
                }
            }
        }
        rules.fnl.clone()
    }
}
