use crate::address;
use crate::config::{ACLConfig, MatchMode, Policy};
use std::sync::Mutex;

pub struct ACLManager {
    rules: Mutex<ACLConfig>,
}

impl ACLManager {
    pub fn new(rules: ACLConfig) -> Self {
        ACLManager {
            rules: Mutex::new(rules),
        }
    }

    fn domain_keyword(x: &str, addr: &str) -> bool {
        addr.contains(x)
    }

    fn domain_suffix(x: &str, addr: &str) -> bool {
        addr.ends_with(x)
    }

    fn domain(x: &str, addr: &str) -> bool {
        addr == x
    }

    fn get_fn(mode: &MatchMode) -> fn(&str, &str) -> bool {
        match mode {
            MatchMode::DomainKeyword => ACLManager::domain_keyword,
            MatchMode::DomainSuffix => ACLManager::domain_suffix,
            MatchMode::Domain => ACLManager::domain,
        }
    }

    pub fn acl(&self, _addr: &address::Address) -> Policy {
        let addr = format!("{}", _addr);
        let addr = addr.strip_prefix("http://").unwrap_or(addr.as_str());
        let addr = addr.strip_prefix("https://").unwrap_or(addr);
        let rules = self.rules.lock().unwrap();
        for rule in rules.rules.iter() {
            let func = ACLManager::get_fn(&rule.mode);
            for pattern in rule.pattern.iter() {
                if func(pattern, addr) {
                    return rule.policy;
                }
            }
        }

        rules.fnl
    }
}
