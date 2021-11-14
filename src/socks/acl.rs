use crate::address;
use crate::config::{ACLConfig, MatchMode, Policy};
use std::sync::RwLock;

pub struct ACLManager {
    rules: RwLock<ACLConfig>,
}

impl ACLManager {
    pub fn new(rules: ACLConfig) -> Self {
        ACLManager {
            rules: RwLock::new(rules),
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

    fn get_match_fn(mode: &MatchMode) -> fn(&str, &str) -> bool {
        match mode {
            MatchMode::DomainKeyword => ACLManager::domain_keyword,
            MatchMode::DomainSuffix => ACLManager::domain_suffix,
            MatchMode::Domain => ACLManager::domain,
        }
    }

    pub fn acl(&self, _addr: &address::Address) -> Policy {
        let rules = &self.rules.read().unwrap();

        if !_addr.is_domain() {
            return Policy::Direct;
        }

        let addr = _addr.domain();
        for rule in rules.rules.iter() {
            let match_fn = ACLManager::get_match_fn(&rule.mode);
            for pattern in rule.pattern.iter() {
                if match_fn(pattern, &addr) {
                    return rule.policy.clone();
                }
            }
        }
        rules.fnl.clone()
    }
}
