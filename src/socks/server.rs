use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use tokio::io::{AsyncRead, AsyncWrite, Result};
use tokio::net::TcpStream;

use crate::config::{ProxyGroup, Server};
use crate::crypto::{CryptoReader, CryptoWriter};
use crate::obfs::{ObfsReader, ObfsWriter};

pub struct ServerManager {
    servers: Vec<Server>,
    server_map: HashMap<String, usize>,
    proxy_groups: RwLock<HashMap<String, ProxyGroupState>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxyGroupState {
    id: String,
    proxy_list: Vec<Proxy>,
    selected_idx: usize,
}

impl ProxyGroupState {
    fn enabled_proxy_list(&self) -> Vec<Proxy> {
        let mut proxies: Vec<Proxy> = Vec::new();
        for proxy in self.proxy_list.iter() {
            if proxy.enabled {
                proxies.push(proxy.clone());
            }
        }
        proxies
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxyGroupStatePatch {
    id: String,
    proxy: Proxy,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Proxy {
    id: String,
    enabled: bool,
}

impl ServerManager {
    pub fn new(servers: Vec<Server>, _proxy_group: Vec<ProxyGroup>) -> Self {
        let mut server_map = HashMap::new();
        let mut idx: usize = 0;
        for server in servers.iter() {
            server_map.insert(server.id.clone(), idx);
            idx += 1;
        }

        let mut proxy_group = HashMap::new();
        for group in _proxy_group.iter() {
            let grp = group.clone();
            let mut proxies: Vec<Proxy> = Vec::with_capacity(grp.proxy_list.len());
            for proxy in grp.proxy_list {
                proxies.push(Proxy {
                    id: proxy,
                    enabled: true,
                })
            }
            let group_state = ProxyGroupState {
                id: grp.id,
                proxy_list: proxies,
                selected_idx: 0,
            };
            proxy_group.insert(group.id.clone(), group_state);
        }

        let mut group_state = ProxyGroupState {
            id: "Proxy".to_string(),
            proxy_list: Vec::with_capacity(servers.len()),
            selected_idx: 0,
        };
        for server in servers.iter() {
            group_state.proxy_list.push(Proxy {
                id: server.id.clone(),
                enabled: true,
            });
        }
        proxy_group.insert(group_state.id.clone(), group_state);

        ServerManager {
            servers,
            server_map,
            proxy_groups: RwLock::new(proxy_group),
        }
    }

    pub fn update(&self, proxy_group: &ProxyGroupStatePatch) {
        let mut proxy_groups = self.proxy_groups.write().unwrap();
        let got = match proxy_groups.get_mut(proxy_group.id.as_str()) {
            Some(got) => got,
            None => return,
        };

        if got.enabled_proxy_list().len() <= 1 {
            return;
        }

        for proxy in got.proxy_list.iter_mut() {
            if proxy.id == proxy_group.proxy.id {
                proxy.enabled = proxy_group.proxy.enabled
            }
        }
    }

    pub fn get_state(&self) -> Vec<ProxyGroupState> {
        let proxy_group = self.proxy_groups.read().unwrap();
        let mut all: Vec<ProxyGroupState> = Vec::with_capacity(proxy_group.len());
        for (_, group) in proxy_group.iter() {
            all.push(group.clone());
        }

        all
    }

    fn pick(&self, proxy_group_id: Option<String>) -> &Server {
        let proxy_groups = self.proxy_groups.read().unwrap();
        let group_id = proxy_group_id.unwrap_or("Proxy".to_string());
        let id = {
            let proxy_group = proxy_groups.get(&group_id).unwrap();
            let proxy_list = proxy_group.enabled_proxy_list();
            let idx = thread_rng().next_u32() as usize % proxy_list.len();
            let sid = &proxy_list[idx].id;
            self.server_map[sid]
        };

        &self.servers[id]
    }

    pub async fn pick_one(
        &self,
        proxy_group_id: Option<String>,
    ) -> Result<(
        Box<dyn AsyncWrite + Unpin + Send>,
        Box<dyn AsyncRead + Unpin + Send>,
        String,
    )> {
        let server_cfg = self.pick(proxy_group_id);

        let server =
            TcpStream::connect(format!("{}:{}", server_cfg.address, server_cfg.port)).await?;

        let (rr, rw) = server.into_split();
        let mut writer: Box<dyn AsyncWrite + Unpin + Send> = Box::new(rw);
        let mut reader: Box<dyn AsyncRead + Unpin + Send> = Box::new(rr);
        if !server_cfg.obfs_url.is_empty() {
            writer = Box::new(ObfsWriter::new(writer, server_cfg.obfs_url.clone()));
            reader = Box::new(ObfsReader::new(reader));
        }

        let sk = server_cfg.key.clone();
        Ok((
            Box::new(CryptoWriter::new(writer, &server_cfg.key)),
            Box::new(CryptoReader::new(reader, &sk)),
            server_cfg.id.clone(),
        ))
    }
}
