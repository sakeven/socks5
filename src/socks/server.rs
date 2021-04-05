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
    proxy_group: RwLock<HashMap<String, ProxyGroupV>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxyGroupV {
    id: String,
    proxy_list: Vec<String>,
    auto_select: bool,
    proxy_selected_idx: usize,
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
            let groupv = ProxyGroupV {
                id: grp.id,
                proxy_list: grp.proxy_list,
                auto_select: true,
                proxy_selected_idx: 0,
            };
            proxy_group.insert(group.id.clone(), groupv);
        }

        ServerManager {
            servers,
            server_map,
            proxy_group: RwLock::new(proxy_group),
        }
    }

    pub fn update(&self, proxy_group: &ProxyGroupV) {
        let mut proxy_groups = self.proxy_group.write().unwrap();
        let got = match proxy_groups.get_mut(proxy_group.id.as_str()) {
            Some(got) => got,
            None => return,
        };
        if proxy_group.proxy_selected_idx >= got.proxy_list.len() {
            return;
        }
        got.proxy_selected_idx = proxy_group.proxy_selected_idx;
        got.auto_select = proxy_group.auto_select;
    }

    pub fn get_state(&self) -> Vec<ProxyGroupV> {
        let mut group = ProxyGroupV {
            id: "Proxy".to_string(),
            proxy_list: vec![],
            auto_select: true,
            proxy_selected_idx: 0,
        };
        for server in self.servers.iter() {
            group.proxy_list.push(server.id.clone());
        }
        let mut all: Vec<ProxyGroupV> = vec![group];

        let proxy_group = self.proxy_group.read().unwrap();
        for (_, group) in proxy_group.iter() {
            all.push(group.clone());
        }

        all
    }

    fn pick(&self, pg: Option<String>) -> &Server {
        let proxy_group = self.proxy_group.read().unwrap();
        let id = match pg {
            Some(group_id) => {
                let proxy_group = proxy_group.get(&group_id).unwrap();
                let idx = thread_rng().next_u32() as usize % proxy_group.proxy_list.len();
                let sid = &proxy_group.proxy_list[idx];
                self.server_map[sid]
            }
            None => thread_rng().next_u32() as usize % self.servers.len(),
        };
        &self.servers[id]
    }

    pub async fn pick_one(
        &self,
        pg: Option<String>,
    ) -> Result<(
        Box<dyn AsyncWrite + Unpin + Send>,
        Box<dyn AsyncRead + Unpin + Send>,
        String,
    )> {
        let server_cfg = self.pick(pg);

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
