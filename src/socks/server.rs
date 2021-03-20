use crate::config::Server;
use rand::{thread_rng, RngCore};

pub struct ServerManager {
    servers: Vec<Server>,
}

impl ServerManager {
    pub fn new(servers: Vec<Server>) -> Self {
        ServerManager { servers }
    }

    pub fn pick(&self) -> Server {
        let id = thread_rng().next_u32() as usize % self.servers.len();
        self.servers[id].clone()
    }
}
