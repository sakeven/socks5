use bstr::ByteSlice;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde_json;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::socks::server::{ProxyGroupV, ServerManager};

pub struct HTTPManager {
    server_manager: Arc<ServerManager>,
}

impl HTTPManager {
    pub fn new(sm: Arc<ServerManager>) -> Self {
        HTTPManager { server_manager: sm }
    }

    pub async fn start(self: Arc<Self>) {
        let make_svc = make_service_fn(move |_conn| {
            let this = self.clone();
            async {
                // service_fn converts our function into a `Service`
                Ok::<_, Infallible>(service_fn(move |req| {
                    let this = this.clone();
                    async move { this.router(req).await }
                }))
            }
        });

        // We'll bind to 127.0.0.1:3000
        let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
        let server = Server::bind(&addr).serve(make_svc);

        // Run this server for... forever!
        if let Err(e) = server.await {
            eprintln!("server error: {}", e);
        }
    }

    async fn get_current_state(
        self: Arc<Self>,
        _req: Request<Body>,
    ) -> Result<Response<Body>, Infallible> {
        let proxy_groups = self.server_manager.get_state();
        let data = serde_json::to_string_pretty(&proxy_groups).unwrap();
        Ok(Response::new(data.into()))
    }

    async fn update_proxy_groups(
        self: Arc<Self>,
        req: Request<Body>,
    ) -> Result<Response<Body>, Infallible> {
        let whole_body = hyper::body::to_bytes(req.into_body()).await.unwrap();
        let pgv: ProxyGroupV = serde_json::from_slice(whole_body.as_bytes()).unwrap();
        self.server_manager.update(&pgv);
        let proxy_groups = self.server_manager.get_state();
        let data = serde_json::to_string_pretty(&proxy_groups).unwrap();
        Ok(Response::new(data.into()))
    }

    async fn router(self: Arc<Self>, req: Request<Body>) -> Result<Response<Body>, Infallible> {
        match (req.method(), req.uri().path()) {
            (&Method::GET, "/") => self.get_current_state(req).await,
            (&Method::PUT, "/proxy_group") => self.update_proxy_groups(req).await,
            // Return the 404 Not Found for other routes.
            _ => {
                let mut not_found = Response::default();
                *not_found.status_mut() = StatusCode::NOT_FOUND;
                Ok(not_found)
            }
        }
    }
}
