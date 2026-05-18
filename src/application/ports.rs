use std::{future::Future, pin::Pin, sync::Arc};

use tokio::net::TcpStream;

use crate::{
    application::config::Config,
    domain::{policy::DomainPolicy, protocol::Destination, subscription::IpInfo},
    infrastructure::runtime::{RuntimeError, RuntimeResult},
};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait Resolver: Send + Sync {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, RuntimeResult<String>>;
}

pub trait OutboundConnector: Send + Sync {
    fn connect<'a>(
        &'a self,
        destination: &'a Destination,
    ) -> BoxFuture<'a, RuntimeResult<TcpStream>>;
}

pub trait PublicIpProvider: Send + Sync {
    fn detect<'a>(&'a self, configured_domain: Option<&'a str>, port: u16)
        -> BoxFuture<'a, IpInfo>;
}

pub trait IspProvider: Send + Sync {
    fn isp<'a>(&'a self) -> BoxFuture<'a, String>;
}

pub trait KeepAliveClient: Send + Sync {
    fn add_access_task<'a>(
        &'a self,
        domain: &'a str,
        sub_path: &'a str,
    ) -> BoxFuture<'a, RuntimeResult<()>>;
}

pub trait MonitorAgent: Send + Sync {
    fn start<'a>(&'a self, config: &'a Config) -> BoxFuture<'a, RuntimeResult<()>>;
    fn cleanup_later<'a>(&'a self) -> BoxFuture<'a, RuntimeResult<()>>;
}

#[derive(Clone)]
pub struct AppDeps {
    pub resolver: Arc<dyn Resolver>,
    pub policy: Arc<dyn DomainPolicy>,
    pub connector: Arc<dyn OutboundConnector>,
    pub public_ip: Arc<dyn PublicIpProvider>,
    pub isp: Arc<dyn IspProvider>,
    pub keep_alive: Arc<dyn KeepAliveClient>,
    pub monitor: Arc<dyn MonitorAgent>,
}

impl AppDeps {
    pub fn validate(&self) -> Result<(), RuntimeError> {
        Ok(())
    }
}
