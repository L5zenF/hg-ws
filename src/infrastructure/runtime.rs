use std::{net::IpAddr, time::Duration};

use snafu::{ResultExt, Snafu};
use tokio::{net::TcpStream, time::timeout};

use crate::{
    application::ports::{BoxFuture, OutboundConnector},
    domain::protocol::Destination,
};

pub type RuntimeResult<T> = Result<T, RuntimeError>;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum RuntimeError {
    #[snafu(display("HTTP request to {url} failed"))]
    Http { url: String, source: reqwest::Error },

    #[snafu(display("HTTP response from {url} could not be decoded"))]
    Decode { url: String, source: reqwest::Error },

    #[snafu(display("DNS lookup failed for {host}"))]
    Dns {
        host: String,
        source: std::io::Error,
    },

    #[snafu(display("TCP connect to {addr} failed"))]
    TcpConnect {
        addr: String,
        source: std::io::Error,
    },

    #[snafu(display("TCP connect to {addr} timed out"))]
    TcpTimeout { addr: String },

    #[snafu(display("I/O operation failed while proxying"))]
    Io { source: std::io::Error },

    #[snafu(display("process `{program}` failed"))]
    Process {
        program: String,
        source: std::io::Error,
    },

    #[snafu(display("invalid Nezha agent response status {status}"))]
    AgentDownloadStatus { status: reqwest::StatusCode },
}

#[derive(Debug, Clone)]
pub struct TokioConnector {
    timeout: Duration,
}

impl TokioConnector {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl OutboundConnector for TokioConnector {
    fn connect<'a>(
        &'a self,
        destination: &'a Destination,
    ) -> BoxFuture<'a, RuntimeResult<TcpStream>> {
        Box::pin(async move {
            let addr = format!("{}:{}", destination.host, destination.port);
            timeout(self.timeout, TcpStream::connect(&addr))
                .await
                .map_err(|_| RuntimeError::TcpTimeout { addr: addr.clone() })?
                .context(TcpConnectSnafu { addr })
        })
    }
}

pub fn is_ip_address(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}
