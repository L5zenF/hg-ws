use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;
use snafu::ResultExt;
use tokio::net::lookup_host;

use crate::{
    application::ports::{BoxFuture, Resolver},
    infrastructure::runtime::{
        is_ip_address, DecodeSnafu, DnsSnafu, HttpSnafu, RuntimeError, RuntimeResult,
    },
};

#[derive(Debug, Clone)]
pub struct DohResolver {
    client: Client,
    timeout: Duration,
}

impl DohResolver {
    pub fn new(client: Client, timeout: Duration) -> Self {
        Self { client, timeout }
    }
}

impl Resolver for DohResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, RuntimeResult<String>> {
        Box::pin(async move {
            if is_ip_address(host) {
                return Ok(host.to_string());
            }

            match self.resolve_doh(host).await {
                Ok(ip) => Ok(ip),
                Err(error) => {
                    tracing::debug!(%host, %error, "DoH lookup failed; falling back to system DNS");
                    self.resolve_system(host).await
                }
            }
        })
    }
}

impl DohResolver {
    async fn resolve_doh(&self, host: &str) -> RuntimeResult<String> {
        let url = format!("https://dns.google/resolve?name={host}&type=A");
        let response = self
            .client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await
            .context(HttpSnafu { url: url.clone() })?;
        let dns = response
            .json::<DnsResponse>()
            .await
            .context(DecodeSnafu { url })?;

        dns.answer
            .into_iter()
            .flatten()
            .find(|answer| answer.record_type == 1)
            .map(|answer| answer.data)
            .ok_or_else(|| RuntimeError::Dns {
                host: host.to_string(),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "no A record"),
            })
    }

    async fn resolve_system(&self, host: &str) -> RuntimeResult<String> {
        let mut addrs = lookup_host((host, 0)).await.context(DnsSnafu {
            host: host.to_string(),
        })?;
        addrs
            .find_map(|addr| {
                let ip = addr.ip();
                ip.is_ipv4().then(|| ip.to_string())
            })
            .ok_or_else(|| RuntimeError::Dns {
                host: host.to_string(),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "no IPv4 address"),
            })
    }
}

#[derive(Debug, Deserialize)]
struct DnsResponse {
    #[serde(rename = "Answer")]
    answer: Option<Vec<DnsAnswer>>,
}

#[derive(Debug, Deserialize)]
struct DnsAnswer {
    #[serde(rename = "type")]
    record_type: u16,
    data: String,
}
