use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use snafu::ResultExt;

use crate::{
    dependencies::{BoxFuture, IspProvider, KeepAliveClient, PublicIpProvider},
    runtime::{DecodeSnafu, HttpSnafu, RuntimeResult},
    subscription::IpInfo,
};

#[derive(Debug, Clone)]
pub struct HttpExternalServices {
    client: Client,
}

impl HttpExternalServices {
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

impl PublicIpProvider for HttpExternalServices {
    fn detect<'a>(
        &'a self,
        configured_domain: Option<&'a str>,
        port: u16,
    ) -> BoxFuture<'a, IpInfo> {
        Box::pin(async move {
            match configured_domain
                .filter(|domain| !domain.is_empty() && *domain != "your-domain.com")
            {
                Some(domain) => IpInfo {
                    domain: domain.to_string(),
                    tls: true,
                    port: 443,
                },
                None => match self.public_ipv4().await {
                    Ok(ip) => IpInfo {
                        domain: ip,
                        tls: false,
                        port,
                    },
                    Err(error) => {
                        tracing::warn!(%error, "public IP detection failed; using fallback subscription host");
                        IpInfo {
                            domain: "change-your-domain.com".to_string(),
                            tls: true,
                            port: 443,
                        }
                    }
                },
            }
        })
    }
}

impl IspProvider for HttpExternalServices {
    fn isp<'a>(&'a self) -> BoxFuture<'a, String> {
        Box::pin(async move {
            if let Ok(isp) = self.ip_sb_isp().await {
                return isp;
            }
            if let Ok(isp) = self.ip_api_isp().await {
                return isp;
            }
            "Unknown".to_string()
        })
    }
}

impl KeepAliveClient for HttpExternalServices {
    fn add_access_task<'a>(
        &'a self,
        domain: &'a str,
        sub_path: &'a str,
    ) -> BoxFuture<'a, RuntimeResult<()>> {
        Box::pin(async move {
            if domain.is_empty() {
                return Ok(());
            }

            let url = "https://oooo.serv00.net/add-url".to_string();
            self.client
                .post(&url)
                .json(&json!({ "url": format!("https://{domain}/{sub_path}") }))
                .send()
                .await
                .context(HttpSnafu { url })?;
            Ok(())
        })
    }
}

impl HttpExternalServices {
    async fn public_ipv4(&self) -> RuntimeResult<String> {
        let url = "https://api-ipv4.ip.sb/ip".to_string();
        let body = self
            .client
            .get(&url)
            .send()
            .await
            .context(HttpSnafu { url: url.clone() })?
            .text()
            .await
            .context(DecodeSnafu { url })?;
        Ok(body.trim().to_string())
    }

    async fn ip_sb_isp(&self) -> RuntimeResult<String> {
        let url = "https://api.ip.sb/geoip".to_string();
        let data = self
            .client
            .get(&url)
            .header("User-Agent", "Mozilla/5.0")
            .send()
            .await
            .context(HttpSnafu { url: url.clone() })?
            .json::<IpSbGeo>()
            .await
            .context(DecodeSnafu { url })?;
        Ok(format_isp(data.country_code, data.isp))
    }

    async fn ip_api_isp(&self) -> RuntimeResult<String> {
        let url = "http://ip-api.com/json".to_string();
        let data = self
            .client
            .get(&url)
            .header("User-Agent", "Mozilla/5.0")
            .send()
            .await
            .context(HttpSnafu { url: url.clone() })?
            .json::<IpApiGeo>()
            .await
            .context(DecodeSnafu { url })?;
        Ok(format_isp(data.country_code, data.org))
    }
}

fn format_isp(country: String, isp: String) -> String {
    format!("{country}-{isp}").replace(' ', "_")
}

#[derive(Debug, Deserialize)]
struct IpSbGeo {
    country_code: String,
    isp: String,
}

#[derive(Debug, Deserialize)]
struct IpApiGeo {
    #[serde(rename = "countryCode")]
    country_code: String,
    org: String,
}
