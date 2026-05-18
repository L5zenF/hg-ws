use std::{path::Path, time::Duration};

use reqwest::Client;
use snafu::{ensure, ResultExt};
use tokio::{process::Command, time::sleep};

use crate::{
    application::{
        config::Config,
        ports::{BoxFuture, MonitorAgent},
    },
    infrastructure::runtime::{AgentDownloadStatusSnafu, HttpSnafu, ProcessSnafu, RuntimeResult},
};

#[derive(Debug, Clone)]
pub struct NezhaMonitor {
    client: Client,
}

impl NezhaMonitor {
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

impl MonitorAgent for NezhaMonitor {
    fn start<'a>(&'a self, config: &'a Config) -> BoxFuture<'a, RuntimeResult<()>> {
        Box::pin(async move {
            let Some(server) = config.nezha_server.as_deref() else {
                return Ok(());
            };
            let Some(key) = config.nezha_key.as_deref() else {
                return Ok(());
            };

            if is_running().await {
                tracing::info!("Nezha agent already running");
                return Ok(());
            }

            download_agent(&self.client, config.nezha_port.as_deref()).await?;

            if let Some(port) = config
                .nezha_port
                .as_deref()
                .filter(|value| !value.is_empty())
            {
                start_v0(server, port, key).await
            } else {
                generate_v1_config(server, key, &config.uuid_text)?;
                start_v1().await
            }
        })
    }

    fn cleanup_later<'a>(&'a self) -> BoxFuture<'a, RuntimeResult<()>> {
        Box::pin(async move {
            sleep(Duration::from_secs(180)).await;
            let _ = tokio::fs::remove_file("npm").await;
            let _ = tokio::fs::remove_file("config.yaml").await;
            Ok(())
        })
    }
}

async fn download_agent(client: &Client, port: Option<&str>) -> RuntimeResult<()> {
    let url = download_url(port);
    let response = client.get(url).send().await.context(HttpSnafu {
        url: url.to_string(),
    })?;
    ensure!(
        response.status().is_success(),
        AgentDownloadStatusSnafu {
            status: response.status()
        }
    );
    let bytes = response.bytes().await.context(HttpSnafu {
        url: url.to_string(),
    })?;
    tokio::fs::write("npm", bytes).await.context(ProcessSnafu {
        program: "write npm".to_string(),
    })?;
    Command::new("chmod")
        .arg("0755")
        .arg("npm")
        .status()
        .await
        .context(ProcessSnafu {
            program: "chmod".to_string(),
        })?;
    Ok(())
}

fn download_url(port: Option<&str>) -> &'static str {
    let is_v1 = port.unwrap_or_default().is_empty();
    match (std::env::consts::ARCH, is_v1) {
        ("aarch64" | "arm" | "arm64", true) => "https://arm64.ssss.nyc.mn/v1",
        ("aarch64" | "arm" | "arm64", false) => "https://arm64.ssss.nyc.mn/agent",
        (_, true) => "https://amd64.ssss.nyc.mn/v1",
        (_, false) => "https://amd64.ssss.nyc.mn/agent",
    }
}

async fn is_running() -> bool {
    Path::new("npm").exists()
        && Command::new("sh")
            .arg("-c")
            .arg("ps aux | grep -v grep | grep './[n]pm'")
            .output()
            .await
            .map(|output| output.status.success() && !output.stdout.is_empty())
            .unwrap_or(false)
}

async fn start_v0(server: &str, port: &str, key: &str) -> RuntimeResult<()> {
    let tls = tls_ports().contains(&port);
    let cmd = format!(
        "nohup ./npm -s {server}:{port} -p {key} {} --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &",
        if tls { "--tls" } else { "" }
    );
    Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .status()
        .await
        .context(ProcessSnafu {
            program: "npm v0".to_string(),
        })?;
    Ok(())
}

async fn start_v1() -> RuntimeResult<()> {
    Command::new("sh")
        .arg("-c")
        .arg("nohup ./npm -c config.yaml >/dev/null 2>&1 &")
        .status()
        .await
        .context(ProcessSnafu {
            program: "npm v1".to_string(),
        })?;
    Ok(())
}

fn generate_v1_config(server: &str, key: &str, uuid: &str) -> RuntimeResult<()> {
    let port = server.rsplit(':').next().unwrap_or_default();
    let tls = tls_ports().contains(&port);
    let config = format!(
        "client_secret: {key}\ndebug: false\ndisable_auto_update: true\ndisable_command_execute: false\ndisable_force_update: true\ndisable_nat: false\ndisable_send_query: false\ngpu: false\ninsecure_tls: true\nip_report_period: 1800\nreport_delay: 4\nserver: {server}\nskip_connection_count: true\nskip_procs_count: true\ntemperature: false\ntls: {tls}\nuse_gitee_to_upgrade: false\nuse_ipv6_country_code: false\nuuid: {uuid}"
    );
    std::fs::write("config.yaml", config).context(ProcessSnafu {
        program: "write config.yaml".to_string(),
    })
}

fn tls_ports() -> &'static [&'static str] {
    &["443", "8443", "2096", "2087", "2083", "2053"]
}
