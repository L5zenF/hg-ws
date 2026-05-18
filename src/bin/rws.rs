use std::net::SocketAddr;

use rws::{app, bootstrap::production_deps, config::Config};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rws=info,tower_http=warn".into()),
        )
        .init();

    let config = Config::from_env()?;
    let deps = production_deps();
    deps.validate()?;

    if config.auto_access {
        if let Some(domain) = config.domain.clone() {
            let sub_path = config.sub_path.clone();
            let keep_alive = deps.keep_alive.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                if let Err(error) = keep_alive.add_access_task(&domain, &sub_path).await {
                    tracing::warn!(%error, "failed to add keep-alive access task");
                }
            });
        }
    }

    if config.nezha_server.is_some() && config.nezha_key.is_some() {
        let monitor = deps.monitor.clone();
        let monitor_config = config.clone();
        tokio::spawn(async move {
            if let Err(error) = monitor.start(&monitor_config).await {
                tracing::warn!(%error, "failed to start Nezha monitor");
            }
        });
        let monitor = deps.monitor.clone();
        tokio::spawn(async move {
            if let Err(error) = monitor.cleanup_later().await {
                tracing::warn!(%error, "failed to cleanup Nezha monitor files");
            }
        });
    }

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let router = app::router(app::AppState { config, deps });
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "server is running");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
