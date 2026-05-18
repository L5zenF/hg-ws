use std::{sync::Arc, time::Duration};

use reqwest::Client;

use crate::{
    application::ports::AppDeps,
    domain::policy::BlockedDomainPolicy,
    infrastructure::{
        dns::DohResolver, external::HttpExternalServices, monitor::NezhaMonitor,
        runtime::TokioConnector,
    },
};

pub fn production_deps() -> AppDeps {
    let http = Client::builder()
        .timeout(Duration::from_secs(8))
        .pool_idle_timeout(Duration::from_secs(60))
        .user_agent("rws/0.1")
        .build()
        .expect("reqwest client config is static and valid");

    let resolver = Arc::new(DohResolver::new(http.clone(), Duration::from_secs(5)));
    let external = Arc::new(HttpExternalServices::new(http.clone()));
    AppDeps {
        resolver,
        policy: Arc::new(BlockedDomainPolicy::default()),
        connector: Arc::new(TokioConnector::new(Duration::from_secs(10))),
        public_ip: external.clone(),
        isp: external.clone(),
        keep_alive: external,
        monitor: Arc::new(NezhaMonitor::new(http)),
    }
}
