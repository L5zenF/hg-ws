pub trait DomainPolicy: Send + Sync {
    fn is_blocked(&self, host: &str) -> bool;
}

#[derive(Debug, Clone)]
pub struct BlockedDomainPolicy {
    blocked_domains: &'static [&'static str],
}

impl Default for BlockedDomainPolicy {
    fn default() -> Self {
        Self {
            blocked_domains: &[
                "speedtest.net",
                "fast.com",
                "speedtest.cn",
                "speed.cloudflare.com",
                "speedof.me",
                "testmy.net",
                "bandwidth.place",
                "speed.io",
                "librespeed.org",
                "speedcheck.org",
            ],
        }
    }
}

impl DomainPolicy for BlockedDomainPolicy {
    fn is_blocked(&self, host: &str) -> bool {
        if host.is_empty() {
            return false;
        }

        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.blocked_domains
            .iter()
            .any(|blocked| host == *blocked || host.ends_with(&format!(".{blocked}")))
    }
}
