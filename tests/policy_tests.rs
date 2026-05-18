use rws::policy::{BlockedDomainPolicy, DomainPolicy};

#[test]
fn blocks_speedtest_domains_and_subdomains_case_insensitively() {
    let policy = BlockedDomainPolicy::default();

    assert!(policy.is_blocked("speedtest.net"));
    assert!(policy.is_blocked("www.SpeedTest.Net"));
    assert!(policy.is_blocked("assets.speed.cloudflare.com"));
}

#[test]
fn allows_unlisted_domains() {
    let policy = BlockedDomainPolicy::default();

    assert!(!policy.is_blocked("example.com"));
    assert!(!policy.is_blocked(""));
}
