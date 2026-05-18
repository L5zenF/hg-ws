use base64::Engine;
use rws::config::Config;
use rws::subscription::{generate_subscription, IpInfo};

#[test]
fn config_uses_uuid_prefix_as_default_ws_path() {
    let config = Config::from_pairs([
        ("UUID", "5efabea4-f6d4-91fd-b8f0-17e004c89c60"),
        ("PORT", "3000"),
    ])
    .unwrap();

    assert_eq!(config.ws_path, "5efabea4");
    assert_eq!(config.sub_path, "sub");
    assert_eq!(config.port, 3000);
}

#[test]
fn config_rejects_invalid_uuid() {
    let err = Config::from_pairs([("UUID", "not-a-uuid")]).unwrap_err();
    assert!(err.to_string().contains("invalid UUID"));
}

#[test]
fn subscription_contains_all_supported_protocols() {
    let config = Config::from_pairs([
        ("UUID", "5efabea4-f6d4-91fd-b8f0-17e004c89c60"),
        ("WSPATH", "edge"),
        ("NAME", "Prod"),
    ])
    .unwrap();

    let encoded = generate_subscription(
        &config,
        &IpInfo {
            domain: "node.example.com".to_string(),
            tls: true,
            port: 443,
        },
        "US-Acme_ISP",
    );
    let decoded = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap(),
    )
    .unwrap();

    assert!(decoded.contains("vless://5efabea4-f6d4-91fd-b8f0-17e004c89c60@node.example.com:443"));
    assert!(decoded.contains("trojan://5efabea4-f6d4-91fd-b8f0-17e004c89c60@node.example.com:443"));
    assert!(decoded.contains("ss://"));
    assert!(decoded.contains("path=%2Fedge"));
    assert!(decoded.contains("#Prod-US-Acme_ISP"));
}
