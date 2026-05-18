use base64::Engine;

use crate::application::config::Config;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpInfo {
    pub domain: String,
    pub tls: bool,
    pub port: u16,
}

pub fn generate_subscription(config: &Config, ip: &IpInfo, isp: &str) -> String {
    let name = match config.name.as_deref() {
        Some(name) => format!("{name}-{isp}"),
        None => isp.to_string(),
    };
    let escaped_name = query_escape(&name);
    let security = if ip.tls { "tls" } else { "none" };
    let ss_tls = if ip.tls { "tls;" } else { "" };
    let ws_path = format!("%2F{}", query_escape(&config.ws_path));

    let vless = format!(
        "vless://{}@{}:{}?encryption=none&security={}&sni={}&fp=chrome&type=ws&host={}&path={}#{}",
        config.uuid_text, ip.domain, ip.port, security, ip.domain, ip.domain, ws_path, escaped_name
    );
    let trojan = format!(
        "trojan://{}@{}:{}?security={}&sni={}&fp=chrome&type=ws&host={}&path={}#{}",
        config.uuid_text, ip.domain, ip.port, security, ip.domain, ip.domain, ws_path, escaped_name
    );
    let ss_method_password =
        base64::engine::general_purpose::STANDARD.encode(format!("none:{}", config.uuid_text));
    let ss = format!(
        "ss://{}@{}:{}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D{};path%3D{};{}sni%3D{};skip-cert-verify%3Dtrue;mux%3D0#{}",
        ss_method_password,
        ip.domain,
        ip.port,
        ip.domain,
        ws_path,
        ss_tls,
        ip.domain,
        escaped_name
    );

    base64::engine::general_purpose::STANDARD.encode(format!("{vless}\n{trojan}\n{ss}"))
}

fn query_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(hex(byte >> 4));
                out.push(hex(byte & 0x0f));
            }
        }
    }
    out
}

fn hex(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'A' + nibble - 10) as char,
        _ => unreachable!("nibble must be <= 15"),
    }
}
