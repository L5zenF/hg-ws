use rws::protocol::{parse_first_packet, ProtocolKind};
use uuid::Uuid;

fn test_uuid() -> Uuid {
    Uuid::parse_str("5efabea4-f6d4-91fd-b8f0-17e004c89c60").unwrap()
}

#[test]
fn parses_vless_domain_request_and_keeps_payload_offset() {
    let uuid = test_uuid();
    let mut packet = Vec::new();
    packet.push(0);
    packet.extend_from_slice(uuid.as_bytes());
    packet.push(0);
    packet.push(1);
    packet.extend_from_slice(&443u16.to_be_bytes());
    packet.push(2);
    packet.push(11);
    packet.extend_from_slice(b"example.com");
    packet.extend_from_slice(b"hello");

    let request = parse_first_packet(&packet, uuid).unwrap();

    assert_eq!(request.protocol, ProtocolKind::Vless);
    assert_eq!(request.destination.host, "example.com");
    assert_eq!(request.destination.port, 443);
    assert_eq!(&packet[request.payload_offset..], b"hello");
    assert_eq!(request.handshake_response.as_deref(), Some(&[0, 0][..]));
}

#[test]
fn parses_trojan_domain_request_with_crlf_markers() {
    let uuid = test_uuid();
    let hash = rws::protocol::trojan_password_hash(uuid);
    let mut packet = Vec::new();
    packet.extend_from_slice(hash.as_bytes());
    packet.extend_from_slice(b"\r\n");
    packet.push(1);
    packet.push(3);
    packet.push(11);
    packet.extend_from_slice(b"example.net");
    packet.extend_from_slice(&8443u16.to_be_bytes());
    packet.extend_from_slice(b"\r\npayload");

    let request = parse_first_packet(&packet, uuid).unwrap();

    assert_eq!(request.protocol, ProtocolKind::Trojan);
    assert_eq!(request.destination.host, "example.net");
    assert_eq!(request.destination.port, 8443);
    assert_eq!(&packet[request.payload_offset..], b"payload");
    assert!(request.handshake_response.is_none());
}

#[test]
fn parses_shadowsocks_ipv4_request() {
    let uuid = test_uuid();
    let mut packet = Vec::new();
    packet.push(1);
    packet.extend_from_slice(&[8, 8, 8, 8]);
    packet.extend_from_slice(&53u16.to_be_bytes());
    packet.extend_from_slice(b"dns-query");

    let request = parse_first_packet(&packet, uuid).unwrap();

    assert_eq!(request.protocol, ProtocolKind::Shadowsocks);
    assert_eq!(request.destination.host, "8.8.8.8");
    assert_eq!(request.destination.port, 53);
    assert_eq!(&packet[request.payload_offset..], b"dns-query");
}

#[test]
fn rejects_wrong_uuid_vless_packet() {
    let uuid = test_uuid();
    let mut packet = Vec::new();
    packet.push(0);
    packet.extend_from_slice(Uuid::new_v4().as_bytes());
    packet.push(0);
    packet.push(1);
    packet.extend_from_slice(&443u16.to_be_bytes());
    packet.push(2);
    packet.push(11);
    packet.extend_from_slice(b"example.com");

    assert!(parse_first_packet(&packet, uuid).is_err());
}
