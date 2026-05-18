use sha2::{Digest, Sha224};
use snafu::{ensure, Snafu};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolKind {
    Vless,
    Trojan,
    Shadowsocks,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyRequest {
    pub protocol: ProtocolKind,
    pub destination: Destination,
    pub payload_offset: usize,
    pub handshake_response: Option<Vec<u8>>,
}

#[derive(Debug, Snafu)]
pub enum ProtocolError {
    #[snafu(display("packet is too short for {protocol} at offset {offset}"))]
    Truncated {
        protocol: &'static str,
        offset: usize,
    },

    #[snafu(display("unsupported {protocol} command {command}"))]
    UnsupportedCommand { protocol: &'static str, command: u8 },

    #[snafu(display("unsupported {protocol} address type {atyp}"))]
    UnsupportedAddress { protocol: &'static str, atyp: u8 },

    #[snafu(display("authentication failed for {protocol}"))]
    Authentication { protocol: &'static str },

    #[snafu(display("unknown protocol"))]
    UnknownProtocol,
}

pub fn parse_first_packet(packet: &[u8], uuid: Uuid) -> Result<ProxyRequest, ProtocolError> {
    if is_vless_candidate(packet) {
        return parse_vless(packet, uuid);
    }

    if is_trojan_candidate(packet) {
        return parse_trojan(packet, uuid);
    }

    if is_shadowsocks_candidate(packet) {
        return parse_shadowsocks(packet);
    }

    Err(ProtocolError::UnknownProtocol)
}

pub fn trojan_password_hash(uuid: Uuid) -> String {
    let mut hasher = Sha224::new();
    hasher.update(uuid.hyphenated().to_string().as_bytes());
    to_lower_hex(&hasher.finalize())
}

fn parse_vless(packet: &[u8], uuid: Uuid) -> Result<ProxyRequest, ProtocolError> {
    let protocol = "VLESS";
    require_len(packet, 18, protocol, 0)?;
    ensure!(
        packet[0] == 0,
        UnsupportedCommandSnafu {
            protocol,
            command: packet[0]
        }
    );
    ensure!(
        &packet[1..17] == uuid.as_bytes(),
        AuthenticationSnafu { protocol }
    );

    let opt_len = packet[17] as usize;
    let mut offset = 18 + opt_len;
    require_len(packet, offset + 4, protocol, offset)?;

    let command = packet[offset];
    offset += 1;
    ensure!(command == 1, UnsupportedCommandSnafu { protocol, command });

    let port = read_port(packet, &mut offset, protocol)?;
    let atyp = read_u8(packet, &mut offset, protocol)?;
    let host = read_address(packet, &mut offset, protocol, atyp, AddressMapping::Vless)?;

    Ok(ProxyRequest {
        protocol: ProtocolKind::Vless,
        destination: Destination { host, port },
        payload_offset: offset,
        handshake_response: Some(vec![0, 0]),
    })
}

fn parse_trojan(packet: &[u8], uuid: Uuid) -> Result<ProxyRequest, ProtocolError> {
    let protocol = "Trojan";
    require_len(packet, 58, protocol, 0)?;
    let expected = trojan_password_hash(uuid);
    ensure!(
        packet.get(..56) == Some(expected.as_bytes()),
        AuthenticationSnafu { protocol }
    );

    let mut offset = 56;
    skip_crlf(packet, &mut offset);

    let command = read_u8(packet, &mut offset, protocol)?;
    ensure!(command == 1, UnsupportedCommandSnafu { protocol, command });

    let atyp = read_u8(packet, &mut offset, protocol)?;
    let host = read_address(packet, &mut offset, protocol, atyp, AddressMapping::Socks)?;
    let port = read_port(packet, &mut offset, protocol)?;
    skip_crlf(packet, &mut offset);

    Ok(ProxyRequest {
        protocol: ProtocolKind::Trojan,
        destination: Destination { host, port },
        payload_offset: offset,
        handshake_response: None,
    })
}

fn parse_shadowsocks(packet: &[u8]) -> Result<ProxyRequest, ProtocolError> {
    let protocol = "Shadowsocks";
    let mut offset = 0;
    let atyp = read_u8(packet, &mut offset, protocol)?;
    let host = read_address(packet, &mut offset, protocol, atyp, AddressMapping::Socks)?;
    let port = read_port(packet, &mut offset, protocol)?;

    Ok(ProxyRequest {
        protocol: ProtocolKind::Shadowsocks,
        destination: Destination { host, port },
        payload_offset: offset,
        handshake_response: None,
    })
}

fn is_vless_candidate(packet: &[u8]) -> bool {
    packet.len() > 17 && packet[0] == 0
}

fn is_trojan_candidate(packet: &[u8]) -> bool {
    packet.len() >= 58
}

fn is_shadowsocks_candidate(packet: &[u8]) -> bool {
    matches!(packet.first(), Some(0x01 | 0x03 | 0x04))
}

fn read_u8(packet: &[u8], offset: &mut usize, protocol: &'static str) -> Result<u8, ProtocolError> {
    require_len(packet, *offset + 1, protocol, *offset)?;
    let value = packet[*offset];
    *offset += 1;
    Ok(value)
}

fn read_port(
    packet: &[u8],
    offset: &mut usize,
    protocol: &'static str,
) -> Result<u16, ProtocolError> {
    require_len(packet, *offset + 2, protocol, *offset)?;
    let port = u16::from_be_bytes([packet[*offset], packet[*offset + 1]]);
    *offset += 2;
    Ok(port)
}

#[derive(Debug, Clone, Copy)]
enum AddressMapping {
    Vless,
    Socks,
}

fn read_address(
    packet: &[u8],
    offset: &mut usize,
    protocol: &'static str,
    atyp: u8,
    mapping: AddressMapping,
) -> Result<String, ProtocolError> {
    match (mapping, atyp) {
        (AddressMapping::Vless, 1) | (AddressMapping::Socks, 0x01) => {
            require_len(packet, *offset + 4, protocol, *offset)?;
            let host = format!(
                "{}.{}.{}.{}",
                packet[*offset],
                packet[*offset + 1],
                packet[*offset + 2],
                packet[*offset + 3]
            );
            *offset += 4;
            Ok(host)
        }
        (AddressMapping::Vless, 2) | (AddressMapping::Socks, 0x03) => {
            let len = read_u8(packet, offset, protocol)? as usize;
            require_len(packet, *offset + len, protocol, *offset)?;
            let host = String::from_utf8_lossy(&packet[*offset..*offset + len]).into_owned();
            *offset += len;
            Ok(host)
        }
        (AddressMapping::Vless, 3) | (AddressMapping::Socks, 0x04) => {
            require_len(packet, *offset + 16, protocol, *offset)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[*offset..*offset + 16]);
            *offset += 16;
            Ok(std::net::Ipv6Addr::from(octets).to_string())
        }
        _ => Err(ProtocolError::UnsupportedAddress { protocol, atyp }),
    }
}

fn skip_crlf(packet: &[u8], offset: &mut usize) {
    if packet.get(*offset..*offset + 2) == Some(b"\r\n") {
        *offset += 2;
    }
}

fn require_len(
    packet: &[u8],
    required: usize,
    protocol: &'static str,
    offset: usize,
) -> Result<(), ProtocolError> {
    ensure!(
        packet.len() >= required,
        TruncatedSnafu { protocol, offset }
    );
    Ok(())
}

fn to_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
