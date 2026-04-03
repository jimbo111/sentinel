use crate::domain::{DetectionSource, DomainRecord};

// ---------------------------------------------------------------------------
// TLS wire-format constants
// ---------------------------------------------------------------------------

/// Byte length of a TLS record header (content_type + version + length).
const TLS_RECORD_HEADER_SIZE: usize = 5;

/// Handshake message type: ClientHello.
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

/// TLS content type for a Handshake record.
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;

/// TLS extension type: Server Name Indication.
const TLS_EXT_SERVER_NAME: u16 = 0x0000;

/// SNI name type: host_name.
const SNI_HOST_NAME_TYPE: u8 = 0x00;

/// TLS extension type: Encrypted Client Hello (ECH).
const TLS_EXT_ECH: u16 = 0xFE0D;

/// TLS extension type: supported_versions (RFC 8446).
const TLS_EXT_SUPPORTED_VERSIONS: u16 = 0x002B;

// ---------------------------------------------------------------------------
// ECH status
// ---------------------------------------------------------------------------

/// Describes the Encrypted Client Hello state detected in a ClientHello.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchStatus {
    /// No ECH extension was found.
    NotPresent,
    /// An ECH extension with `ext_len <= 4` was found (likely GREASE).
    Grease,
    /// An ECH extension with `ext_len > 4` was found.
    Active,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Attempts to extract the SNI hostname from a TLS ClientHello record and
/// return it as a [`DomainRecord`] stamped with [`DetectionSource::Sni`].
///
/// The function validates:
/// 1. `content_type == 0x16` (Handshake).
/// 2. The record body fits within `data`.
/// 3. `handshake_type == 0x01` (ClientHello).
/// 4. The ClientHello fields are structurally sound.
/// 5. An SNI extension (`0x0000`) is present and contains a `host_name` entry.
///
/// The name passes through [`DomainRecord::from_raw_name`], so noise domains,
/// IP literals, and bare hostnames are all filtered out.
///
/// Returns `None` on any structural error or failed validation instead of
/// panicking.
///
/// # Examples
///
/// ```
/// use packet_engine::tls::extract_sni;
/// use packet_engine::domain::DetectionSource;
///
/// // Build a minimal TLS 1.2 ClientHello with SNI "amazon.com".
/// let sni_name = b"amazon.com";
/// let name_len = sni_name.len() as u16;
/// let list_len = name_len + 3;
/// let ext_len  = list_len + 2;
///
/// let mut sni_ext = Vec::new();
/// sni_ext.extend_from_slice(&0x0000u16.to_be_bytes());
/// sni_ext.extend_from_slice(&ext_len.to_be_bytes());
/// sni_ext.extend_from_slice(&list_len.to_be_bytes());
/// sni_ext.push(0x00);
/// sni_ext.extend_from_slice(&name_len.to_be_bytes());
/// sni_ext.extend_from_slice(sni_name);
///
/// let mut ch = Vec::new();
/// ch.extend_from_slice(&[0x03, 0x03]);
/// ch.extend_from_slice(&[0u8; 32]);
/// ch.push(0x00);
/// ch.extend_from_slice(&[0x00, 0x02]);
/// ch.extend_from_slice(&[0x00, 0xff]);
/// ch.push(0x01);
/// ch.push(0x00);
/// ch.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
/// ch.extend_from_slice(&sni_ext);
///
/// let hs_len = ch.len() as u32;
/// let mut hs = Vec::new();
/// hs.push(0x01);
/// hs.push(((hs_len >> 16) & 0xFF) as u8);
/// hs.push(((hs_len >> 8)  & 0xFF) as u8);
/// hs.push((hs_len & 0xFF) as u8);
/// hs.extend_from_slice(&ch);
///
/// let rec_len = hs.len() as u16;
/// let mut pkt = Vec::new();
/// pkt.push(0x16);
/// pkt.extend_from_slice(&[0x03, 0x01]);
/// pkt.extend_from_slice(&rec_len.to_be_bytes());
/// pkt.extend_from_slice(&hs);
///
/// let record = extract_sni(&pkt).expect("SNI must be extracted");
/// assert_eq!(record.domain, "amazon.com");
/// assert_eq!(record.source, DetectionSource::Sni);
/// ```
#[must_use]
pub fn extract_sni(data: &[u8]) -> Option<DomainRecord> {
    // Minimum: TLS record header (5) + handshake header (4).
    if data.len() < TLS_RECORD_HEADER_SIZE + 4 {
        return None;
    }

    // --- TLS record header ------------------------------------------------
    if data[0] != TLS_CONTENT_TYPE_HANDSHAKE {
        return None;
    }

    let record_body_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let record_end = TLS_RECORD_HEADER_SIZE.checked_add(record_body_len)?;
    if data.len() < record_end {
        return None;
    }

    let body = &data[TLS_RECORD_HEADER_SIZE..record_end];

    // --- Handshake header -------------------------------------------------
    // handshake_type(1) + length(3)
    if body.len() < 4 {
        return None;
    }
    if body[0] != TLS_HANDSHAKE_CLIENT_HELLO {
        return None;
    }

    let hs_len =
        ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | (body[3] as usize);
    let hs_end = 4usize.checked_add(hs_len)?;
    if body.len() < hs_end {
        return None;
    }
    let ch = &body[4..hs_end];

    // --- ClientHello fields -----------------------------------------------
    // client_version(2) + random(32) = 34 bytes before session_id.
    if ch.len() < 34 {
        return None;
    }
    let mut pos: usize = 34;

    // session_id length (1 byte) + session_id bytes.
    let sid_len = *ch.get(pos)? as usize;
    pos = pos.checked_add(1)?.checked_add(sid_len)?;
    if ch.len() < pos {
        return None;
    }

    // cipher_suites length (2 bytes) + cipher_suites.
    if ch.len() < pos + 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos = pos.checked_add(2)?.checked_add(cs_len)?;
    if ch.len() < pos {
        return None;
    }

    // compression_methods length (1 byte) + methods.
    if ch.len() < pos + 1 {
        return None;
    }
    let cm_len = *ch.get(pos)? as usize;
    pos = pos.checked_add(1)?.checked_add(cm_len)?;
    if ch.len() < pos {
        return None;
    }

    // --- Extensions -------------------------------------------------------
    if ch.len() < pos + 2 {
        return None;
    }
    let exts_total_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos = pos.checked_add(2)?;
    let exts_end = pos.checked_add(exts_total_len)?;
    if ch.len() < exts_end {
        return None;
    }

    let extensions = &ch[pos..exts_end];
    walk_extensions_for_sni(extensions)
}

/// Attempts to extract the negotiated TLS version from a TLS ClientHello record.
///
/// The function first checks for the `supported_versions` extension (type
/// `0x002B`).  If the extension is present and contains `0x0304`, the function
/// returns `Some("1.3")` because the client is advertising TLS 1.3.
///
/// If no `supported_versions` extension is found, the function falls back to
/// reading the `client_version` field from the ClientHello body and maps it:
/// - `0x0304` → `"1.3"`
/// - `0x0303` → `"1.2"`
/// - `0x0302` → `"1.1"`
/// - `0x0301` → `"1.0"`
///
/// Returns `None` on any structural error or on an unrecognised version.
///
/// # Examples
///
/// ```
/// use packet_engine::tls::extract_tls_version;
///
/// // Minimal TLS 1.2 ClientHello (no supported_versions extension).
/// let sni_name = b"example.com";
/// let name_len = sni_name.len() as u16;
/// let list_len = name_len + 3;
/// let ext_len  = list_len + 2;
/// let mut sni_ext = Vec::new();
/// sni_ext.extend_from_slice(&0x0000u16.to_be_bytes());
/// sni_ext.extend_from_slice(&ext_len.to_be_bytes());
/// sni_ext.extend_from_slice(&list_len.to_be_bytes());
/// sni_ext.push(0x00);
/// sni_ext.extend_from_slice(&name_len.to_be_bytes());
/// sni_ext.extend_from_slice(sni_name);
///
/// let mut ch = Vec::new();
/// ch.extend_from_slice(&[0x03, 0x03]); // client_version = TLS 1.2
/// ch.extend_from_slice(&[0u8; 32]);
/// ch.push(0x00);
/// ch.extend_from_slice(&[0x00, 0x02]);
/// ch.extend_from_slice(&[0x00, 0xff]);
/// ch.push(0x01);
/// ch.push(0x00);
/// ch.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
/// ch.extend_from_slice(&sni_ext);
///
/// let hs_len = ch.len() as u32;
/// let mut hs = Vec::new();
/// hs.push(0x01);
/// hs.push(((hs_len >> 16) & 0xFF) as u8);
/// hs.push(((hs_len >> 8)  & 0xFF) as u8);
/// hs.push((hs_len & 0xFF) as u8);
/// hs.extend_from_slice(&ch);
///
/// let rec_len = hs.len() as u16;
/// let mut pkt = Vec::new();
/// pkt.push(0x16);
/// pkt.extend_from_slice(&[0x03, 0x01]);
/// pkt.extend_from_slice(&rec_len.to_be_bytes());
/// pkt.extend_from_slice(&hs);
///
/// let version = extract_tls_version(&pkt).expect("version must be extracted");
/// assert_eq!(version, "1.2");
/// ```
#[must_use]
pub fn extract_tls_version(data: &[u8]) -> Option<String> {
    // Minimum: TLS record header (5) + handshake header (4).
    if data.len() < TLS_RECORD_HEADER_SIZE + 4 {
        return None;
    }

    // --- TLS record header ------------------------------------------------
    if data[0] != TLS_CONTENT_TYPE_HANDSHAKE {
        return None;
    }

    let record_body_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let record_end = TLS_RECORD_HEADER_SIZE.checked_add(record_body_len)?;
    if data.len() < record_end {
        return None;
    }

    let body = &data[TLS_RECORD_HEADER_SIZE..record_end];

    // --- Handshake header -------------------------------------------------
    // handshake_type(1) + length(3)
    if body.len() < 4 {
        return None;
    }
    if body[0] != TLS_HANDSHAKE_CLIENT_HELLO {
        return None;
    }

    let hs_len =
        ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | (body[3] as usize);
    let hs_end = 4usize.checked_add(hs_len)?;
    if body.len() < hs_end {
        return None;
    }
    let ch = &body[4..hs_end];

    // --- ClientHello fields -----------------------------------------------
    // client_version(2) + random(32) = 34 bytes before session_id.
    if ch.len() < 34 {
        return None;
    }

    // Read client_version for the fallback path.
    let client_version = u16::from_be_bytes([ch[0], ch[1]]);

    let mut pos: usize = 34;

    // session_id length (1 byte) + session_id bytes.
    let sid_len = *ch.get(pos)? as usize;
    pos = pos.checked_add(1)?.checked_add(sid_len)?;
    if ch.len() < pos {
        return None;
    }

    // cipher_suites length (2 bytes) + cipher_suites.
    if ch.len() < pos + 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos = pos.checked_add(2)?.checked_add(cs_len)?;
    if ch.len() < pos {
        return None;
    }

    // compression_methods length (1 byte) + methods.
    if ch.len() < pos + 1 {
        return None;
    }
    let cm_len = *ch.get(pos)? as usize;
    pos = pos.checked_add(1)?.checked_add(cm_len)?;
    if ch.len() < pos {
        return None;
    }

    // --- Extensions -------------------------------------------------------
    if ch.len() < pos + 2 {
        // No extensions block — fall back to client_version.
        return map_client_version(client_version);
    }
    let exts_total_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos = pos.checked_add(2)?;
    let exts_end = pos.checked_add(exts_total_len)?;
    if ch.len() < exts_end {
        return None;
    }

    let extensions = &ch[pos..exts_end];

    // Walk extensions looking for supported_versions (0x002B).
    if let Some(version) = walk_extensions_for_supported_versions(extensions) {
        return Some(version);
    }

    // Fall back to client_version field.
    map_client_version(client_version)
}

/// Maps a two-byte TLS `client_version` field to a version string.
///
/// Returns `None` for unrecognised values.
#[must_use]
fn map_client_version(version: u16) -> Option<String> {
    match version {
        0x0304 => Some("1.3".to_string()),
        0x0303 => Some("1.2".to_string()),
        0x0302 => Some("1.1".to_string()),
        0x0301 => Some("1.0".to_string()),
        _ => None,
    }
}

/// Walks a serialised TLS extensions block looking for the `supported_versions`
/// extension (type `0x002B`).
///
/// Returns `Some("1.3")` if `0x0304` is listed in the extension's version list,
/// otherwise `None`.
#[must_use]
fn walk_extensions_for_supported_versions(extensions: &[u8]) -> Option<String> {
    let mut pos = 0usize;

    while pos + 4 <= extensions.len() {
        let ext_type = u16::from_be_bytes([extensions[pos], extensions[pos + 1]]);
        let ext_len = u16::from_be_bytes([extensions[pos + 2], extensions[pos + 3]]) as usize;
        pos += 4;

        let ext_end = pos.checked_add(ext_len)?;
        if extensions.len() < ext_end {
            break; // malformed — stop walking
        }

        if ext_type == TLS_EXT_SUPPORTED_VERSIONS {
            let ext_data = &extensions[pos..ext_end];
            // supported_versions in ClientHello:
            // versions_length (1 byte) followed by two-byte version values.
            if ext_data.is_empty() {
                break;
            }
            let versions_len = ext_data[0] as usize;
            let versions_end = 1usize.checked_add(versions_len)?;
            if ext_data.len() < versions_end {
                break;
            }
            let versions = &ext_data[1..versions_end];
            let mut i = 0;
            while i + 1 < versions.len() {
                let v = u16::from_be_bytes([versions[i], versions[i + 1]]);
                if v == 0x0304 {
                    return Some("1.3".to_string());
                }
                i += 2;
            }
            // supported_versions found but 0x0304 not in the list — no match.
            return None;
        }

        pos = ext_end;
    }

    None
}

/// Parses the body of a TLS SNI extension into a [`DomainRecord`].
///
/// `ext_data` is the raw bytes of the extension value (the bytes that come
/// after the two-byte `ext_type` and two-byte `ext_len` fields).
///
/// Wire format:
/// ```text
/// server_name_list_length (2)
///   name_type              (1)  — must be 0x00 (host_name)
///   name_length            (2)
///   name_bytes             (name_length)
/// ```
///
/// The record is stamped with [`DetectionSource::Sni`].
///
/// Returns `None` if the data is malformed or the name fails
/// [`DomainRecord::from_raw_name`] validation.
#[must_use]
pub fn parse_sni_extension(ext_data: &[u8]) -> Option<DomainRecord> {
    // Minimum: list_len(2) + name_type(1) + name_len(2) + at least 1 char.
    if ext_data.len() < 6 {
        return None;
    }

    let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
    let list_end = 2usize.checked_add(list_len)?;
    if ext_data.len() < list_end {
        return None;
    }

    let list = &ext_data[2..list_end];

    if list.len() < 3 {
        return None;
    }

    let name_type = list[0];
    if name_type != SNI_HOST_NAME_TYPE {
        return None;
    }

    let name_len = u16::from_be_bytes([list[1], list[2]]) as usize;
    let name_end = 3usize.checked_add(name_len)?;
    if list.len() < name_end {
        return None;
    }

    let name = std::str::from_utf8(&list[3..name_end]).ok()?;
    DomainRecord::from_raw_name(name).map(|r| r.with_source(DetectionSource::Sni))
}

/// Returns `true` when `tcp_payload` begins with a TLS ClientHello record.
///
/// This is a cheap pre-filter; it does not parse the full message.
/// Three conditions must hold:
/// - `content_type` at offset 0 is `0x16` (Handshake).
/// - `version_major` at offset 1 is `0x03` (SSL 3.x / TLS 1.x record layer).
/// - The byte at offset 5 is `0x01` (ClientHello handshake type).
///
/// # Examples
///
/// ```
/// use packet_engine::tls::is_tls_client_hello_start;
///
/// let mut data = vec![0u8; 10];
/// data[0] = 0x16; // content type: Handshake
/// data[1] = 0x03; // version major
/// data[2] = 0x01; // version minor
/// data[5] = 0x01; // handshake type: ClientHello
///
/// assert!(is_tls_client_hello_start(&data));
/// assert!(!is_tls_client_hello_start(&[0x17, 0x03, 0x01, 0x00, 0x05, 0x01]));
/// ```
#[must_use]
pub fn is_tls_client_hello_start(tcp_payload: &[u8]) -> bool {
    if tcp_payload.len() < TLS_RECORD_HEADER_SIZE + 1 {
        return false;
    }
    tcp_payload[0] == TLS_CONTENT_TYPE_HANDSHAKE
        && tcp_payload[1] == 0x03
        && tcp_payload[5] == TLS_HANDSHAKE_CLIENT_HELLO
}

/// Walks a serialised TLS extensions block looking for an ECH extension
/// (`0xFE0D`).
///
/// `client_hello_extensions` must be the raw extension bytes starting
/// immediately after the two-byte extensions-total-length field (i.e. the
/// same slice that [`walk_extensions_for_sni`] receives).
///
/// Returns:
/// - [`EchStatus::Active`] when the ECH extension is present with `ext_len > 4`.
/// - [`EchStatus::Grease`] when the ECH extension is present with `ext_len <= 4`.
/// - [`EchStatus::NotPresent`] when no ECH extension is found.
#[must_use]
pub fn detect_ech(client_hello_extensions: &[u8]) -> EchStatus {
    let mut pos = 0usize;

    while pos + 4 <= client_hello_extensions.len() {
        let ext_type = u16::from_be_bytes([
            client_hello_extensions[pos],
            client_hello_extensions[pos + 1],
        ]);
        let ext_len = u16::from_be_bytes([
            client_hello_extensions[pos + 2],
            client_hello_extensions[pos + 3],
        ]) as usize;
        pos += 4;

        if pos + ext_len > client_hello_extensions.len() {
            break; // malformed — stop walking
        }

        if ext_type == TLS_EXT_ECH {
            return if ext_len > 4 {
                EchStatus::Active
            } else {
                EchStatus::Grease
            };
        }

        pos += ext_len;
    }

    EchStatus::NotPresent
}

// ---------------------------------------------------------------------------
// Test helpers (compiled only during testing)
// ---------------------------------------------------------------------------

/// Builds a minimal but structurally valid TLS 1.2 ClientHello record
/// containing an SNI extension for `hostname`.
///
/// Intended for use in unit tests across crates.  The returned `Vec<u8>`
/// starts at the 5-byte TLS record header.
#[cfg(test)]
#[must_use]
pub fn build_test_client_hello(hostname: &str) -> Vec<u8> {
    let sni_body = {
        let name_bytes = hostname.as_bytes();
        let name_len = name_bytes.len() as u16;
        let list_len: u16 = 1 + 2 + name_len;
        let mut out = Vec::new();
        out.extend_from_slice(&TLS_EXT_SERVER_NAME.to_be_bytes());
        out.extend_from_slice(&(list_len + 2).to_be_bytes()); // ext_len
        out.extend_from_slice(&list_len.to_be_bytes());
        out.push(SNI_HOST_NAME_TYPE);
        out.extend_from_slice(&name_len.to_be_bytes());
        out.extend_from_slice(name_bytes);
        out
    };

    let mut ch: Vec<u8> = Vec::new();
    ch.extend_from_slice(&[0x03, 0x03]); // client_version = TLS 1.2
    ch.extend_from_slice(&[0u8; 32]); // random
    ch.push(0x00); // session_id_len = 0
    ch.extend_from_slice(&[0x00, 0x02]); // cipher_suites_len = 2
    ch.extend_from_slice(&[0x00, 0x2F]); // TLS_RSA_WITH_AES_128_CBC_SHA
    ch.push(0x01); // compression_methods_len = 1
    ch.push(0x00); // null compression
    ch.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
    ch.extend_from_slice(&sni_body);

    let hs_len = ch.len() as u32;
    let mut hs: Vec<u8> = Vec::new();
    hs.push(TLS_HANDSHAKE_CLIENT_HELLO);
    hs.push(((hs_len >> 16) & 0xFF) as u8);
    hs.push(((hs_len >> 8) & 0xFF) as u8);
    hs.push((hs_len & 0xFF) as u8);
    hs.extend_from_slice(&ch);

    let rec_len = hs.len() as u16;
    let mut rec: Vec<u8> = Vec::new();
    rec.push(TLS_CONTENT_TYPE_HANDSHAKE);
    rec.extend_from_slice(&[0x03, 0x01]);
    rec.extend_from_slice(&rec_len.to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Walks a serialised extensions block looking for the SNI extension.
fn walk_extensions_for_sni(extensions: &[u8]) -> Option<DomainRecord> {
    let mut pos = 0usize;

    while pos + 4 <= extensions.len() {
        let ext_type = u16::from_be_bytes([extensions[pos], extensions[pos + 1]]);
        let ext_len = u16::from_be_bytes([extensions[pos + 2], extensions[pos + 3]]) as usize;
        pos += 4;

        let ext_end = pos.checked_add(ext_len)?;
        if extensions.len() < ext_end {
            return None;
        }

        if ext_type == TLS_EXT_SERVER_NAME {
            return parse_sni_extension(&extensions[pos..ext_end]);
        }

        pos = ext_end;
    }

    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::DetectionSource;

    // -----------------------------------------------------------------------
    // Wire-format builder helpers
    // -----------------------------------------------------------------------

    /// Serialises an SNI extension body (the value bytes only, without the
    /// leading ext_type and ext_len fields).
    fn encode_sni_ext_body(hostname: &str) -> Vec<u8> {
        let name_bytes = hostname.as_bytes();
        let name_len = name_bytes.len() as u16;
        // ServerNameList: name_type(1) + name_len(2) + name
        let list_len: u16 = 1 + 2 + name_len;

        let mut out = Vec::new();
        out.extend_from_slice(&list_len.to_be_bytes());
        out.push(SNI_HOST_NAME_TYPE);
        out.extend_from_slice(&name_len.to_be_bytes());
        out.extend_from_slice(name_bytes);
        out
    }

    /// Builds a complete TLS ClientHello record.
    ///
    /// When `hostname` is `Some`, an SNI extension is included.
    fn build_client_hello(hostname: Option<&str>) -> Vec<u8> {
        // Extensions block.
        let mut extensions: Vec<u8> = Vec::new();
        if let Some(host) = hostname {
            let sni_body = encode_sni_ext_body(host);
            extensions.extend_from_slice(&TLS_EXT_SERVER_NAME.to_be_bytes());
            extensions.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&sni_body);
        }

        // ClientHello body.
        let mut ch: Vec<u8> = Vec::new();
        ch.extend_from_slice(&[0x03, 0x03]); // client_version = TLS 1.2
        ch.extend_from_slice(&[0u8; 32]); // random
        ch.push(0x00); // session_id_len = 0
        ch.extend_from_slice(&[0x00, 0x02]); // cipher_suites_len = 2
        ch.extend_from_slice(&[0x00, 0xFF]); // one cipher suite
        ch.push(0x01); // compression_methods_len = 1
        ch.push(0x00); // null compression
        if !extensions.is_empty() {
            ch.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            ch.extend_from_slice(&extensions);
        }

        // Handshake header: type(1) + length(3).
        let hs_len = ch.len() as u32;
        let mut hs: Vec<u8> = Vec::new();
        hs.push(TLS_HANDSHAKE_CLIENT_HELLO);
        hs.push(((hs_len >> 16) & 0xFF) as u8);
        hs.push(((hs_len >> 8) & 0xFF) as u8);
        hs.push((hs_len & 0xFF) as u8);
        hs.extend_from_slice(&ch);

        // TLS record header: content_type(1) + version(2) + length(2).
        let rec_len = hs.len() as u16;
        let mut rec: Vec<u8> = Vec::new();
        rec.push(TLS_CONTENT_TYPE_HANDSHAKE);
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&rec_len.to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    // -----------------------------------------------------------------------
    // extract_sni
    // -----------------------------------------------------------------------

    #[test]
    fn client_hello_with_sni_amazon_is_extracted() {
        let pkt = build_client_hello(Some("amazon.com"));
        let record = extract_sni(&pkt).expect("SNI must be extracted");
        assert_eq!(record.domain, "amazon.com");
        assert_eq!(record.source, DetectionSource::Sni);
    }

    #[test]
    fn client_hello_without_sni_returns_none() {
        let pkt = build_client_hello(None);
        assert!(
            extract_sni(&pkt).is_none(),
            "ClientHello without SNI must yield None"
        );
    }

    #[test]
    fn non_handshake_tls_record_returns_none() {
        // Application data record (content_type = 0x17).
        let data = [0x17u8, 0x03, 0x03, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04];
        assert!(extract_sni(&data).is_none());
    }

    #[test]
    fn truncated_data_does_not_panic() {
        let full = build_client_hello(Some("amazon.com"));
        for len in 0..full.len() {
            let _ = extract_sni(&full[..len]);
        }
    }

    #[test]
    fn noise_domain_in_sni_is_accepted() {
        // Noise filtering is the engine's responsibility, not the parser's.
        let pkt = build_client_hello(Some("apple.com"));
        let record = extract_sni(&pkt).expect("parser must accept noise domains");
        assert_eq!(record.domain, "apple.com");
    }

    // -----------------------------------------------------------------------
    // is_tls_client_hello_start
    // -----------------------------------------------------------------------

    #[test]
    fn valid_client_hello_start_detected() {
        let pkt = build_client_hello(Some("amazon.com"));
        assert!(is_tls_client_hello_start(&pkt));
    }

    #[test]
    fn non_handshake_content_type_rejected() {
        let data = [0x17u8, 0x03, 0x01, 0x00, 0x01, 0x01];
        assert!(!is_tls_client_hello_start(&data));
    }

    #[test]
    fn wrong_major_version_rejected() {
        let data = [0x16u8, 0x02, 0x01, 0x00, 0x01, 0x01];
        assert!(!is_tls_client_hello_start(&data));
    }

    #[test]
    fn server_hello_handshake_type_rejected() {
        // Handshake type 0x02 = ServerHello.
        let data = [0x16u8, 0x03, 0x01, 0x00, 0x01, 0x02];
        assert!(!is_tls_client_hello_start(&data));
    }

    #[test]
    fn too_short_data_rejected() {
        assert!(!is_tls_client_hello_start(&[0x16u8, 0x03, 0x01]));
        assert!(!is_tls_client_hello_start(&[]));
    }

    // -----------------------------------------------------------------------
    // detect_ech
    // -----------------------------------------------------------------------

    #[test]
    fn no_ech_extension_is_not_present() {
        // Only an SNI extension — no ECH.
        let sni_body = encode_sni_ext_body("amazon.com");
        let mut exts: Vec<u8> = Vec::new();
        exts.extend_from_slice(&TLS_EXT_SERVER_NAME.to_be_bytes());
        exts.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_body);
        assert_eq!(detect_ech(&exts), EchStatus::NotPresent);
    }

    #[test]
    fn ech_active_detected() {
        let mut exts: Vec<u8> = Vec::new();
        exts.extend_from_slice(&TLS_EXT_ECH.to_be_bytes());
        exts.extend_from_slice(&8u16.to_be_bytes()); // ext_len = 8 > 4
        exts.extend_from_slice(&[0u8; 8]);
        assert_eq!(detect_ech(&exts), EchStatus::Active);
    }

    #[test]
    fn ech_grease_detected() {
        let mut exts: Vec<u8> = Vec::new();
        exts.extend_from_slice(&TLS_EXT_ECH.to_be_bytes());
        exts.extend_from_slice(&4u16.to_be_bytes()); // ext_len = 4, not > 4
        exts.extend_from_slice(&[0u8; 4]);
        assert_eq!(detect_ech(&exts), EchStatus::Grease);
    }

    // -----------------------------------------------------------------------
    // parse_sni_extension
    // -----------------------------------------------------------------------

    #[test]
    fn valid_sni_body_parsed() {
        let body = encode_sni_ext_body("example.com");
        let record = parse_sni_extension(&body).expect("should parse");
        assert_eq!(record.domain, "example.com");
        assert_eq!(record.source, DetectionSource::Sni);
    }

    #[test]
    fn truncated_sni_body_does_not_panic() {
        let body = encode_sni_ext_body("example.com");
        for len in 0..body.len() {
            let _ = parse_sni_extension(&body[..len]);
        }
    }

    // -----------------------------------------------------------------------
    // extract_tls_version
    // -----------------------------------------------------------------------

    /// Builds a ClientHello with the given `client_version` and no
    /// `supported_versions` extension (so the fallback path is exercised).
    fn build_client_hello_with_version(client_version: u16, hostname: Option<&str>) -> Vec<u8> {
        // Extensions block.
        let mut extensions: Vec<u8> = Vec::new();
        if let Some(host) = hostname {
            let sni_body = encode_sni_ext_body(host);
            extensions.extend_from_slice(&TLS_EXT_SERVER_NAME.to_be_bytes());
            extensions.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&sni_body);
        }

        let mut ch: Vec<u8> = Vec::new();
        ch.push((client_version >> 8) as u8);
        ch.push((client_version & 0xFF) as u8);
        ch.extend_from_slice(&[0u8; 32]); // random
        ch.push(0x00); // session_id_len = 0
        ch.extend_from_slice(&[0x00, 0x02]); // cipher_suites_len = 2
        ch.extend_from_slice(&[0x00, 0xFF]);
        ch.push(0x01); // compression_methods_len = 1
        ch.push(0x00); // null compression
        if !extensions.is_empty() {
            ch.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            ch.extend_from_slice(&extensions);
        }

        let hs_len = ch.len() as u32;
        let mut hs: Vec<u8> = Vec::new();
        hs.push(TLS_HANDSHAKE_CLIENT_HELLO);
        hs.push(((hs_len >> 16) & 0xFF) as u8);
        hs.push(((hs_len >> 8) & 0xFF) as u8);
        hs.push((hs_len & 0xFF) as u8);
        hs.extend_from_slice(&ch);

        let rec_len = hs.len() as u16;
        let mut rec: Vec<u8> = Vec::new();
        rec.push(TLS_CONTENT_TYPE_HANDSHAKE);
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&rec_len.to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// Builds a ClientHello with a `supported_versions` extension listing the
    /// given versions (two-byte values, big-endian).
    fn build_client_hello_with_supported_versions(versions: &[u16]) -> Vec<u8> {
        // supported_versions extension body: length(1) + version entries.
        let versions_bytes: Vec<u8> = versions
            .iter()
            .flat_map(|v| v.to_be_bytes())
            .collect();
        let mut sv_ext_body: Vec<u8> = Vec::new();
        sv_ext_body.push(versions_bytes.len() as u8);
        sv_ext_body.extend_from_slice(&versions_bytes);

        let mut extensions: Vec<u8> = Vec::new();
        extensions.extend_from_slice(&TLS_EXT_SUPPORTED_VERSIONS.to_be_bytes());
        extensions.extend_from_slice(&(sv_ext_body.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sv_ext_body);

        // Use client_version = 0x0303 (TLS 1.2 legacy value for TLS 1.3 hellos).
        let client_version: u16 = 0x0303;
        let mut ch: Vec<u8> = Vec::new();
        ch.push((client_version >> 8) as u8);
        ch.push((client_version & 0xFF) as u8);
        ch.extend_from_slice(&[0u8; 32]); // random
        ch.push(0x00); // session_id_len = 0
        ch.extend_from_slice(&[0x00, 0x02]); // cipher_suites_len = 2
        ch.extend_from_slice(&[0x00, 0xFF]);
        ch.push(0x01); // compression_methods_len = 1
        ch.push(0x00);
        ch.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        ch.extend_from_slice(&extensions);

        let hs_len = ch.len() as u32;
        let mut hs: Vec<u8> = Vec::new();
        hs.push(TLS_HANDSHAKE_CLIENT_HELLO);
        hs.push(((hs_len >> 16) & 0xFF) as u8);
        hs.push(((hs_len >> 8) & 0xFF) as u8);
        hs.push((hs_len & 0xFF) as u8);
        hs.extend_from_slice(&ch);

        let rec_len = hs.len() as u16;
        let mut rec: Vec<u8> = Vec::new();
        rec.push(TLS_CONTENT_TYPE_HANDSHAKE);
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&rec_len.to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn test_tls_version_1_2_extraction() {
        // client_version = 0x0303, no supported_versions extension.
        let pkt = build_client_hello_with_version(0x0303, Some("example.com"));
        let version = extract_tls_version(&pkt).expect("version must be extracted");
        assert_eq!(version, "1.2");
    }

    #[test]
    fn test_tls_version_1_3_extraction() {
        // supported_versions lists 0x0304 — must return "1.3".
        let pkt = build_client_hello_with_supported_versions(&[0x0304, 0x0303]);
        let version = extract_tls_version(&pkt).expect("version must be extracted");
        assert_eq!(version, "1.3");
    }

    #[test]
    fn test_tls_version_1_1_via_client_version() {
        let pkt = build_client_hello_with_version(0x0302, None);
        let version = extract_tls_version(&pkt).expect("version must be extracted");
        assert_eq!(version, "1.1");
    }

    #[test]
    fn test_tls_version_1_0_via_client_version() {
        let pkt = build_client_hello_with_version(0x0301, None);
        let version = extract_tls_version(&pkt).expect("version must be extracted");
        assert_eq!(version, "1.0");
    }

    #[test]
    fn test_tls_version_not_present_for_non_hello() {
        // Application data record.
        let data = [0x17u8, 0x03, 0x03, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04];
        assert!(extract_tls_version(&data).is_none());
    }

    #[test]
    fn test_tls_version_supported_versions_without_tls13() {
        // supported_versions present but only lists 0x0303 — no 1.3.
        // The extension is found but 0x0304 is absent, so walk_extensions_for_supported_versions
        // returns None and we fall back to the client_version field (0x0303 → "1.2").
        let pkt = build_client_hello_with_supported_versions(&[0x0303]);
        let version = extract_tls_version(&pkt).expect("version must be extracted via fallback");
        assert_eq!(
            version, "1.2",
            "when supported_versions lacks 0x0304, fall back to client_version 0x0303 → 1.2"
        );
    }

    #[test]
    fn test_tls_version_truncated_does_not_panic() {
        let pkt = build_client_hello_with_version(0x0303, Some("example.com"));
        for len in 0..pkt.len() {
            let _ = extract_tls_version(&pkt[..len]);
        }
    }
}
