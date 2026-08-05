//! The tls-virt scheme, shared by both deliveries (`tls-virt-guest`,
//! the wasm virtualizer component, and `tls-virt-wasmtime`, the
//! wasmtime host provider).
//!
//! An application opts a connection into transparent TLS by name: it
//! resolves `host.tls-virt.alt` instead of `host`. The interposing
//! sockets layer resolves the real name, stores `(hostname, addresses)`
//! in a [`HandleTable`], and returns a **handle address** in place of
//! the real ones: a random 64-bit suffix under a random ULA /64 prefix
//! (RFC 4193 `fd00::/8`) minted once per table. A later connect to a
//! handle address is the layer's cue to open a real connection to a
//! stored address and drive a TLS handshake with the stored hostname
//! (SNI + certificate verification); everything else passes through
//! unchanged.
//!
//! Handle addresses never appear on the wire. The random prefix keeps
//! collisions with real ULA deployments improbable; the random suffix
//! keeps handles unguessable across resolutions.
//!
//! This crate holds only the scheme — name opt-in, handle minting and
//! lookup, and destination selection — in `std::net` terms. Each
//! delivery converts its bindings' address types at the edge and owns
//! its TLS engine and data path.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// Names under this suffix opt in to TLS tunneling.
pub const SUFFIX: &str = ".tls-virt.alt";

/// The real hostname of an opted-in name, if it is one.
pub fn strip_suffix(name: &str) -> Option<&str> {
    name.strip_suffix(SUFFIX)
}

/// A resolved destination a handle address stands for.
pub struct Entry {
    /// The real hostname: the TLS server name (SNI + verification).
    pub hostname: String,
    /// The real addresses the name resolved to.
    pub addrs: Vec<IpAddr>,
}

/// The handle-address table: mints handles for resolved destinations
/// and recognizes them at connect time.
pub struct HandleTable {
    /// The random ULA /64 prefix handles are minted under.
    prefix: [u8; 8],
    /// Random 64-bit suffix → destination.
    entries: HashMap<u64, Entry>,
}

impl HandleTable {
    /// Creates a table under a fresh random `fd00::/8` prefix.
    ///
    /// Panics if the platform provides no randomness.
    pub fn new() -> Self {
        let mut prefix = [0u8; 8];
        getrandom::fill(&mut prefix).expect("randomness available");
        prefix[0] = 0xfd;
        Self {
            prefix,
            entries: HashMap::new(),
        }
    }

    /// Stores a destination and mints the handle address that stands
    /// for it.
    ///
    /// Panics if the platform provides no randomness.
    pub fn mint(&mut self, entry: Entry) -> Ipv6Addr {
        let mut suffix = [0u8; 8];
        getrandom::fill(&mut suffix).expect("randomness available");
        let key = u64::from_be_bytes(suffix);
        self.entries.insert(key, entry);
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&self.prefix);
        bytes[8..].copy_from_slice(&suffix);
        Ipv6Addr::from(bytes)
    }

    /// The destination a handle address stands for, if it is one this
    /// table minted.
    pub fn lookup(&self, addr: &Ipv6Addr) -> Option<&Entry> {
        let bytes = addr.octets();
        if bytes[..8] != self.prefix {
            return None;
        }
        let key = u64::from_be_bytes(bytes[8..].try_into().unwrap());
        self.entries.get(&key)
    }
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}

/// A destination socket-address from a resolved entry, preferring IPv6.
pub fn pick_addr(addrs: &[IpAddr], port: u16) -> Option<SocketAddr> {
    let v6 = addrs
        .iter()
        .find(|a| matches!(a, IpAddr::V6(_)))
        .or_else(|| addrs.first());
    v6.map(|ip| SocketAddr::new(*ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn suffix_opt_in() {
        assert_eq!(
            strip_suffix("example.com.tls-virt.alt"),
            Some("example.com")
        );
        assert_eq!(strip_suffix("example.com"), None);
        assert_eq!(strip_suffix(".tls-virt.alt"), Some(""));
    }

    #[test]
    fn mint_then_lookup() {
        let mut table = HandleTable::new();
        let addrs = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
        let handle = table.mint(Entry {
            hostname: "example.com".into(),
            addrs: addrs.clone(),
        });
        assert_eq!(handle.octets()[0], 0xfd);
        let entry = table.lookup(&handle).expect("handle resolves");
        assert_eq!(entry.hostname, "example.com");
        assert_eq!(entry.addrs, addrs);
    }

    #[test]
    fn non_handles_do_not_resolve() {
        let mut table = HandleTable::new();
        let handle = table.mint(Entry {
            hostname: "example.com".into(),
            addrs: vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
        });
        // Same suffix under a different prefix: not ours.
        let mut foreign = handle.octets();
        foreign[1] ^= 0xff;
        assert!(table.lookup(&Ipv6Addr::from(foreign)).is_none());
        // Loopback and unspecified are never handles.
        assert!(table.lookup(&Ipv6Addr::LOCALHOST).is_none());
        assert!(table.lookup(&Ipv6Addr::UNSPECIFIED).is_none());
    }

    #[test]
    fn tables_do_not_recognize_each_other() {
        let mut a = HandleTable::new();
        let b = HandleTable::new();
        let handle = a.mint(Entry {
            hostname: "example.com".into(),
            addrs: vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
        });
        assert!(b.lookup(&handle).is_none());
    }

    #[test]
    fn destination_prefers_ipv6() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(pick_addr(&[v4, v6], 443), Some(SocketAddr::new(v6, 443)),);
        assert_eq!(pick_addr(&[v4], 443), Some(SocketAddr::new(v4, 443)));
        assert_eq!(pick_addr(&[], 443), None);
    }
}
