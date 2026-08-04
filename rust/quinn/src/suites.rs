//! The profile's cipher suites with QUIC packet protection wired in.
//!
//! The TLS 1.3 machinery (hash, HKDF, record AEAD) is rustls-rustcrypto's;
//! these statics rebuild its suites with the `quic` slot populated by this
//! crate's RFC 9001 implementations, which the upstream provider leaves
//! `None`.

use rustls::crypto::CipherSuiteCommon;
use rustls::{CipherSuite, SupportedCipherSuite, Tls13CipherSuite};

use crate::packet;

const fn tls13_suite(suite: SupportedCipherSuite) -> &'static Tls13CipherSuite {
    match suite {
        SupportedCipherSuite::Tls13(inner) => inner,
        #[allow(unreachable_patterns)]
        _ => panic!("not a TLS 1.3 suite"),
    }
}

const BASE_CHACHA20_POLY1305_SHA256: &Tls13CipherSuite =
    tls13_suite(rustls_rustcrypto::TLS13_CHACHA20_POLY1305_SHA256);
const BASE_AES_128_GCM_SHA256: &Tls13CipherSuite =
    tls13_suite(rustls_rustcrypto::TLS13_AES_128_GCM_SHA256);

/// `TLS_CHACHA20_POLY1305_SHA256` with QUIC support.
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: BASE_CHACHA20_POLY1305_SHA256.common.hash_provider,
            confidentiality_limit: BASE_CHACHA20_POLY1305_SHA256.common.confidentiality_limit,
        },
        hkdf_provider: BASE_CHACHA20_POLY1305_SHA256.hkdf_provider,
        aead_alg: BASE_CHACHA20_POLY1305_SHA256.aead_alg,
        quic: Some(&packet::CHACHA20_POLY1305),
    });

/// `TLS_AES_128_GCM_SHA256` with QUIC support.
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: BASE_AES_128_GCM_SHA256.common.hash_provider,
            confidentiality_limit: BASE_AES_128_GCM_SHA256.common.confidentiality_limit,
        },
        hkdf_provider: BASE_AES_128_GCM_SHA256.hkdf_provider,
        aead_alg: BASE_AES_128_GCM_SHA256.aead_alg,
        quic: Some(&packet::AES_128_GCM),
    });
