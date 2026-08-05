//! Benchmark harness for the profile's TLS/QUIC deliveries.
//!
//! One binary, two build targets: compiled natively and to
//! wasm32-wasip2, it runs identical code in both environments, so a
//! native-vs-wasm comparison isolates the environment (hardware AES/
//! carryless multiply vs the fixsliced software path; native codegen vs
//! Wasmtime) rather than implementation differences.
//!
//! Subcommands:
//!
//! ```text
//! tls-bench aead       QUIC packet protection (RFC 9001 seal/open),
//!                      both profile suites, representative sizes
//! tls-bench handshake  TLS 1.3 handshakes over in-memory transport
//!                      (Ed25519 identity, fixture PKI)
//! tls-bench bulk       TLS 1.3 record-path throughput over in-memory
//!                      transport, both profile suites
//! tls-bench all        everything above
//! ```
//!
//! Methodology: each measurement warms up, then runs a fixed batch
//! count and reports the median batch rate (see `bench/README.md` for
//! the caveats). Output is one CSV line per measurement on stdout:
//!
//! ```text
//! bench,<name>,<detail>,<unit>,<median>,<min>,<max>
//! ```

use std::sync::Arc;
use std::time::Instant;

use rustls::crypto::CryptoProvider;
use rustls::quic;
use rustls::{CipherSuite, ClientConnection, ServerConnection, SupportedCipherSuite};
use rustls_pki_types::{CertificateDer, ServerName};

const CA_DER: &[u8] = include_bytes!("../../../rust/quinn/tests/testdata/ca.der");
const LEAF_DER: &[u8] = include_bytes!("../../../rust/quinn/tests/testdata/leaf.der");
const LEAF_KEY_P8: &[u8] = include_bytes!("../../../rust/quinn/tests/testdata/leaf-key.p8");

/// Payload sizes for the packet-protection rows: a small control
/// packet, a full QUIC datagram, and a full TLS record.
const AEAD_SIZES: &[usize] = &[256, 1200, 16384];

/// Batches per measurement; the reported figure is the median batch.
const BATCHES: usize = 9;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("aead") => aead(),
        Some("handshake") => handshake(),
        Some("bulk") => bulk(),
        Some("all") => {
            aead();
            handshake();
            bulk();
        }
        _ => {
            eprintln!(
                "usage: {} <aead|handshake|bulk|all>",
                args.first().map(String::as_str).unwrap_or("tls-bench"),
            );
            std::process::exit(2);
        }
    }
}

/// Runs `op` in timed batches (after one warmup batch) and reports the
/// median/min/max per-batch rate via `row`.
fn measure(
    iters_per_batch: usize,
    mut op: impl FnMut(),
    row: impl FnOnce(/* median */ f64, /* min */ f64, /* max */ f64),
) {
    let batch = |op: &mut dyn FnMut()| {
        let start = Instant::now();
        for _ in 0..iters_per_batch {
            op();
        }
        start.elapsed().as_secs_f64() / iters_per_batch as f64
    };
    batch(&mut op); // warmup
    let mut seconds_per_iter: Vec<f64> = (0..BATCHES).map(|_| batch(&mut op)).collect();
    seconds_per_iter.sort_by(|a, b| a.total_cmp(b));
    let median = seconds_per_iter[seconds_per_iter.len() / 2];
    // Rates invert the ordering: fastest batch is the max rate.
    row(
        median,
        *seconds_per_iter.last().unwrap(),
        seconds_per_iter[0],
    );
}

fn suite_label(suite: CipherSuite) -> &'static str {
    match suite {
        CipherSuite::TLS13_AES_128_GCM_SHA256 => "aes-128-gcm",
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => "chacha20-poly1305",
        _ => "unknown",
    }
}

// --- QUIC packet protection ---

fn aead() {
    for suite in lann_tls_quinn::provider().cipher_suites.iter() {
        let label = suite_label(suite.suite());
        let tls13 = suite.tls13().expect("profile suites are TLS 1.3");
        let algorithm = tls13
            .quic
            .expect("quinn provider suites carry QUIC support");
        for &size in AEAD_SIZES {
            aead_suite_size(tls13, algorithm, label, size);
        }
    }
}

fn aead_suite_size(
    tls13: &'static rustls::Tls13CipherSuite,
    algorithm: &'static dyn quic::Algorithm,
    label: &str,
    size: usize,
) {
    // Key material through the public initial-secrets derivation (the
    // same path quinn uses); the bench measures the seal/open path, so
    // the derivation happens once, outside the timed loop. The
    // derivation is suite-generic even though real QUIC uses AES-only
    // initial keys.
    let keys = quic::Keys::initial(
        quic::Version::V1,
        tls13,
        algorithm,
        &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08],
        rustls::Side::Client,
    );
    let packet = keys.local.packet;
    let header_key = keys.local.header;

    let header = [0x42u8, 0xc0, 0xff, 0xee];
    let mut payload = vec![0xa5u8; size + packet.tag_len()];
    let plain_len = size;

    // Seal: encrypt in place, appending the tag where open expects it.
    let mut packet_number = 0u64;
    measure(
        aead_iters(size),
        || {
            let tag = packet
                .encrypt_in_place(packet_number, &header, &mut payload[..plain_len])
                .expect("seal");
            payload[plain_len..].copy_from_slice(tag.as_ref());
            packet_number += 1;
        },
        |median, min, max| rate_row("aead-seal", label, size, median, min, max),
    );

    // Open: decrypt the last sealed packet, restoring it afterwards so
    // every iteration decrypts authentic input.
    let sealed = payload.clone();
    let sealed_pn = packet_number - 1;
    measure(
        aead_iters(size),
        || {
            payload.copy_from_slice(&sealed);
            packet
                .decrypt_in_place(sealed_pn, &header, &mut payload)
                .expect("open");
        },
        |median, min, max| rate_row("aead-open", label, size, median, min, max),
    );

    // Header protection mask application (sample-derived, RFC 9001 §5.4).
    let sample = [0x5au8; 16];
    let mut first = 0x42u8;
    let mut pn_bytes = [0u8; 4];
    measure(
        200_000,
        || {
            header_key
                .encrypt_in_place(&sample, &mut first, &mut pn_bytes[..])
                .expect("mask");
        },
        |median, min, max| {
            println!(
                "bench,header-mask,{label},ns/op,{:.0},{:.0},{:.0}",
                median * 1e9,
                min * 1e9,
                max * 1e9,
            );
        },
    );
}

/// Iteration counts sized so a batch is milliseconds even at wasm
/// speeds.
fn aead_iters(size: usize) -> usize {
    match size {
        0..=512 => 20_000,
        513..=4096 => 5_000,
        _ => 1_000,
    }
}

fn rate_row(name: &str, label: &str, size: usize, median: f64, min: f64, max: f64) {
    let mb = |seconds_per_iter: f64| size as f64 / seconds_per_iter / 1e6;
    println!(
        "bench,{name},{label}/{size},MB/s,{:.1},{:.1},{:.1}",
        mb(median),
        mb(min),
        mb(max),
    );
}

// --- TLS 1.3 over in-memory transport ---

/// A provider restricted to one profile suite, for per-suite rows.
fn single_suite_provider(suite: SupportedCipherSuite) -> Arc<CryptoProvider> {
    let base = lann_tls::provider();
    Arc::new(CryptoProvider {
        cipher_suites: vec![suite],
        ..Arc::try_unwrap(base).unwrap_or_else(|arc| (*arc).clone())
    })
}

fn configs(
    provider: Option<Arc<CryptoProvider>>,
) -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(CA_DER.to_vec()))
        .expect("fixture CA");
    let identity = lann_tls_profile::Ed25519Identity::from_pkcs8_der(
        vec![CertificateDer::from(LEAF_DER.to_vec())],
        LEAF_KEY_P8,
    )
    .expect("fixture identity");

    let (client, server) = match provider {
        Some(provider) => {
            let client = rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let (chain, key) = {
                let identity = lann_tls_profile::ServerIdentity::Ed25519(identity);
                match identity {
                    lann_tls_profile::ServerIdentity::Ed25519(id) => id.into_parts(),
                    _ => unreachable!(),
                }
            };
            let server = rustls::ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .expect("fixture identity");
            (client, server)
        }
        None => (
            lann_tls::client_config(roots),
            lann_tls::server_config(lann_tls_profile::ServerIdentity::Ed25519(identity))
                .expect("fixture identity"),
        ),
    };
    (Arc::new(client), Arc::new(server))
}

/// Drives both connections until neither wants to move handshake bytes.
fn pump(client: &mut ClientConnection, server: &mut ServerConnection) {
    let mut buf = Vec::with_capacity(32 * 1024);
    loop {
        let mut moved = false;
        buf.clear();
        while client.wants_write() {
            client.write_tls(&mut buf).expect("client write_tls");
        }
        if !buf.is_empty() {
            let mut slice = buf.as_slice();
            while !slice.is_empty() {
                let n = server.read_tls(&mut slice).expect("server read_tls");
                assert!(n > 0);
            }
            server.process_new_packets().expect("server packets");
            moved = true;
        }
        buf.clear();
        while server.wants_write() {
            server.write_tls(&mut buf).expect("server write_tls");
        }
        if !buf.is_empty() {
            let mut slice = buf.as_slice();
            while !slice.is_empty() {
                let n = client.read_tls(&mut slice).expect("client read_tls");
                assert!(n > 0);
            }
            client.process_new_packets().expect("client packets");
            moved = true;
        }
        if !moved {
            return;
        }
    }
}

fn connected(
    client_config: &Arc<rustls::ClientConfig>,
    server_config: &Arc<rustls::ServerConfig>,
) -> (ClientConnection, ServerConnection) {
    let mut client = ClientConnection::new(
        client_config.clone(),
        ServerName::try_from("localhost").unwrap(),
    )
    .expect("client connection");
    let mut server = ServerConnection::new(server_config.clone()).expect("server connection");
    pump(&mut client, &mut server);
    assert!(!client.is_handshaking() && !server.is_handshaking());
    (client, server)
}

fn handshake() {
    let (client_config, server_config) = configs(None);
    measure(
        50,
        || {
            let _ = connected(&client_config, &server_config);
        },
        |median, min, max| {
            println!(
                "bench,handshake,ed25519,handshakes/s,{:.0},{:.0},{:.0}",
                1.0 / median,
                1.0 / min,
                1.0 / max,
            );
        },
    );
}

/// Bytes pushed through the record path per bulk batch.
const BULK_BATCH_BYTES: usize = 8 * 1024 * 1024;
/// Application write size; two records' worth keeps the record layer
/// busy without giant buffers.
const BULK_CHUNK: usize = 32 * 1024;

fn bulk() {
    for suite in [
        lann_tls_quinn::TLS13_CHACHA20_POLY1305_SHA256,
        lann_tls_quinn::TLS13_AES_128_GCM_SHA256,
    ] {
        let label = suite_label(suite.suite());
        let (client_config, server_config) = configs(Some(single_suite_provider(suite)));
        let (mut client, mut server) = connected(&client_config, &server_config);

        let chunk = vec![0xa5u8; BULK_CHUNK];
        let mut wire = Vec::with_capacity(2 * BULK_CHUNK);
        let mut sink = vec![0u8; 2 * BULK_CHUNK];

        let mut push_chunk = || {
            use std::io::{Read, Write};
            client.writer().write_all(&chunk).expect("plaintext write");
            wire.clear();
            while client.wants_write() {
                client.write_tls(&mut wire).expect("client write_tls");
            }
            let mut slice = wire.as_slice();
            while !slice.is_empty() {
                server.read_tls(&mut slice).expect("server read_tls");
                server.process_new_packets().expect("server packets");
            }
            let mut received = 0;
            while received < BULK_CHUNK {
                received += server.reader().read(&mut sink).expect("plaintext read");
            }
            assert_eq!(received, BULK_CHUNK);
        };

        measure(
            BULK_BATCH_BYTES / BULK_CHUNK,
            &mut push_chunk,
            |median, min, max| {
                let mb = |s: f64| BULK_CHUNK as f64 / s / 1e6;
                println!(
                    "bench,tls-bulk,{label},MB/s,{:.1},{:.1},{:.1}",
                    mb(median),
                    mb(min),
                    mb(max),
                );
            },
        );
    }
}
