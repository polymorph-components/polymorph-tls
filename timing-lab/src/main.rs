//! The timing lab: dudect-style statistical timing tests of the TLS/QUIC
//! deliveries' protocol-level secret-bearing surfaces, run in-guest as a
//! wasm32-wasip2 command under wasmtime.
//!
//! Methodology ("dude, is my code constant time?" — Reparaz, Balasch,
//! Verbauwhede, DATE 2017), inherited from component-webcrypto's
//! timing-lab: for each surface, interleave measurements of two input
//! classes chosen so that only secret-dependent control flow could separate
//! them (e.g. an AEAD tag corrupted at the FIRST byte vs the LAST byte —
//! both calls fail, so any timing difference isolates the tag comparison),
//! then compare the two timing distributions with Welch's t-test over the
//! full data and upper-percentile-cropped subsets, flagging max |t| > 10.
//!
//! Class order is a balanced shuffled schedule and every trial performs the
//! same preparation work regardless of class, so neither the run's own
//! drift nor the harness's input generation can masquerade as a class
//! difference. In-guest positive controls bracket detectability, one per
//! class shape and one per signal scale; they MUST read as leaks or the run
//! fails.
//!
//! See timing-lab/README.md for the surfaces, the detection limits, and why
//! this is a non-gating lab rather than a CI check.

mod stats;

use std::sync::Arc;
use std::time::Instant;

use polymorph_tls_profile::RpkIdentity;
use rustls::crypto::cipher::{
    InboundOpaqueMessage, MessageDecrypter, MessageEncrypter, OutboundChunks, OutboundPlainMessage,
};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{PrivateKeyDer, ServerName};
use rustls::server::AlwaysResolvesServerRawPublicKeys;
use rustls::{
    ClientConfig, ClientConnection, ContentType, ProtocolVersion, ServerConfig, ServerConnection,
    SignatureScheme,
};

use stats::{max_cropped_t, Accumulator, Verdict, THRESHOLD};

/// Samples per class per surface (override with TIMING_LAB_SAMPLES).
const DEFAULT_SAMPLES: usize = 2000;

/// Trials per class run and discarded before sampling begins: populate code
/// paths, caches, and lazy allocations so their one-off costs land outside
/// the measured data.
const WARMUP: usize = 32;

/// Buffer length for the large byte-comparison controls. Large enough that
/// an early-exit compare's first-vs-last-byte difference clears the clock
/// and call-overhead noise floor by orders of magnitude.
const COMPARE_LEN: usize = 4096;

/// Message length for the tag-rejection surfaces.
///
/// Deliberately short: an early-exit tag compare's signal is a fixed
/// ~15-byte difference no matter how long the message is, while the noise
/// it competes with — the MAC/GHASH recomputation inside the timed window —
/// grows with the message. A short message maximizes the signal-to-noise
/// ratio of exactly the difference these surfaces exist to detect.
const TAG_PROBE_LEN: usize = 64;

/// Plaintext length for the fixed-vs-random seal surfaces. Long, for the
/// opposite reason: data-dependent cipher effects accumulate per block, so
/// the signal grows with the plaintext. 16 KiB is also the TLS 1.3 record
/// plaintext ceiling.
///
/// The fixed class is a fixed *random-valued* buffer, not all zeros. Any
/// constant detects value-dependent code paths (dudect's fixed-vs-random
/// design); all-zero bulk data additionally sits on hardware value-
/// dependent timing — measured at ~1–2% over 16 KiB on Apple Silicon by
/// the no-crypto isolation controls (see README.md, "The hardware floor")
/// — and degenerates GHASH (a zero accumulator keeps every multiply
/// operand zero), so a zeros class would attribute hardware physics to
/// the code under test.
const SEAL_LEN: usize = 16 * 1024;

/// AEAD tag length, all suites.
const TAG_LEN: usize = 16;

/// Batch factors: calls per timed sample, for surfaces whose single call
/// sits near the guest clock's resolution and read overhead. The signal
/// scales with the batch while per-sample clock noise does not, so batching
/// raises sensitivity; the reported mean/sigma describe the whole batch
/// window.
const TAG_BATCH: u32 = 16;
const HP_BATCH: u32 = 32;
const HKDF_BATCH: u32 = 16;

/// xorshift64* — deterministic, seedable, good enough for class selection
/// and random-class inputs. Not a CSPRNG and doesn't need to be: lab keys
/// protect nothing; they only have to be distribution-representative.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.max(1))
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    /// Fisher-Yates shuffle. The modulo's bias is irrelevant here: this
    /// orders a class schedule, it does not generate secrets.
    fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = (self.next_u64() % (i as u64 + 1)) as usize;
            items.swap(i, j);
        }
    }
}

const fn nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        _ => panic!("invalid hex digit"),
    }
}

/// Compile-time hex decoding for the published test vectors below.
const fn hex<const N: usize>(s: &str) -> [u8; N] {
    let s = s.as_bytes();
    assert!(s.len() == N * 2, "hex literal has the wrong length");
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (nibble(s[i * 2]) << 4) | nibble(s[i * 2 + 1]);
        i += 1;
    }
    out
}

/// The deliberately leaky positive-control compare: byte-by-byte with an
/// early exit, the exact shape dudect exists to catch.
#[inline(never)]
fn leaky_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (x, y) in a.iter().zip(b) {
        if x != y {
            return false;
        }
    }
    true
}

/// The deliberately data-dependent positive control, for the
/// *fixed-vs-random* class shape the seal surfaces use.
///
/// Each byte drives a loop whose trip count is its low nibble: the all-zero
/// fixed class does no inner work, a random one averages 7.5 iterations per
/// byte. A variable trip count cannot be flattened into branchless code, so
/// this leaks by construction — which is the point. Without it, a quiet
/// verdict on the seal surfaces cannot distinguish "the cipher has no data
/// dependence" from "the harness cannot see data dependence here".
#[inline(never)]
fn data_dependent_work(data: &[u8]) -> u32 {
    let mut acc = 1u32;
    for &b in data {
        for _ in 0..(b & 0x0f) {
            acc = acc.wrapping_mul(31).wrapping_add(b as u32);
        }
    }
    acc
}

/// One measured surface's result row.
struct Report {
    name: &'static str,
    expect_leak: bool,
    samples_per_class: usize,
    /// Calls per timed sample; mean/sigma describe the whole batch window.
    batch: u32,
    max_t: f64,
    verdict: Verdict,
    /// Pooled mean sample time, ns — the measurement distance: how much
    /// work each sample carries alongside the difference under test.
    mean_ns: f64,
    /// Pooled standard deviation, ns. Together with the sample count this
    /// is what a quiet verdict actually bounds: a per-class difference much
    /// below `sigma_ns / sqrt(samples)` is invisible here.
    sigma_ns: f64,
    /// Uncropped mean difference, class0 minus class1, ns — the effect
    /// size behind the t statistic, signed like t: negative means class0
    /// (the fixed class) ran faster.
    delta_ns: f64,
}

/// Interleaved two-class sampling loop over a balanced, shuffled schedule,
/// so environmental drift decorrelates from class. `sample(class)` runs the
/// surface once (including any batching) and returns the timed window in
/// nanoseconds.
fn measure(
    name: &'static str,
    expect_leak: bool,
    samples: usize,
    batch: u32,
    rng: &mut Rng,
    mut sample: impl FnMut(bool) -> Result<u64, String>,
) -> Result<Report, String> {
    let mut class0 = Vec::with_capacity(samples);
    let mut class1 = Vec::with_capacity(samples);
    // Warm-up: populate code paths, caches, and lazy allocations untimed.
    for i in 0..WARMUP * 2 {
        sample(i % 2 == 1).map_err(|e| format!("{name}: {e}"))?;
    }
    // A balanced shuffled schedule, not a per-trial coin flip: a coin
    // flip's random walk exhausts one class ~sqrt(n) trials before the
    // other, so the run's final samples are all one class — recorrelating
    // class with time exactly where end-of-run drift lives.
    let mut schedule = vec![false; samples];
    schedule.resize(samples * 2, true);
    rng.shuffle(&mut schedule);
    for class in schedule {
        let ns = sample(class).map_err(|e| format!("{name}: {e}"))?;
        if class {
            class1.push(ns as f64);
        } else {
            class0.push(ns as f64);
        }
    }
    let max_t = max_cropped_t(&class0, &class1);
    let verdict = if !max_t.is_finite() {
        Verdict::Inconclusive
    } else if max_t.abs() > THRESHOLD {
        Verdict::Leak
    } else {
        Verdict::Quiet
    };
    let mut pooled = Accumulator::default();
    for &x in class0.iter().chain(&class1) {
        pooled.push(x);
    }
    let mut acc0 = Accumulator::default();
    let mut acc1 = Accumulator::default();
    for &x in &class0 {
        acc0.push(x);
    }
    for &x in &class1 {
        acc1.push(x);
    }
    Ok(Report {
        name,
        expect_leak,
        samples_per_class: samples,
        batch,
        max_t,
        verdict,
        mean_ns: pooled.mean(),
        sigma_ns: pooled.variance().sqrt(),
        delta_ns: acc0.mean() - acc1.mean(),
    })
}

/// Build a comparison probe: `expected` corrupted at the first byte
/// (class 0) or the last byte (class 1). Both compares FAIL; only an early
/// exit distinguishes them.
fn corrupted(expected: &[u8], class: bool) -> Vec<u8> {
    let mut probe = expected.to_vec();
    let index = if class { probe.len() - 1 } else { 0 };
    probe[index] ^= 0x01;
    probe
}

// --- Ed25519 key material ---

/// PKCS#8 v1 PrivateKeyInfo prefix for an Ed25519 key (RFC 8410 OID
/// 1.3.101.112); the 32-byte seed follows. Every length is fixed, so the
/// encoding is this constant plus the seed. The setup known-answer check
/// validates the template.
const ED25519_PKCS8_PREFIX: [u8; 16] = hex("302e020100300506032b657004220420");

fn ed25519_pkcs8(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = ED25519_PKCS8_PREFIX.to_vec();
    der.extend_from_slice(seed);
    der
}

/// RFC 8032 §7.1 TEST 1: seed, and the signature of the empty message.
/// Ed25519 signing is deterministic, so the signer path can be checked
/// end-to-end against the published signature before sampling.
const ED25519_KAT_SEED: [u8; 32] =
    hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
const ED25519_KAT_SIG: [u8; 64] = hex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e3970\
     1cf9b46bd25bf5f0595bbe24655141438e7a100b",
);

// --- Key-exchange test vectors and class scalars ---

/// X25519 known answer, RFC 7748 §6.1: Alice's scalar, Bob's public key,
/// and the published shared secret.
const X25519_KAT_D: [u8; 32] =
    hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
const X25519_PEER: [u8; 32] =
    hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
const X25519_SHARED: [u8; 32] =
    hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

/// ECDH P-256 known answer, Wycheproof `ecdh_secp256r1_ecpoint_test.json`
/// tcId 1: scalar, peer SEC1 point, shared secret.
const ECDH_P256_KAT_D: [u8; 32] =
    hex("0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346");
const ECDH_P256_PEER: [u8; 65] = hex(
    "0462d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26ac333a93a9e70a81cd5a95\
     b5bf8d13990eb741c8c38872b4a07d275a014e30cf",
);
const ECDH_P256_SHARED: [u8; 32] =
    hex("53020d908b0219328b658b525f26780e3ae12bcd952bb25a93bc0895e1714285");

/// A scalar with one bit set, at `bit` counted in `LE` little-endian or
/// big-endian byte order.
const fn single_bit_scalar<const N: usize, const LE: bool>(bit: usize) -> [u8; N] {
    let mut scalar = [0u8; N];
    let byte = bit / 8;
    scalar[if LE { byte } else { N - 1 - byte }] = 1 << (bit % 8);
    scalar
}

/// The key-exchange surfaces' fixed-class scalars: a single mid-position
/// bit, the extreme low end of the Hamming-weight distribution the random
/// class draws from (mean n/2 ± ~√n/2). The canonical leak the
/// fixed-vs-random scalar shape targets — weight-proportional scalar-mult
/// timing, a double-and-add regression — separates the class *means* by
/// the weight difference times the per-bit cost, so the fixed scalar's
/// distance from the random mean is a direct multiplier on the surface's
/// sensitivity. X25519 clamping sets bit 254, so its fixed scalar measures
/// at weight 2; the P-256 scalar measures at weight 1.
const X25519_FIXED_D: [u8; 32] = single_bit_scalar::<32, true>(128);
const ECDH_P256_FIXED_D: [u8; 32] = single_bit_scalar::<32, false>(128);

/// The P-256 group order, big-endian: a fresh scalar draw is valid iff it
/// is nonzero and below the order, so the sampling loop rejection-samples
/// locally. Byte-lexicographic comparison is numeric comparison for
/// equal-length big-endian strings.
const N_P256: [u8; 32] = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

fn scalar_in_range(scalar: &[u8], order: &[u8]) -> bool {
    scalar.iter().any(|&b| b != 0) && scalar < order
}

/// RFC 5869 test case 1, checked through the suite's `Hkdf` trait object
/// before the key-schedule surface samples it: IKM, salt, info, and the
/// first 32 OKM bytes.
const HKDF_KAT_IKM: [u8; 22] = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
const HKDF_KAT_SALT: [u8; 13] = hex("000102030405060708090a0b0c");
const HKDF_KAT_INFO: [u8; 10] = hex("f0f1f2f3f4f5f6f7f8f9");
const HKDF_KAT_OKM: [u8; 32] =
    hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf");

// --- rustls plumbing ---

/// A raw-public-key config pair under `provider`: the client pins the
/// server's key, the server authenticates with `identity`, clients are
/// unauthenticated. Assembled from the `polymorph_tls::rpk` building blocks
/// rather than its `client_config`/`server_config` so the lab can restrict
/// the provider's cipher suites and skip client authentication — client
/// CertificateVerify work is class-independent here and would only widen
/// the timed window (see README.md, "Surfaces").
fn rpk_pair(
    provider: Arc<CryptoProvider>,
    identity: &RpkIdentity,
    extract_secrets: bool,
) -> Result<(Arc<ClientConfig>, Arc<ServerConfig>), String> {
    let algorithms = provider.signature_verification_algorithms;
    let certified = polymorph_tls::rpk::certified_key(identity)
        .map_err(|e| format!("rpk certified key: {e}"))?;
    let mut server = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("server config versions: {e}"))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(Arc::new(
            certified,
        ))));
    // Tickets would add per-handshake sealing work after the flights the
    // handshake surface times; the lab measures the handshake proper.
    server.send_tls13_tickets = 0;
    server.enable_secret_extraction = extract_secrets;
    let mut client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("client config versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(polymorph_tls::rpk::RpkServerVerifier::new(
            &identity.public_key(),
            algorithms,
        )))
        .with_no_client_auth();
    client.enable_secret_extraction = extract_secrets;
    Ok((Arc::new(client), Arc::new(server)))
}

/// The profile provider restricted to a single cipher suite, so a setup
/// handshake negotiates exactly the suite whose record machinery a surface
/// measures.
fn provider_with_suite(id: rustls::CipherSuite) -> Arc<CryptoProvider> {
    let base = polymorph_tls::provider();
    let suite = *base
        .cipher_suites
        .iter()
        .find(|s| s.suite() == id)
        .expect("the profile provider carries the requested suite");
    Arc::new(CryptoProvider {
        cipher_suites: vec![suite],
        kx_groups: base.kx_groups.clone(),
        signature_verification_algorithms: base.signature_verification_algorithms,
        secure_random: base.secure_random,
        key_provider: base.key_provider,
    })
}

fn new_connections(
    client_config: &Arc<ClientConfig>,
    server_config: &Arc<ServerConfig>,
) -> Result<(ClientConnection, ServerConnection), String> {
    let name = ServerName::try_from("rpk.invalid").expect("static name parses");
    let client = ClientConnection::new(client_config.clone(), name)
        .map_err(|e| format!("client connection: {e}"))?;
    let server = ServerConnection::new(server_config.clone())
        .map_err(|e| format!("server connection: {e}"))?;
    Ok((client, server))
}

/// Drives the handshake to completion in memory, returning the total
/// nanoseconds spent in *server-side* processing (`read_tls` +
/// `process_new_packets` + `write_tls`) — the secret-holder's observable
/// latency. Client-side processing runs outside the timed windows.
fn handshake_timed(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<u64, String> {
    let mut server_ns = 0u64;
    let mut wire = Vec::with_capacity(8 * 1024);
    for _ in 0..16 {
        // Client flight (untimed) → server processing (timed).
        wire.clear();
        while client.wants_write() {
            client
                .write_tls(&mut wire)
                .map_err(|e| format!("client write_tls: {e}"))?;
        }
        if !wire.is_empty() {
            let start = Instant::now();
            let mut rd = &wire[..];
            while !rd.is_empty() {
                server
                    .read_tls(&mut rd)
                    .map_err(|e| format!("server read_tls: {e}"))?;
                server
                    .process_new_packets()
                    .map_err(|e| format!("server handshake: {e}"))?;
            }
            server_ns += start.elapsed().as_nanos() as u64;
        }
        // Server flight (timed) → client processing (untimed).
        wire.clear();
        if server.wants_write() {
            let start = Instant::now();
            while server.wants_write() {
                server
                    .write_tls(&mut wire)
                    .map_err(|e| format!("server write_tls: {e}"))?;
            }
            server_ns += start.elapsed().as_nanos() as u64;
        }
        if !wire.is_empty() {
            let mut rd = &wire[..];
            while !rd.is_empty() {
                client
                    .read_tls(&mut rd)
                    .map_err(|e| format!("client read_tls: {e}"))?;
                client
                    .process_new_packets()
                    .map_err(|e| format!("client handshake: {e}"))?;
            }
        }
        if !client.is_handshaking()
            && !server.is_handshaking()
            && !client.wants_write()
            && !server.wants_write()
        {
            return Ok(server_ns);
        }
    }
    Err("handshake did not complete".into())
}

/// One suite's record-layer rig: encrypter and decrypter built by the
/// suite's `Tls13AeadAlgorithm` from traffic secrets extracted out of a
/// real handshake (the client's tx and the server's rx are the same
/// direction's keys, extracted twice because the secrets types are
/// move-only), plus a sealed template record for the rejection probes.
struct RecordRig {
    enc: Box<dyn MessageEncrypter>,
    dec: Box<dyn MessageDecrypter>,
    seq: u64,
    /// A sealed `TAG_PROBE_LEN`-byte application record body (no 5-byte
    /// header); the final `TAG_LEN` bytes are the tag.
    template: Vec<u8>,
}

fn record_rig(id: rustls::CipherSuite, rng: &mut Rng) -> Result<RecordRig, String> {
    let provider = provider_with_suite(id);
    let suite = provider.cipher_suites[0]
        .tls13()
        .expect("profile suites are TLS 1.3");
    let identity = RpkIdentity::from_pkcs8_der(&ed25519_pkcs8(&{
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        seed
    }))
    .map_err(|e| format!("record rig identity: {e}"))?;
    let (client_config, server_config) = rpk_pair(provider, &identity, true)?;
    let (mut client, mut server) = new_connections(&client_config, &server_config)?;
    handshake_timed(&mut client, &mut server).map_err(|e| format!("record rig handshake: {e}"))?;

    let client_secrets = client
        .dangerous_extract_secrets()
        .map_err(|e| format!("client secret extraction: {e}"))?;
    let server_secrets = server
        .dangerous_extract_secrets()
        .map_err(|e| format!("server secret extraction: {e}"))?;
    let (tx_seq, tx) = client_secrets.tx;
    let (rx_seq, rx) = server_secrets.rx;
    if tx_seq != rx_seq {
        return Err("extracted sequence numbers disagree".into());
    }
    // The variant label is ignored: rustls-rustcrypto's TLS 1.3 GCM
    // `extract_keys` mislabels AES-128-GCM secrets as `Aes256Gcm` (its
    // macro hardcodes the variant), and the label plays no role here —
    // the key material goes straight back into the same suite's
    // `aead_alg`, and the roundtrip guard below validates it.
    let key_iv = |secrets: rustls::ConnectionTrafficSecrets| match secrets {
        rustls::ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv }
        | rustls::ConnectionTrafficSecrets::Aes128Gcm { key, iv }
        | rustls::ConnectionTrafficSecrets::Aes256Gcm { key, iv } => Ok((key, iv)),
        _ => Err("unexpected extracted secrets variant".to_string()),
    };
    let (enc_key, enc_iv) = key_iv(tx)?;
    let (dec_key, dec_iv) = key_iv(rx)?;
    let mut enc = suite.aead_alg.encrypter(enc_key, enc_iv);
    let mut dec = suite.aead_alg.decrypter(dec_key, dec_iv);

    // Template and guards: an uncorrupted roundtrip must succeed; a
    // corrupted tag must fail *and leave the buffer intact*, since the
    // rejection probes reuse one probe buffer across a batch.
    let mut plain = vec![0u8; TAG_PROBE_LEN];
    rng.fill(&mut plain);
    let sealed = enc
        .encrypt(
            OutboundPlainMessage {
                typ: ContentType::ApplicationData,
                version: ProtocolVersion::TLSv1_3,
                payload: OutboundChunks::new(&[&plain]),
            },
            tx_seq,
        )
        .map_err(|e| format!("record rig seal: {e}"))?;
    let template = sealed.payload.as_ref().to_vec();
    let mut check = template.clone();
    let opened = dec
        .decrypt(
            InboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                &mut check,
            ),
            rx_seq,
        )
        .map_err(|e| format!("record rig roundtrip: {e}"))?;
    if opened.payload != &plain[..] {
        return Err("record rig roundtrip produced wrong plaintext".into());
    }
    let mut bad = template.clone();
    let tag_at = bad.len() - TAG_LEN;
    bad[tag_at] ^= 0x01;
    let snapshot = bad.clone();
    if dec
        .decrypt(
            InboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                &mut bad,
            ),
            rx_seq,
        )
        .is_ok()
    {
        return Err("record rig accepted a corrupted record".into());
    }
    if bad != snapshot {
        return Err("record decrypter modified the buffer on failure".into());
    }
    Ok(RecordRig {
        enc,
        dec,
        seq: tx_seq,
        template,
    })
}

/// One suite's RFC 9001 packet rig: packet and header-protection keys from
/// the public initial-keys derivation (deterministic in the connection ID),
/// sealing with one side's local keys and opening with the other side's
/// matching remote keys.
struct PacketRig {
    seal: rustls::quic::Keys,
    open: rustls::quic::Keys,
    /// A sealed `TAG_PROBE_LEN`-byte payload; the final `TAG_LEN` bytes are
    /// the tag.
    template: Vec<u8>,
}

/// Fixed short-header fields for the packet probes.
const PACKET_HEADER: [u8; 4] = [0x42, 0x00, 0xbf, 0xf4];
const PACKET_NUMBER: u64 = 3;

fn packet_rig(suite: rustls::SupportedCipherSuite, rng: &mut Rng) -> Result<PacketRig, String> {
    let quic_suite = suite
        .tls13()
        .expect("profile suites are TLS 1.3")
        .quic_suite()
        .expect("quinn provider suites carry QUIC support");
    let mut cid = [0u8; 8];
    rng.fill(&mut cid);
    let seal = quic_suite.keys(&cid, rustls::Side::Client, rustls::quic::Version::V1);
    let open = quic_suite.keys(&cid, rustls::Side::Server, rustls::quic::Version::V1);

    let mut payload = vec![0u8; TAG_PROBE_LEN];
    rng.fill(&mut payload);
    let plain = payload.clone();
    let tag = seal
        .local
        .packet
        .encrypt_in_place(PACKET_NUMBER, &PACKET_HEADER, &mut payload)
        .map_err(|e| format!("packet rig seal: {e}"))?;
    payload.extend_from_slice(tag.as_ref());
    let template = payload;

    let mut check = template.clone();
    let opened = open
        .remote
        .packet
        .decrypt_in_place(PACKET_NUMBER, &PACKET_HEADER, &mut check)
        .map_err(|e| format!("packet rig roundtrip: {e}"))?;
    if opened != &plain[..] {
        return Err("packet rig roundtrip produced wrong plaintext".into());
    }
    let mut bad = template.clone();
    bad[TAG_PROBE_LEN] ^= 0x01;
    let snapshot = bad.clone();
    if open
        .remote
        .packet
        .decrypt_in_place(PACKET_NUMBER, &PACKET_HEADER, &mut bad)
        .is_ok()
    {
        return Err("packet rig accepted a corrupted packet".into());
    }
    if bad != snapshot {
        return Err("packet opener modified the buffer on failure".into());
    }
    Ok(PacketRig {
        seal,
        open,
        template,
    })
}

fn run_lab() -> Result<(), String> {
    let samples = std::env::var("TIMING_LAB_SAMPLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SAMPLES);
    let seed = std::env::var("TIMING_LAB_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x6c61_6e6e_5f74_6c73);
    let mut rng = Rng::new(seed);
    let provider = polymorph_tls::provider();

    let mut expected = vec![0u8; COMPARE_LEN];
    rng.fill(&mut expected);

    let mut reports = Vec::new();

    // Positive control, corrupted-first-vs-last shape at large scale: the
    // harness MUST see this leak.
    {
        let expected = expected.clone();
        reports.push(measure(
            "control/leaky-equal",
            true,
            samples,
            1,
            &mut rng,
            |class| {
                let probe = corrupted(&expected, class);
                let start = Instant::now();
                let equal = leaky_equal(&expected, &probe);
                let ns = start.elapsed().as_nanos() as u64;
                if equal {
                    return Err("corrupted buffer compared equal".into());
                }
                Ok(ns)
            },
        )?);
    }

    // The same positive control at AEAD-tag scale, batched like the
    // tag-rejection surfaces: it calibrates detectability at exactly the
    // signal size those surfaces' quiet verdicts need bounding against.
    {
        let mut tag = [0u8; TAG_LEN];
        rng.fill(&mut tag);
        reports.push(measure(
            "control/leaky-tag-compare",
            true,
            samples,
            TAG_BATCH,
            &mut rng,
            |class| {
                let probe = corrupted(&tag, class);
                let start = Instant::now();
                for _ in 0..TAG_BATCH {
                    // black_box defeats loop-invariant hoisting: the
                    // compare's inputs are identical across the batch, and
                    // a hoisted compare would time an empty loop.
                    if leaky_equal(std::hint::black_box(&tag), std::hint::black_box(&probe)) {
                        return Err("corrupted tag compared equal".into());
                    }
                }
                Ok(start.elapsed().as_nanos() as u64)
            },
        )?);
    }

    // Negative control: subtle::ConstantTimeEq, expected quiet.
    {
        use subtle::ConstantTimeEq;
        let expected = expected.clone();
        reports.push(measure(
            "control/subtle-ct-eq",
            false,
            samples,
            1,
            &mut rng,
            |class| {
                let probe = corrupted(&expected, class);
                let start = Instant::now();
                let equal = bool::from(expected.ct_eq(&probe));
                let ns = start.elapsed().as_nanos() as u64;
                if equal {
                    return Err("corrupted buffer compared equal".into());
                }
                Ok(ns)
            },
        )?);
    }

    // Positive control for the fixed-vs-random class shape, bracketing the
    // seal and scalar surfaces the way leaky-equal brackets the compares.
    {
        let fixed = vec![0u8; SEAL_LEN];
        let mut random = vec![0u8; SEAL_LEN];
        let mut inputs = Rng::new(rng.next_u64());
        reports.push(measure(
            "control/data-dependent-work",
            true,
            samples,
            1,
            &mut rng,
            |class| {
                // Symmetric per-trial work: both classes draw the fill.
                inputs.fill(&mut random);
                let data = if class { &random } else { &fixed };
                let start = Instant::now();
                let acc = data_dependent_work(data);
                let ns = start.elapsed().as_nanos() as u64;
                std::hint::black_box(acc);
                Ok(ns)
            },
        )?);
    }

    // handshake/certificate-verify-sign: the provider's Ed25519 signer —
    // the object rustls calls to sign the endpoint's own CertificateVerify,
    // TLS 1.3's one class-D-shaped operation — over a fixed
    // CertificateVerify-sized message, fixed vs freshly random identity
    // key. Key loading (seed expansion, public-key derivation) runs
    // per-trial for both classes, outside the timed window.
    {
        // Signer-path known answer: RFC 8032 TEST 1 through the provider's
        // key loader and scheme selection. A wrong template or signer path
        // fails here rather than timing something else.
        let kat = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(
                ed25519_pkcs8(&ED25519_KAT_SEED).into(),
            ))
            .map_err(|e| format!("ed25519 known-answer load: {e}"))?;
        let signer = kat
            .choose_scheme(&[SignatureScheme::ED25519])
            .ok_or("ed25519 known-answer signer missing")?;
        let sig = signer
            .sign(b"")
            .map_err(|e| format!("ed25519 known-answer sign: {e}"))?;
        if sig != ED25519_KAT_SIG {
            return Err("ed25519 known-answer signature mismatch".into());
        }

        let mut fixed_seed = [0u8; 32];
        rng.fill(&mut fixed_seed);
        let mut message = vec![0u8; 130];
        rng.fill(&mut message);
        let mut random_seed = [0u8; 32];
        let mut inputs = Rng::new(rng.next_u64());
        let provider = provider.clone();
        reports.push(measure(
            "handshake/certificate-verify-sign",
            false,
            samples,
            1,
            &mut rng,
            |class| {
                inputs.fill(&mut random_seed);
                let seed = if class { &random_seed } else { &fixed_seed };
                let key = provider
                    .key_provider
                    .load_private_key(PrivateKeyDer::Pkcs8(ed25519_pkcs8(seed).into()))
                    .map_err(|e| format!("key load: {e}"))?;
                let signer = key
                    .choose_scheme(&[SignatureScheme::ED25519])
                    .ok_or("no ed25519 signer")?;
                let start = Instant::now();
                let sig = signer.sign(&message).map_err(|e| format!("sign: {e}"))?;
                let ns = start.elapsed().as_nanos() as u64;
                std::hint::black_box(sig);
                Ok(ns)
            },
        )?);
    }

    // handshake/server: a full TLS 1.3 handshake per trial over the
    // raw-public-key posture, fixed vs freshly random server identity;
    // timed window = the server's processing only. Ephemeral key exchange,
    // transcript, key schedule, and Finished all draw fresh randomness in
    // both classes, so only identity-key-dependent server timing separates
    // them — the Brumley–Boneh shape (repeated handshakes under one
    // long-term key, attacker-observable latency).
    {
        let mut fixed_seed = [0u8; 32];
        rng.fill(&mut fixed_seed);
        // Template guard: the fixed seed's PKCS#8 must parse and derive
        // the same public key ed25519-dalek derives from the raw seed.
        let identity = RpkIdentity::from_pkcs8_der(&ed25519_pkcs8(&fixed_seed))
            .map_err(|e| format!("handshake identity template: {e}"))?;
        let direct = ed25519_dalek::SigningKey::from_bytes(&fixed_seed);
        if identity.public_key() != direct.verifying_key().to_bytes() {
            return Err("ed25519 PKCS#8 template derives the wrong public key".into());
        }

        let mut random_seed = [0u8; 32];
        let mut inputs = Rng::new(rng.next_u64());
        let provider = provider.clone();
        reports.push(measure(
            "handshake/server",
            false,
            samples,
            1,
            &mut rng,
            |class| {
                inputs.fill(&mut random_seed);
                let seed = if class { &random_seed } else { &fixed_seed };
                let identity = RpkIdentity::from_pkcs8_der(&ed25519_pkcs8(seed))
                    .map_err(|e| format!("identity: {e}"))?;
                let (client_config, server_config) = rpk_pair(provider.clone(), &identity, false)?;
                let (mut client, mut server) = new_connections(&client_config, &server_config)?;
                handshake_timed(&mut client, &mut server)
            },
        )?);
    }

    // key-schedule/hkdf-extract-expand: the suite's HKDF-SHA256 trait
    // object — the machinery behind every key-schedule derivation, the
    // Finished keys, and key updates — with a fixed-vs-random input secret.
    {
        let hkdf = provider.cipher_suites[0]
            .tls13()
            .expect("profile suites are TLS 1.3")
            .hkdf_provider;
        // RFC 5869 test case 1 through the same trait path.
        let expander = hkdf.extract_from_secret(Some(&HKDF_KAT_SALT), &HKDF_KAT_IKM);
        let mut okm = [0u8; 32];
        expander
            .expand_slice(&[&HKDF_KAT_INFO], &mut okm)
            .map_err(|_| "hkdf known-answer expand failed".to_string())?;
        if okm != HKDF_KAT_OKM {
            return Err("hkdf known-answer output mismatch".into());
        }

        let mut salt = [0u8; 32];
        rng.fill(&mut salt);
        let mut fixed_secret = [0u8; 32];
        rng.fill(&mut fixed_secret);
        let mut random_secret = [0u8; 32];
        let mut inputs = Rng::new(rng.next_u64());
        reports.push(measure(
            "key-schedule/hkdf-extract-expand",
            false,
            samples,
            HKDF_BATCH,
            &mut rng,
            |class| {
                inputs.fill(&mut random_secret);
                let secret = if class { &random_secret } else { &fixed_secret };
                let mut okm = [0u8; 32];
                let start = Instant::now();
                for _ in 0..HKDF_BATCH {
                    let expander = hkdf.extract_from_secret(Some(&salt), secret);
                    expander
                        .expand_slice(&[b"timing lab expand"], &mut okm)
                        .map_err(|_| "expand failed".to_string())?;
                    std::hint::black_box(&okm);
                }
                Ok(start.elapsed().as_nanos() as u64)
            },
        )?);
    }

    // key-exchange/x25519: fixed-vs-random secret scalar against a fixed
    // peer, through the same x25519-dalek entry point the provider's key
    // exchange uses. The peer — and with it every point-dependent operand —
    // is identical across classes, so only scalar-dependent control flow or
    // memory access separates them. Below the rustls seam by necessity:
    // rustls draws ephemeral scalars internally (see README.md).
    {
        if x25519_dalek::x25519(X25519_KAT_D, X25519_PEER) != X25519_SHARED {
            return Err("x25519 known-answer mismatch".into());
        }
        let mut random_scalar = [0u8; 32];
        let mut inputs = Rng::new(rng.next_u64());
        reports.push(measure(
            "key-exchange/x25519",
            false,
            samples,
            1,
            &mut rng,
            |class| {
                inputs.fill(&mut random_scalar);
                let scalar = if class { random_scalar } else { X25519_FIXED_D };
                let start = Instant::now();
                let shared = x25519_dalek::x25519(scalar, X25519_PEER);
                let ns = start.elapsed().as_nanos() as u64;
                std::hint::black_box(shared);
                Ok(ns)
            },
        )?);
    }

    // key-exchange/p256: as x25519, over the p256 crate's ECDH. Scalar
    // parsing (with local rejection sampling of out-of-range draws) runs
    // per-trial for both classes, outside the timed window.
    {
        let peer = p256::PublicKey::from_sec1_bytes(&ECDH_P256_PEER)
            .map_err(|e| format!("p256 peer point: {e}"))?;
        let peer = *peer.as_affine();
        let kat_scalar = Option::<p256::NonZeroScalar>::from(p256::NonZeroScalar::from_repr(
            ECDH_P256_KAT_D.into(),
        ))
        .ok_or("p256 known-answer scalar out of range")?;
        let shared = p256::ecdh::diffie_hellman(kat_scalar, peer);
        if shared.raw_secret_bytes().as_slice() != ECDH_P256_SHARED {
            return Err("p256 known-answer mismatch".into());
        }

        let mut random_bytes = [0u8; 32];
        let mut inputs = Rng::new(rng.next_u64());
        reports.push(measure(
            "key-exchange/p256",
            false,
            samples,
            1,
            &mut rng,
            |class| {
                loop {
                    inputs.fill(&mut random_bytes);
                    if scalar_in_range(&random_bytes, &N_P256) {
                        break;
                    }
                }
                let bytes = if class {
                    &random_bytes
                } else {
                    &ECDH_P256_FIXED_D
                };
                let scalar = Option::<p256::NonZeroScalar>::from(p256::NonZeroScalar::from_repr(
                    (*bytes).into(),
                ))
                .ok_or("scalar out of range")?;
                let start = Instant::now();
                let shared = p256::ecdh::diffie_hellman(scalar, peer);
                let ns = start.elapsed().as_nanos() as u64;
                std::hint::black_box(shared.raw_secret_bytes());
                Ok(ns)
            },
        )?);
    }

    // Record-layer surfaces, per suite: the rustls record machinery the
    // TLS deliveries drive, keyed by traffic secrets extracted from a real
    // handshake. Rejection isolates the tag comparison (corrupt first vs
    // last tag byte — both fail, the MAC recomputation is identical); seal
    // probes data-dependent cipher timing (fixed vs random plaintext).
    for (name_open, name_seal, id) in [
        (
            "record/chacha20-poly1305/open-reject",
            "record/chacha20-poly1305/seal",
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        ),
        (
            "record/aes-128-gcm/open-reject",
            "record/aes-128-gcm/seal",
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        ),
    ] {
        let mut rig = record_rig(id, &mut rng)?;
        let tag_at = rig.template.len() - TAG_LEN;
        {
            let template = rig.template.clone();
            let seq = rig.seq;
            let dec = &mut rig.dec;
            reports.push(measure(
                name_open,
                false,
                samples,
                TAG_BATCH,
                &mut rng,
                |class| {
                    let mut probe = template.clone();
                    let index = if class { tag_at + TAG_LEN - 1 } else { tag_at };
                    probe[index] ^= 0x01;
                    let start = Instant::now();
                    for _ in 0..TAG_BATCH {
                        let msg = InboundOpaqueMessage::new(
                            ContentType::ApplicationData,
                            ProtocolVersion::TLSv1_2,
                            &mut probe,
                        );
                        if dec.decrypt(msg, seq).is_ok() {
                            return Err("corrupted record accepted".into());
                        }
                    }
                    Ok(start.elapsed().as_nanos() as u64)
                },
            )?);
        }
        {
            let mut fixed = vec![0u8; SEAL_LEN];
            rng.fill(&mut fixed);
            let mut random = vec![0u8; SEAL_LEN];
            let mut work = vec![0u8; SEAL_LEN];
            let mut inputs = Rng::new(rng.next_u64());
            let seq = rig.seq;
            let enc = &mut rig.enc;
            reports.push(measure(name_seal, false, samples, 1, &mut rng, |class| {
                // Symmetric prep: both classes draw the fill and write
                // the work buffer, so the timed window's cache state is
                // class-independent and only the values differ.
                inputs.fill(&mut random);
                work.copy_from_slice(if class { &random } else { &fixed });
                let start = Instant::now();
                let sealed = enc
                    .encrypt(
                        OutboundPlainMessage {
                            typ: ContentType::ApplicationData,
                            version: ProtocolVersion::TLSv1_3,
                            payload: OutboundChunks::new(&[&work]),
                        },
                        seq,
                    )
                    .map_err(|e| format!("seal: {e}"))?;
                let ns = start.elapsed().as_nanos() as u64;
                std::hint::black_box(sealed.payload.as_ref().len());
                Ok(ns)
            })?);
        }
    }

    // Packet-protection surfaces (RFC 9001), per suite: the quinn
    // delivery's packet keys and header protection. The header-protection
    // classes are fixed-vs-random *sample* under a fixed key — a
    // table-based AES's timing varies with its input, which is the class-C
    // failure mode this repository's profile excludes by construction.
    for (name_open, name_seal, name_hp, suite) in [
        (
            "packet/chacha20-poly1305/open-reject",
            "packet/chacha20-poly1305/seal",
            "packet/chacha20-poly1305/hp-mask",
            polymorph_tls_quinn::TLS13_CHACHA20_POLY1305_SHA256,
        ),
        (
            "packet/aes-128-gcm/open-reject",
            "packet/aes-128-gcm/seal",
            "packet/aes-128-gcm/hp-mask",
            polymorph_tls_quinn::TLS13_AES_128_GCM_SHA256,
        ),
    ] {
        let rig = packet_rig(suite, &mut rng)?;
        {
            let template = rig.template.clone();
            let opener = &rig.open.remote.packet;
            reports.push(measure(
                name_open,
                false,
                samples,
                TAG_BATCH,
                &mut rng,
                |class| {
                    let mut probe = template.clone();
                    let index = if class {
                        TAG_PROBE_LEN + TAG_LEN - 1
                    } else {
                        TAG_PROBE_LEN
                    };
                    probe[index] ^= 0x01;
                    let start = Instant::now();
                    for _ in 0..TAG_BATCH {
                        if opener
                            .decrypt_in_place(PACKET_NUMBER, &PACKET_HEADER, &mut probe)
                            .is_ok()
                        {
                            return Err("corrupted packet accepted".into());
                        }
                    }
                    Ok(start.elapsed().as_nanos() as u64)
                },
            )?);
        }
        {
            let mut fixed = vec![0u8; SEAL_LEN];
            rng.fill(&mut fixed);
            let mut random = vec![0u8; SEAL_LEN];
            let mut work = vec![0u8; SEAL_LEN];
            let mut inputs = Rng::new(rng.next_u64());
            let sealer = &rig.seal.local.packet;
            reports.push(measure(name_seal, false, samples, 1, &mut rng, |class| {
                // encrypt_in_place consumes the buffer, so both classes
                // pay one fill and one copy into the work buffer.
                inputs.fill(&mut random);
                work.copy_from_slice(if class { &random } else { &fixed });
                let start = Instant::now();
                let tag = sealer
                    .encrypt_in_place(PACKET_NUMBER, &PACKET_HEADER, &mut work)
                    .map_err(|e| format!("seal: {e}"))?;
                let ns = start.elapsed().as_nanos() as u64;
                std::hint::black_box(tag.as_ref());
                Ok(ns)
            })?);
        }
        {
            let mut fixed_sample = [0u8; 16];
            rng.fill(&mut fixed_sample);
            let mut random_sample = [0u8; 16];
            let mut inputs = Rng::new(rng.next_u64());
            let hp = &rig.seal.local.header;
            reports.push(measure(
                name_hp,
                false,
                samples,
                HP_BATCH,
                &mut rng,
                |class| {
                    inputs.fill(&mut random_sample);
                    let sample = if class { &random_sample } else { &fixed_sample };
                    let start = Instant::now();
                    for _ in 0..HP_BATCH {
                        // Masking XORs in place, so reset the header fields
                        // each iteration; the reset is class-independent.
                        let mut first = 0x43u8;
                        let mut pn = [0x00u8, 0x01, 0x02, 0x03];
                        hp.encrypt_in_place(sample, &mut first, &mut pn)
                            .map_err(|e| format!("hp mask: {e}"))?;
                        std::hint::black_box((first, pn));
                    }
                    Ok(start.elapsed().as_nanos() as u64)
                },
            )?);
        }
    }

    // token/open-reject: the quinn endpoint's retry/NEW_TOKEN AEAD
    // (HKDF-SHA256 into AES-256-GCM) — attacker-supplied tokens opened
    // under a long-lived key on unauthenticated Initial packets.
    {
        use quinn_proto::crypto::HandshakeTokenKey;
        let token_key = polymorph_tls_quinn::TokenKey::new(b"timing-lab token master");
        let aead = token_key.aead_from_hkdf(b"timing-lab token");
        let mut token = vec![0u8; TAG_PROBE_LEN];
        rng.fill(&mut token);
        let plain = token.clone();
        aead.seal(&mut token, b"timing-lab aad")
            .map_err(|_| "token seal failed".to_string())?;
        let template = token;
        let mut check = template.clone();
        let opened = aead
            .open(&mut check, b"timing-lab aad")
            .map_err(|_| "token roundtrip failed".to_string())?;
        if opened != &plain[..] {
            return Err("token roundtrip produced wrong plaintext".into());
        }
        let mut bad = template.clone();
        let tag_at = bad.len() - TAG_LEN;
        bad[tag_at] ^= 0x01;
        let snapshot = bad.clone();
        if aead.open(&mut bad, b"timing-lab aad").is_ok() {
            return Err("token rig accepted a corrupted token".into());
        }
        if bad != snapshot {
            return Err("token opener modified the buffer on failure".into());
        }

        reports.push(measure(
            "token/aes-256-gcm/open-reject",
            false,
            samples,
            TAG_BATCH,
            &mut rng,
            |class| {
                let mut probe = template.clone();
                let index = if class { tag_at + TAG_LEN - 1 } else { tag_at };
                probe[index] ^= 0x01;
                let start = Instant::now();
                for _ in 0..TAG_BATCH {
                    if aead.open(&mut probe, b"timing-lab aad").is_ok() {
                        return Err("corrupted token accepted".into());
                    }
                }
                Ok(start.elapsed().as_nanos() as u64)
            },
        )?);
    }

    // error/record-reject: the full record rejection path through a live
    // server connection — deframing, decrypt failure, and the alert state
    // machine — with the tag corrupted at the first vs last byte. A fresh
    // handshake per trial, because a TLS connection is unusable after a
    // decrypt failure; the handshake runs outside the timed window.
    {
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        let identity = RpkIdentity::from_pkcs8_der(&ed25519_pkcs8(&seed))
            .map_err(|e| format!("error-path identity: {e}"))?;
        let (client_config, server_config) = rpk_pair(provider.clone(), &identity, false)?;
        let mut message = vec![0u8; TAG_PROBE_LEN];
        rng.fill(&mut message);
        reports.push(measure(
            "error/record-reject",
            false,
            samples,
            1,
            &mut rng,
            |class| {
                use std::io::Write;
                let (mut client, mut server) = new_connections(&client_config, &server_config)?;
                handshake_timed(&mut client, &mut server)?;
                client
                    .writer()
                    .write_all(&message)
                    .map_err(|e| format!("client write: {e}"))?;
                let mut wire = Vec::with_capacity(TAG_PROBE_LEN + 64);
                while client.wants_write() {
                    client
                        .write_tls(&mut wire)
                        .map_err(|e| format!("client write_tls: {e}"))?;
                }
                let index = if class {
                    wire.len() - 1
                } else {
                    wire.len() - TAG_LEN
                };
                wire[index] ^= 0x01;
                let start = Instant::now();
                let mut rd = &wire[..];
                while !rd.is_empty() {
                    server
                        .read_tls(&mut rd)
                        .map_err(|e| format!("server read_tls: {e}"))?;
                }
                let rejected = server.process_new_packets().is_err();
                let ns = start.elapsed().as_nanos() as u64;
                if !rejected {
                    return Err("corrupted record accepted".into());
                }
                Ok(ns)
            },
        )?);
    }

    // Isolation surfaces (TIMING_LAB_ISOLATE=1): investigation aids for a
    // LEAK on the seal surfaces, splitting the AES-GCM seal into its
    // kernels and removing prep-state asymmetries one at a time.
    //
    // "Mask prep" replaces the fixed-vs-random buffer selection with one
    // buffer written through one code path in both classes — work[i] =
    // random[i] & mask, mask 0x00 or 0xff — so the classes' instruction
    // traces and memory traffic are identical and only the VALUES differ.
    // A leak that survives mask prep is value dependence in the timed
    // kernel; one that dies was an artifact of the classes' differing
    // cache/write-back state.
    if std::env::var_os("TIMING_LAB_ISOLATE").is_some() {
        let mask_prep = |work: &mut [u8], random: &[u8], class: bool| {
            let mask = std::hint::black_box(if class { 0xffu8 } else { 0x00 });
            for (w, r) in work.iter_mut().zip(random) {
                *w = r & mask;
            }
        };

        // The record seal under mask prep.
        {
            let mut rig = record_rig(rustls::CipherSuite::TLS13_AES_128_GCM_SHA256, &mut rng)?;
            let mut random = vec![0u8; SEAL_LEN];
            let mut work = vec![0u8; SEAL_LEN];
            let mut inputs = Rng::new(rng.next_u64());
            let seq = rig.seq;
            let enc = &mut rig.enc;
            reports.push(measure(
                "isolate/record-aes-seal/mask-prep",
                false,
                samples,
                1,
                &mut rng,
                |class| {
                    inputs.fill(&mut random);
                    mask_prep(&mut work, &random, class);
                    let start = Instant::now();
                    let sealed = enc
                        .encrypt(
                            OutboundPlainMessage {
                                typ: ContentType::ApplicationData,
                                version: ProtocolVersion::TLSv1_3,
                                payload: OutboundChunks::new(&[&work]),
                            },
                            seq,
                        )
                        .map_err(|e| format!("seal: {e}"))?;
                    let ns = start.elapsed().as_nanos() as u64;
                    std::hint::black_box(sealed.payload.as_ref().len());
                    Ok(ns)
                },
            )?);
        }

        // The packet seal under mask prep.
        {
            let rig = packet_rig(polymorph_tls_quinn::TLS13_AES_128_GCM_SHA256, &mut rng)?;
            let mut random = vec![0u8; SEAL_LEN];
            let mut work = vec![0u8; SEAL_LEN];
            let mut inputs = Rng::new(rng.next_u64());
            let sealer = &rig.seal.local.packet;
            reports.push(measure(
                "isolate/packet-aes-seal/mask-prep",
                false,
                samples,
                1,
                &mut rng,
                |class| {
                    inputs.fill(&mut random);
                    mask_prep(&mut work, &random, class);
                    let start = Instant::now();
                    let tag = sealer
                        .encrypt_in_place(PACKET_NUMBER, &PACKET_HEADER, &mut work)
                        .map_err(|e| format!("seal: {e}"))?;
                    let ns = start.elapsed().as_nanos() as u64;
                    std::hint::black_box(tag.as_ref());
                    Ok(ns)
                },
            )?);
        }

        // AES-CTR alone (keystream generation + XOR application; no GHASH),
        // fixed key and IV so the keystream is identical every call, mask
        // prep. The cipher is constructed inside the window in both classes
        // (class-independent key schedule).
        {
            use ctr::cipher::{KeyIvInit, StreamCipher};
            type Ctr128 = ctr::Ctr32BE<aes::Aes128>;
            let mut key = [0u8; 16];
            rng.fill(&mut key);
            let iv = [0u8; 16];
            let mut random = vec![0u8; SEAL_LEN];
            let mut work = vec![0u8; SEAL_LEN];
            let mut inputs = Rng::new(rng.next_u64());
            reports.push(measure(
                "isolate/aes-ctr/apply-keystream",
                false,
                samples,
                1,
                &mut rng,
                |class| {
                    inputs.fill(&mut random);
                    mask_prep(&mut work, &random, class);
                    let start = Instant::now();
                    let mut cipher = Ctr128::new(&key.into(), &iv.into());
                    cipher.apply_keystream(&mut work);
                    let ns = start.elapsed().as_nanos() as u64;
                    std::hint::black_box(&work);
                    Ok(ns)
                },
            )?);
        }

        // GHASH alone over all-zero vs random input, mask prep: probes
        // input-value dependence of the soft carryless multiply at the
        // extreme low end of the operand-weight distribution. NOTE the real
        // seal never feeds GHASH zeros (its input is the ciphertext, random-
        // looking in both classes); this is the wider net.
        {
            use ghash::universal_hash::UniversalHash;
            let mut h = [0u8; 16];
            rng.fill(&mut h);
            let mut random = vec![0u8; SEAL_LEN];
            let mut work = vec![0u8; SEAL_LEN];
            let mut inputs = Rng::new(rng.next_u64());
            reports.push(measure(
                "isolate/ghash/zeros-vs-random",
                false,
                samples,
                1,
                &mut rng,
                |class| {
                    inputs.fill(&mut random);
                    mask_prep(&mut work, &random, class);
                    let start = Instant::now();
                    let mut g = ghash::GHash::new(&h.into());
                    g.update_padded(&work);
                    let tag = g.finalize();
                    let ns = start.elapsed().as_nanos() as u64;
                    std::hint::black_box(tag);
                    Ok(ns)
                },
            )?);
        }

        // GHASH alone over a FIXED random-looking value vs a fresh random
        // value — the class structure GHASH actually sees inside the seal
        // (class 0's ciphertext is the keystream, the same value every
        // call). Copy prep: work is written in both classes.
        {
            use ghash::universal_hash::UniversalHash;
            let mut h = [0u8; 16];
            rng.fill(&mut h);
            let mut fixed_rand = vec![0u8; SEAL_LEN];
            rng.fill(&mut fixed_rand);
            let mut random = vec![0u8; SEAL_LEN];
            let mut work = vec![0u8; SEAL_LEN];
            let mut inputs = Rng::new(rng.next_u64());
            reports.push(measure(
                "isolate/ghash/fixedrand-vs-random",
                false,
                samples,
                1,
                &mut rng,
                |class| {
                    inputs.fill(&mut random);
                    work.copy_from_slice(if class { &random } else { &fixed_rand });
                    let start = Instant::now();
                    let mut g = ghash::GHash::new(&h.into());
                    g.update_padded(&work);
                    let tag = g.finalize();
                    let ns = start.elapsed().as_nanos() as u64;
                    std::hint::black_box(tag);
                    Ok(ns)
                },
            )?);
        }

        // A bare XOR sweep (read 16 KiB, XOR a fixed pad, write 16 KiB),
        // mask prep: the pure "values are zeros vs random" probe with no
        // cryptography at all. A leak here would mean the measurement
        // itself sees data values (physical effects), not any cipher code.
        {
            const XOR_BATCH: u32 = 4;
            let mut pad = vec![0u8; SEAL_LEN];
            rng.fill(&mut pad);
            let mut random = vec![0u8; SEAL_LEN];
            let mut work = vec![0u8; SEAL_LEN];
            let mut out = vec![0u8; SEAL_LEN];
            let mut inputs = Rng::new(rng.next_u64());
            reports.push(measure(
                "isolate/xor-sweep/zeros-vs-random",
                false,
                samples,
                XOR_BATCH,
                &mut rng,
                |class| {
                    inputs.fill(&mut random);
                    mask_prep(&mut work, &random, class);
                    let start = Instant::now();
                    for _ in 0..XOR_BATCH {
                        for ((o, w), p) in out.iter_mut().zip(&work).zip(&pad) {
                            *o = w ^ p;
                        }
                        std::hint::black_box(&out);
                    }
                    Ok(start.elapsed().as_nanos() as u64)
                },
            )?);
        }
    }

    // Render and evaluate.
    let mut failures = 0;
    println!(
        "timing lab: {samples} samples/class, seed {seed:#x}, threshold max |t| > {THRESHOLD}"
    );
    println!();
    println!(
        "| surface | samples/class | batch | mean ns | sigma ns | delta ns | max \\|t\\| | verdict | expected |"
    );
    println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- |");
    for r in &reports {
        let verdict = match r.verdict {
            Verdict::Quiet => "quiet",
            Verdict::Leak => "LEAK",
            Verdict::Inconclusive => "inconclusive",
        };
        let expected = if r.expect_leak { "leak" } else { "quiet" };
        let ok = matches!(
            (&r.verdict, r.expect_leak),
            (Verdict::Leak, true) | (Verdict::Quiet, false)
        );
        if !ok {
            failures += 1;
        }
        println!(
            "| {} | {} | {} | {:.0} | {:.0} | {:.0} | {:.1} | {}{} | {} |",
            r.name,
            r.samples_per_class,
            r.batch,
            r.mean_ns,
            r.sigma_ns,
            r.delta_ns,
            r.max_t,
            verdict,
            if ok { "" } else { " ***" },
            expected,
        );
    }
    println!();
    if failures > 0 {
        return Err(format!(
            "{failures} surface(s) diverged from expectation (see ***). \
             A quiet positive control means the harness cannot detect leaks \
             at this measurement distance; a LEAK on a real surface warrants \
             investigation (statistical flakes happen — rerun with more \
             samples via TIMING_LAB_SAMPLES before drawing conclusions)."
        ));
    }
    println!("OK: all surfaces matched expectations.");
    Ok(())
}

fn main() -> std::process::ExitCode {
    // TIMING_LAB_DIT=1 (native aarch64 only): set PSTATE.DIT, making the
    // instructions FEAT_DIT covers data-independent-timing in hardware. An
    // investigation knob: a leak that DIT suppresses is hardware operand-
    // dependent timing, not a code path. Wasm runs cannot set it — a guest
    // has no PSTATE access and wasmtime does not set it either — which is
    // part of the hardware floor recorded in README.md.
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    if std::env::var_os("TIMING_LAB_DIT").is_some() {
        // MSR DIT, #1 (FEAT_DIT is architecturally EL0-accessible; present
        // on this host per /proc/cpuinfo `dit`).
        unsafe { core::arch::asm!(".inst 0xd503415f", options(nomem, nostack, preserves_flags)) };
        eprintln!("timing lab: PSTATE.DIT set");
    }
    match run_lab() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("timing lab failed: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}
