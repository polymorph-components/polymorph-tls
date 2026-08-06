//! RFC 9001 packet protection and header protection over RustCrypto
//! primitives, including the multipath nonce construction
//! (draft-ietf-quic-multipath-11) noq-proto's path-aware calls use.
//!
//! These implement [`rustls::quic::Algorithm`] for the profile's two cipher
//! suites, using the same AEAD implementations the record layer uses:
//! ChaCha20-Poly1305 (class A/B) and fixsliced AES-128-GCM (class C + B).

use aead::consts::{U12, U16};
use aead::{AeadCore, AeadInOut, KeyInit};
use aes::cipher::{BlockCipherEncrypt, KeyIvInit, StreamCipher, StreamCipherSeek};
use rustls::crypto::cipher::{AeadKey, Iv, Nonce};
use rustls::quic;
use rustls::Error;
use subtle::{Choice, ConditionallySelectable as _};

pub(crate) static AES_128_GCM: Aes128GcmAlgorithm = Aes128GcmAlgorithm;
pub(crate) static CHACHA20_POLY1305: ChaCha20Poly1305Algorithm = ChaCha20Poly1305Algorithm;

// AEAD usage limits from RFC 9001 §6.6 / Appendix B.
const AES_128_GCM_CONFIDENTIALITY_LIMIT: u64 = 1 << 23;
const AES_128_GCM_INTEGRITY_LIMIT: u64 = 1 << 52;
// ChaCha20-Poly1305 has no meaningful confidentiality limit; packet numbers
// cap at 2^62 - 1 (RFC 9000 §17.1).
const CHACHA20_POLY1305_CONFIDENTIALITY_LIMIT: u64 = 1 << 62;
const CHACHA20_POLY1305_INTEGRITY_LIMIT: u64 = 1 << 36;

pub(crate) struct Aes128GcmAlgorithm;

impl quic::Algorithm for Aes128GcmAlgorithm {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        Box::new(PacketKey {
            cipher: aes_gcm::Aes128Gcm::new_from_slice(key.as_ref()).expect("invalid key length"),
            iv,
            confidentiality_limit: AES_128_GCM_CONFIDENTIALITY_LIMIT,
            integrity_limit: AES_128_GCM_INTEGRITY_LIMIT,
        })
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        Box::new(AesHeaderProtectionKey(
            aes::Aes128::new_from_slice(key.as_ref()).expect("invalid key length"),
        ))
    }

    fn aead_key_len(&self) -> usize {
        16
    }
}

pub(crate) struct ChaCha20Poly1305Algorithm;

impl quic::Algorithm for ChaCha20Poly1305Algorithm {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        Box::new(PacketKey {
            cipher: chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                .expect("invalid key length"),
            iv,
            confidentiality_limit: CHACHA20_POLY1305_CONFIDENTIALITY_LIMIT,
            integrity_limit: CHACHA20_POLY1305_INTEGRITY_LIMIT,
        })
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        let key: [u8; 32] = key.as_ref().try_into().expect("invalid key length");
        Box::new(ChaChaHeaderProtectionKey(zeroize::Zeroizing::new(key)))
    }

    fn aead_key_len(&self) -> usize {
        32
    }
}

struct PacketKey<C> {
    cipher: C,
    iv: Iv,
    confidentiality_limit: u64,
    integrity_limit: u64,
}

impl<C> quic::PacketKey for PacketKey<C>
where
    C: AeadInOut + AeadCore<NonceSize = U12, TagSize = U16> + Send + Sync,
{
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, Error> {
        let nonce = Nonce::new(&self.iv, packet_number).0;
        let tag = self
            .cipher
            .encrypt_inout_detached(&nonce.into(), header, payload.into())
            .map_err(|_| Error::EncryptError)?;
        Ok(quic::Tag::from(tag.as_slice()))
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let plain_len = payload.len().checked_sub(16).ok_or(Error::DecryptError)?;
        let nonce = Nonce::new(&self.iv, packet_number).0;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&payload[plain_len..]);
        self.cipher
            .decrypt_inout_detached(
                &nonce.into(),
                header,
                (&mut payload[..plain_len]).into(),
                &tag.into(),
            )
            .map_err(|_| Error::DecryptError)?;
        Ok(&payload[..plain_len])
    }

    // The multipath nonce (draft-ietf-quic-multipath-11 §"Nonce
    // Calculation"): IV XOR the 96-bit concatenation of path ID and packet
    // number. Path 0 reduces to the RFC 9001 nonce, so noq-proto routes
    // every packet — multipath negotiated or not — through these.

    fn encrypt_in_place_for_path(
        &self,
        path_id: u32,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, Error> {
        let nonce = Nonce::for_path(path_id, &self.iv, packet_number).0;
        let tag = self
            .cipher
            .encrypt_inout_detached(&nonce.into(), header, payload.into())
            .map_err(|_| Error::EncryptError)?;
        Ok(quic::Tag::from(tag.as_slice()))
    }

    fn decrypt_in_place_for_path<'a>(
        &self,
        path_id: u32,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let plain_len = payload.len().checked_sub(16).ok_or(Error::DecryptError)?;
        let nonce = Nonce::for_path(path_id, &self.iv, packet_number).0;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&payload[plain_len..]);
        self.cipher
            .decrypt_inout_detached(
                &nonce.into(),
                header,
                (&mut payload[..plain_len]).into(),
                &tag.into(),
            )
            .map_err(|_| Error::DecryptError)?;
        Ok(&payload[..plain_len])
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn confidentiality_limit(&self) -> u64 {
        self.confidentiality_limit
    }

    fn integrity_limit(&self) -> u64 {
        self.integrity_limit
    }
}

struct AesHeaderProtectionKey(aes::Aes128);

impl AesHeaderProtectionKey {
    /// RFC 9001 §5.4.3: mask = AES-ECB(hp_key, sample)[0..5].
    fn mask(&self, sample: &[u8]) -> Result<[u8; 5], Error> {
        let block: [u8; 16] = sample
            .try_into()
            .map_err(|_| Error::General("sample of invalid length".into()))?;
        let mut block = aes::Block::from(block);
        self.0.encrypt_block(&mut block);
        Ok(block[..5].try_into().unwrap())
    }
}

impl quic::HeaderProtectionKey for AesHeaderProtectionKey {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        xor_in_place(self.mask(sample)?, first, packet_number, false)
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        xor_in_place(self.mask(sample)?, first, packet_number, true)
    }

    fn sample_len(&self) -> usize {
        16
    }
}

// The raw key scrubs itself on drop; the AES twin needs no wrapper — its
// expanded schedule zeroizes via the `aes` crate's `zeroize` feature, as
// do the transient `chacha20` cipher states built per mask.
struct ChaChaHeaderProtectionKey(zeroize::Zeroizing<[u8; 32]>);

impl ChaChaHeaderProtectionKey {
    /// RFC 9001 §5.4.4: the sample's first 4 bytes are the block counter,
    /// the remaining 12 the nonce; the mask is the first 5 bytes of the
    /// resulting ChaCha20 keystream.
    fn mask(&self, sample: &[u8]) -> Result<[u8; 5], Error> {
        let sample: &[u8; 16] = sample
            .try_into()
            .map_err(|_| Error::General("sample of invalid length".into()))?;
        let counter = u32::from_le_bytes(sample[..4].try_into().unwrap());
        let nonce: [u8; 12] = sample[4..].try_into().unwrap();
        let mut cipher = chacha20::ChaCha20::new((&*self.0).into(), &nonce.into());
        cipher.seek(u64::from(counter) * 64);
        let mut mask = [0u8; 5];
        cipher.apply_keystream(&mut mask);
        Ok(mask)
    }
}

impl quic::HeaderProtectionKey for ChaChaHeaderProtectionKey {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        xor_in_place(self.mask(sample)?, first, packet_number, false)
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        xor_in_place(self.mask(sample)?, first, packet_number, true)
    }

    fn sample_len(&self) -> usize {
        16
    }
}

/// Header protection application, RFC 9001 §5.4.1.
///
/// Long headers mask the low 4 bits of the first byte, short headers the low
/// 5; the packet-number field masks as many bytes as the (unmasked) first
/// byte's pn-length bits say. `masked` selects whether `first` must be
/// unmasked before reading those bits.
///
/// The packet-number loop is uniform: every provided byte is visited and
/// the mask is gated by arithmetic selection, never by the loop bound or a
/// branch. `pn_len` comes from the pn-length bits — the field header
/// protection exists to hide, unmasked one line above on the decrypt path —
/// so control flow that depends on it is a timing side channel. Do not
/// "simplify" to `take(pn_len)` or an early exit: bytes at and past
/// `pn_len` XOR with zero, which the RFC 9001 Appendix A vectors pin. On
/// decrypt the caller always provides the full 4-byte region (§5.4.2's
/// sampling arithmetic guarantees it exists), so uniformity here makes
/// that path's timing independent of the protected bits; on encrypt the
/// caller's slice is already exactly `pn_len` bytes, an upstream trait
/// shape this function cannot widen.
fn xor_in_place(
    mask: [u8; 5],
    first: &mut u8,
    packet_number: &mut [u8],
    masked: bool,
) -> Result<(), Error> {
    let (first_mask, pn_mask) = mask.split_first().unwrap();
    if packet_number.len() > pn_mask.len() {
        return Err(Error::General("packet number too long".into()));
    }

    const LONG_HEADER_FORM: u8 = 0x80;
    // The form bit is never masked (public), so this branch is benign.
    let bits = match *first & LONG_HEADER_FORM == LONG_HEADER_FORM {
        true => 0x0f,
        false => 0x1f,
    };

    let first_plain = match masked {
        true => *first ^ (first_mask & bits),
        false => *first,
    };
    let pn_len = (first_plain & 0x03) as usize + 1;

    *first ^= first_mask & bits;
    for (index, (dst, m)) in packet_number.iter_mut().zip(pn_mask).enumerate() {
        let in_pn = Choice::from(u8::from(index < pn_len));
        *dst ^= u8::conditional_select(&0, m, in_pn);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rustls::quic::{Algorithm, PacketKey as _};

    use super::*;

    /// RFC 9001 §A.2: AES header protection mask for the client Initial.
    #[test]
    fn aes_header_protection_mask_vector() {
        let hp_key: [u8; 16] = [
            0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad,
            0xed, 0xd2,
        ];
        let sample: [u8; 16] = [
            0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8, 0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23,
            0xdc, 0x9b,
        ];
        let key = AesHeaderProtectionKey(aes::Aes128::new_from_slice(&hp_key).unwrap());
        assert_eq!(key.mask(&sample).unwrap(), [0x43, 0x7b, 0x9a, 0xec, 0x36]);
    }

    /// RFC 9001 §A.5: ChaCha20 header protection mask.
    #[test]
    fn chacha_header_protection_mask_vector() {
        let hp_key: [u8; 32] = [
            0x25, 0xa2, 0x82, 0xb9, 0xe8, 0x2f, 0x06, 0xf2, 0x1f, 0x48, 0x89, 0x17, 0xa4, 0xfc,
            0x8f, 0x1b, 0x73, 0x57, 0x36, 0x85, 0x60, 0x85, 0x97, 0xd0, 0xef, 0xcb, 0x07, 0x6b,
            0x0a, 0xb7, 0xa7, 0xa4,
        ];
        let sample: [u8; 16] = [
            0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90, 0x80, 0x57, 0x5d, 0x79, 0x99, 0xc2, 0x5a,
            0x5b, 0xfb,
        ];
        let key = ChaChaHeaderProtectionKey(zeroize::Zeroizing::new(hp_key));
        assert_eq!(key.mask(&sample).unwrap(), [0xae, 0xfe, 0xfe, 0x7d, 0x03]);
    }

    /// Guards `xor_in_place`'s uniform-loop contract: with a 2-byte packet
    /// number, decrypt's full 4-byte region unmasks exactly the two pn
    /// bytes — the trailing payload bytes come back untouched — and the
    /// round trip restores the original header.
    #[test]
    fn header_protection_masks_only_the_pn_length() {
        let hp_key: [u8; 16] = [
            0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad,
            0xed, 0xd2,
        ];
        let sample: [u8; 16] = [
            0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8, 0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23,
            0xdc, 0x9b,
        ];
        let key = AesHeaderProtectionKey(aes::Aes128::new_from_slice(&hp_key).unwrap());

        // Short header, pn-length bits = 0b01: a 2-byte packet number.
        let mut first = 0x41u8;
        let mut pn = [0x00u8, 0x01];
        quic::HeaderProtectionKey::encrypt_in_place(&key, &sample, &mut first, &mut pn).unwrap();
        assert_ne!(first, 0x41);

        // Decrypt sees the full 4-byte region the sampling arithmetic
        // guarantees: the two masked pn bytes plus two payload bytes.
        let mut region = [pn[0], pn[1], 0xaa, 0xbb];
        quic::HeaderProtectionKey::decrypt_in_place(&key, &sample, &mut first, &mut region)
            .unwrap();
        assert_eq!(first, 0x41);
        assert_eq!(region, [0x00, 0x01, 0xaa, 0xbb]);
    }

    /// RFC 9001 §A.5: ChaCha20-Poly1305 short-packet protection.
    #[test]
    fn chacha_packet_protection_vector() {
        let key: [u8; 32] = [
            0xc6, 0xd9, 0x8f, 0xf3, 0x44, 0x1c, 0x3f, 0xe1, 0xb2, 0x18, 0x20, 0x94, 0xf6, 0x9c,
            0xaa, 0x2e, 0xd4, 0xb7, 0x16, 0xb6, 0x54, 0x88, 0x96, 0x0a, 0x7a, 0x98, 0x49, 0x79,
            0xfb, 0x23, 0xe1, 0xc8,
        ];
        let iv: [u8; 12] = [
            0xe0, 0x45, 0x9b, 0x34, 0x74, 0xbd, 0xd0, 0xe4, 0x4a, 0x41, 0xc1, 0x44,
        ];
        let pk = CHACHA20_POLY1305.packet_key(AeadKey::from(key), Iv::from(iv));

        // A one-byte ping frame in a short-header packet, pn=654360564.
        let header: [u8; 4] = [0x42, 0x00, 0xbf, 0xf4];
        let mut payload = [0x01u8];
        let tag = pk
            .encrypt_in_place(654_360_564, &header, &mut payload)
            .unwrap();
        assert_eq!(payload, [0x65]);
        assert_eq!(
            tag.as_ref(),
            &[
                0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90, 0x80, 0x57, 0x5d, 0x79, 0x99, 0xc2, 0x5a,
                0x5b, 0xfb
            ]
        );

        let mut sealed = Vec::from(payload);
        sealed.extend_from_slice(tag.as_ref());
        let plain = pk
            .decrypt_in_place(654_360_564, &header, &mut sealed)
            .unwrap();
        assert_eq!(plain, &[0x01]);
    }

    /// Initial keys are AES-128-GCM (RFC 9001 §5.2); a client→server
    /// roundtrip through the public derivation path covers the AES packet
    /// key end to end.
    #[test]
    fn aes_initial_keys_roundtrip() {
        let suite = crate::suites::TLS13_AES_128_GCM_SHA256
            .tls13()
            .unwrap()
            .quic_suite()
            .unwrap();
        let cid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let client = suite.keys(&cid, rustls::Side::Client, rustls::quic::Version::V1);
        let server = suite.keys(&cid, rustls::Side::Server, rustls::quic::Version::V1);

        let header = [0xc3u8, 1, 2, 3];
        let mut buf = b"hello quic".to_vec();
        let tag = client
            .local
            .packet
            .encrypt_in_place(9, &header, &mut buf)
            .unwrap();
        buf.extend_from_slice(tag.as_ref());
        assert_eq!(
            server
                .remote
                .packet
                .decrypt_in_place(9, &header, &mut buf)
                .unwrap(),
            b"hello quic"
        );
        // Tampered header fails integrity.
        let mut buf2 = buf.clone();
        assert!(server
            .remote
            .packet
            .decrypt_in_place(9, &[0xc3u8, 1, 2, 4], &mut buf2)
            .is_err());
    }

    /// TLS 1.3 HKDF-Expand-Label over SHA-256, for deriving the multipath
    /// vector's key and IV from its traffic secret.
    fn expand_label(secret: &[u8; 32], label: &[u8], out: &mut [u8]) {
        let hk = hkdf::Hkdf::<sha2::Sha256>::from_prk(secret).unwrap();
        let mut info = Vec::new();
        info.extend_from_slice(&(out.len() as u16).to_be_bytes());
        info.push((6 + label.len()) as u8);
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label);
        info.push(0);
        hk.expand(&info, out).unwrap();
    }

    /// The multipath traffic secret picoquic's `multipath_aead_test` uses
    /// (note the 35 where 25 would be — the quirk is part of the vector).
    const MULTIPATH_SECRET: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        35, 26, 27, 28, 29, 30, 31,
    ];
    const MULTIPATH_PAYLOAD: &[u8] = b"The quick brown fox jumps over the lazy dog";
    const MULTIPATH_HEADER: &[u8] = b"This is a test";

    fn multipath_packet_key() -> PacketKey<aes_gcm::Aes128Gcm> {
        let mut key = [0u8; 16];
        expand_label(&MULTIPATH_SECRET, b"quic key", &mut key);
        let mut iv = [0u8; 12];
        expand_label(&MULTIPATH_SECRET, b"quic iv", &mut iv);
        PacketKey {
            cipher: aes_gcm::Aes128Gcm::new_from_slice(&key).unwrap(),
            iv: Iv::from(iv),
            confidentiality_limit: AES_128_GCM_CONFIDENTIALITY_LIMIT,
            integrity_limit: AES_128_GCM_INTEGRITY_LIMIT,
        }
    }

    /// Multipath packet protection pinned to picoquic's
    /// `multipath_aead_test` output — the same vector rustls's providers
    /// pin their `_for_path` implementations to.
    #[test]
    fn multipath_aead_vector() {
        const EXPECTED: &[u8] = &[
            123, 139, 232, 52, 136, 25, 201, 143, 250, 89, 87, 39, 37, 63, 0, 210, 220, 227, 186,
            140, 183, 251, 13, 203, 6, 116, 204, 100, 166, 64, 43, 185, 174, 85, 212, 163, 242,
            141, 24, 166, 62, 228, 187, 137, 248, 31, 152, 126, 240, 151, 79, 51, 253, 130, 43,
            114, 173, 234, 254,
        ];

        let pk = multipath_packet_key();
        let mut buf = MULTIPATH_PAYLOAD.to_vec();
        let tag = pk
            .encrypt_in_place_for_path(2, 12345, MULTIPATH_HEADER, &mut buf)
            .unwrap();
        buf.extend_from_slice(tag.as_ref());
        assert_eq!(buf.as_slice(), EXPECTED);
    }

    /// Path 0's multipath nonce is RFC 9001's nonce: `_for_path(0, ..)`
    /// interoperates with the plain methods, every path round-trips, and
    /// a packet sealed on one path does not open on another.
    #[test]
    fn multipath_roundtrip_and_path_zero_equivalence() {
        let pk = multipath_packet_key();

        for path_id in [0u32, 1, 2, 0xaead] {
            let mut buf = MULTIPATH_PAYLOAD.to_vec();
            let tag = pk
                .encrypt_in_place_for_path(path_id, 12345, MULTIPATH_HEADER, &mut buf)
                .unwrap();
            buf.extend_from_slice(tag.as_ref());
            let plain = pk
                .decrypt_in_place_for_path(path_id, 12345, MULTIPATH_HEADER, &mut buf)
                .unwrap();
            assert_eq!(plain, MULTIPATH_PAYLOAD);
        }

        let mut buf = MULTIPATH_PAYLOAD.to_vec();
        let tag = pk
            .encrypt_in_place(12345, MULTIPATH_HEADER, &mut buf)
            .unwrap();
        buf.extend_from_slice(tag.as_ref());
        let mut cross = buf.clone();
        assert_eq!(
            pk.decrypt_in_place_for_path(0, 12345, MULTIPATH_HEADER, &mut cross)
                .unwrap(),
            MULTIPATH_PAYLOAD
        );
        let mut wrong = buf.clone();
        assert!(pk
            .decrypt_in_place_for_path(1, 12345, MULTIPATH_HEADER, &mut wrong)
            .is_err());
    }
}
