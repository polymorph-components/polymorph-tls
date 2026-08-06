//! The `polymorph:tls` conformance suite.
//!
//! Cases exercise the package's WIT surface — the composed component is
//! the system under test — on the `polymorph:test` contract, so one
//! suite artifact runs identically against every delivery a target
//! composes in (in-guest Ed25519 posture, the `tls-delegated` world
//! with a composed signer). Target facts live in
//! `conformance/driver-ct/targets.toml`; the committed case inventory
//! in `tests.lock`.

// The whole crate is wasm32-only: the SDK glue exports the component
// contract, which only exists for the component target (the native
// build is an empty shell; `just clippy` lints the real target).
#![cfg(target_arch = "wasm32")]

// The system under test: the `polymorph:tls` package surface, imported
// exactly as a consumer would. The `polymorph:test` contract bindings
// come from the SDK (disjoint packages, merged at link).
wit_bindgen::generate!({
    path: "../../wit",
    inline: "
        package inline:conformance;
        world suite-sut {
            import polymorph:tls/types@0.1.0;
            import polymorph:tls/client@0.1.0;
            import polymorph:tls/server@0.1.0;
        }
    ",
    generate_all,
});

mod support;

#[component_test_sdk::suite(name = "")]
mod tls {
    mod identity {
        mod ed25519 {
            /// The structural signing gate: the Ed25519 constructor is
            /// the only way to introduce in-guest signing capability,
            /// and it rejects everything the profile forbids.
            #[case]
            async fn reject_foreign_key() -> Verdict {
                use crate::polymorph::tls::server::Identity;
                check!(
                    Identity::ed25519(
                        &[crate::support::LEAF_DER.to_vec()],
                        crate::support::P256_KEY_P8,
                    )
                    .is_err(),
                    "ed25519 identity must reject non-Ed25519 key material"
                );
                Ok(())
            }
        }
    }

    mod handshake {
        #[case]
        async fn alpn_sni() -> Verdict {
            let identity = crate::support::ed25519_identity().or_fail()?;
            let lb = crate::support::connect(&identity).await.or_fail()?;
            check_eq!(
                lb.client_info.alpn_protocol.as_deref(),
                Some(crate::support::ALPN),
                "client-side negotiated ALPN"
            );
            check_eq!(
                lb.server_info.alpn_protocol.as_deref(),
                Some(crate::support::ALPN),
                "server-side negotiated ALPN"
            );
            check_eq!(
                lb.server_info.server_name.as_deref(),
                Some(crate::support::SERVER_NAME),
                "SNI as seen by the acceptor"
            );
            check_eq!(
                lb.client_info.server_name.as_deref(),
                None::<&str>,
                "server-name on an initiated connection"
            );
            lb.shutdown().await.or_fail()?;
            Ok(())
        }
    }

    mod data {
        /// Application data crosses both transforms in both directions.
        #[case]
        async fn echo() -> Verdict {
            const MESSAGE: &[u8] = b"hello over the polymorph:tls component";
            let identity = crate::support::ed25519_identity().or_fail()?;
            let mut lb = crate::support::connect(&identity).await.or_fail()?;

            let leftover = lb.client_tx.write_all(MESSAGE.to_vec()).await;
            check!(leftover.is_empty(), "client write accepted only partially");
            let received = crate::support::read_exact(&mut lb.server_rx, MESSAGE.len()).await;
            check_eq!(received, MESSAGE, "server-received bytes");

            let leftover = lb.server_tx.write_all(received).await;
            check!(leftover.is_empty(), "server write accepted only partially");
            let echoed = crate::support::read_exact(&mut lb.client_rx, MESSAGE.len()).await;
            check_eq!(echoed, MESSAGE, "client-received echo");

            lb.shutdown().await.or_fail()?;
            Ok(())
        }
    }

    mod shutdown {
        /// Closing both write directions with no application data still
        /// yields a clean close_notify in every direction.
        #[case]
        async fn close_notify() -> Verdict {
            let identity = crate::support::ed25519_identity().or_fail()?;
            let lb = crate::support::connect(&identity).await.or_fail()?;
            lb.shutdown().await.or_fail()?;
            Ok(())
        }
    }

    mod delegated {
        /// The decline half of the signer gate: with no signer
        /// composed, delegated identities must fail at construction,
        /// not at first use.
        #[case(tags("!delegated-signer"))]
        async fn decline() -> Verdict {
            use crate::polymorph::tls::server::Identity;
            check!(
                Identity::delegated(vec![crate::support::LEAF_DER.to_vec()])
                    .await
                    .is_err(),
                "delegated identity must fail without a composed signer"
            );
            Ok(())
        }

        /// The delegated posture: the component holds only the
        /// certificate chain; CertificateVerify is signed by the
        /// composed signer.
        #[case(tags("delegated-signer"))]
        async fn handshake() -> Verdict {
            use crate::polymorph::tls::server::Identity;
            let identity = Identity::delegated(vec![crate::support::LEAF_DER.to_vec()])
                .await
                .map_err(crate::support::render)
                .or_fail()?;
            let lb = crate::support::connect(&identity).await.or_fail()?;
            check_eq!(
                lb.client_info.alpn_protocol.as_deref(),
                Some(crate::support::ALPN),
                "ALPN over a delegated-identity handshake"
            );
            lb.shutdown().await.or_fail()?;
            Ok(())
        }

        /// The in-guest Ed25519 posture coexists with the signer import.
        #[case(tags("delegated-signer"))]
        async fn coexist_in_guest_ed25519() -> Verdict {
            let identity = crate::support::ed25519_identity().or_fail()?;
            let lb = crate::support::connect(&identity).await.or_fail()?;
            lb.shutdown().await.or_fail()?;
            Ok(())
        }
    }
}
