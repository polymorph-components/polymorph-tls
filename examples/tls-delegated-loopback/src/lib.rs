//! Composed smoke test for the `tls-delegated` world.
//!
//! Like `tls-loopback`, but the server identity is *delegated*: the TLS
//! component holds only the certificate chain, and CertificateVerify is
//! signed by the composed `polymorph:tls/signer` implementation. Also verifies
//! the in-guest Ed25519 posture still works alongside the signer import.
//!
//! Run composed under a runtime with component-model async enabled.

use futures::join;
use wit_bindgen::StreamResult;

wit_bindgen::generate!({
    path: "../../wit",
    inline: "
        package inline:app;
        world app {
            import polymorph:tls/types@0.1.0;
            import polymorph:tls/client@0.1.0;
            import polymorph:tls/server@0.1.0;
        }
    ",
    generate_all,
});

use polymorph::tls::client::Connector;
use polymorph::tls::server::{Acceptor, Identity};

const CA_DER: &[u8] = include_bytes!("../../../rust/quic/tests/testdata/ca.der");
const LEAF_DER: &[u8] = include_bytes!("../../../rust/quic/tests/testdata/leaf.der");
const LEAF_KEY_P8: &[u8] = include_bytes!("../../../rust/quic/tests/testdata/leaf-key.p8");

const ALPN: &[u8] = b"tls-delegated-loopback/1";
const MESSAGE: &[u8] = b"hello via the composed signer";

struct Component;

impl wasip3::exports::cli::run::Guest for Component {
    async fn run() -> Result<(), ()> {
        // The delegated posture: chain only, no key material.
        let identity = Identity::delegated(vec![LEAF_DER.to_vec()])
            .await
            .expect("composed signer serves delegation");
        roundtrip(&identity, "delegated identity").await?;

        // The in-guest Ed25519 posture coexists with the signer import.
        let identity = Identity::ed25519(&[LEAF_DER.to_vec()], LEAF_KEY_P8)
            .expect("Ed25519 identity from testdata");
        roundtrip(&identity, "in-guest Ed25519 identity").await?;

        println!("tls delegated loopback OK");
        Ok(())
    }
}

wasip3::cli::command::export!(Component);

/// One full connection: handshake as `identity`, one message, clean close.
async fn roundtrip(identity: &Identity, label: &str) -> Result<(), ()> {
    let connector = Connector::new(&[CA_DER.to_vec()]);
    let acceptor = Acceptor::new(identity);

    let (mut client_app_tx, client_app_rx) = wit_stream::new();
    let (client_ct, client_send_done) = connector.send(client_app_rx);
    let (mut server_app_rx, server_recv_done) = acceptor.receive(client_ct);

    let (server_app_tx, server_app_reply_rx) = wit_stream::new();
    let (server_ct, server_send_done) = acceptor.send(server_app_reply_rx);
    let (client_app_reply_rx, client_recv_done) = connector.receive(server_ct);

    let (client_info, server_info) = join!(
        connector.connect("localhost".to_string(), vec![ALPN.to_vec()]),
        acceptor.accept(vec![ALPN.to_vec()]),
    );
    let client_info = client_info.map_err(|e| eprintln!("client: {}", e.to_debug_string()))?;
    let server_info = server_info.map_err(|e| eprintln!("server: {}", e.to_debug_string()))?;
    assert_eq!(client_info.alpn_protocol.as_deref(), Some(ALPN));
    assert_eq!(server_info.server_name.as_deref(), Some("localhost"));

    let leftover = client_app_tx.write_all(MESSAGE.to_vec()).await;
    assert!(leftover.is_empty());
    let mut received = Vec::new();
    while received.len() < MESSAGE.len() {
        let (status, chunk) = server_app_rx.read(Vec::with_capacity(MESSAGE.len())).await;
        received.extend_from_slice(&chunk);
        if matches!(status, StreamResult::Dropped | StreamResult::Cancelled) {
            break;
        }
    }
    assert_eq!(received, MESSAGE, "server received the message ({label})");

    drop(client_app_tx);
    drop(server_app_tx);
    drop(client_app_reply_rx);
    for (name, result) in [
        ("client send", client_send_done.await),
        ("server receive", server_recv_done.await),
        ("server send", server_send_done.await),
        ("client receive", client_recv_done.await),
    ] {
        if let Err(e) = result {
            eprintln!("{name} direction failed ({label}): {}", e.to_debug_string());
            return Err(());
        }
    }

    println!("{label}: handshake, data, and clean shutdown OK");
    Ok(())
}
