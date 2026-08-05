//! Composed smoke test for the `polymorph:tls` component.
//!
//! One guest plays both endpoints: a `connector` and an `acceptor` from
//! the composed TLS component, wired to each other by passing each side's
//! ciphertext output stream directly as the other side's transport input —
//! no sockets, no copies in this app. Verifies the handshake (Ed25519
//! identity, ALPN, SNI), bidirectional application data, clean shutdown
//! via close_notify, and the structural signing gates.
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

const CA_DER: &[u8] = include_bytes!("../../../rust/quinn/tests/testdata/ca.der");
const LEAF_DER: &[u8] = include_bytes!("../../../rust/quinn/tests/testdata/leaf.der");
const LEAF_KEY_P8: &[u8] = include_bytes!("../../../rust/quinn/tests/testdata/leaf-key.p8");
const P256_KEY_P8: &[u8] = include_bytes!("../../../rust/profile/src/testdata/p256-key.p8");

const ALPN: &[u8] = b"tls-loopback/1";
const MESSAGE: &[u8] = b"hello over the polymorph:tls component";

struct Component;

impl wasip3::exports::cli::run::Guest for Component {
    async fn run() -> Result<(), ()> {
        // Structural gates: the identity constructors are the only way to
        // introduce signing capability, and they reject everything the
        // profile forbids.
        assert!(
            Identity::ed25519(&[LEAF_DER.to_vec()], P256_KEY_P8).is_err(),
            "ed25519 identity must reject non-Ed25519 key material",
        );
        assert!(
            Identity::delegated(vec![LEAF_DER.to_vec()]).await.is_err(),
            "delegated identity must fail without a composed signer",
        );
        println!("structural gates hold (P-256 key rejected; no signer composed)");

        let identity = Identity::ed25519(&[LEAF_DER.to_vec()], LEAF_KEY_P8)
            .expect("Ed25519 identity from testdata");

        let connector = Connector::new(&[CA_DER.to_vec()]);
        let acceptor = Acceptor::new(&identity);

        // Client → server path: the client's ciphertext output stream *is*
        // the server's transport input.
        let (mut client_app_tx, client_app_rx) = wit_stream::new();
        let (client_ct, client_send_done) = connector.send(client_app_rx);
        let (mut server_app_rx, server_recv_done) = acceptor.receive(client_ct);

        // Server → client path, symmetrically.
        let (mut server_app_tx, server_app_reply_rx) = wit_stream::new();
        let (server_ct, server_send_done) = acceptor.send(server_app_reply_rx);
        let (mut client_app_reply_rx, client_recv_done) = connector.receive(server_ct);

        // Handshake, both sides concurrently: `accept` spawns the server's
        // pumps, so the two calls must overlap.
        let (client_info, server_info) = join!(
            connector.connect("localhost".to_string(), vec![ALPN.to_vec()]),
            acceptor.accept(vec![ALPN.to_vec()]),
        );
        let client_info = client_info.map_err(|e| eprintln!("client: {}", e.to_debug_string()))?;
        let server_info = server_info.map_err(|e| eprintln!("server: {}", e.to_debug_string()))?;

        assert_eq!(client_info.alpn_protocol.as_deref(), Some(ALPN));
        assert_eq!(server_info.alpn_protocol.as_deref(), Some(ALPN));
        assert_eq!(server_info.server_name.as_deref(), Some("localhost"));
        println!(
            "handshake complete (ALPN {}, SNI {})",
            String::from_utf8_lossy(ALPN),
            server_info.server_name.as_deref().unwrap(),
        );

        // Client sends; server reads.
        let leftover = client_app_tx.write_all(MESSAGE.to_vec()).await;
        assert!(leftover.is_empty());
        let received = read_exact(&mut server_app_rx, MESSAGE.len()).await;
        assert_eq!(received, MESSAGE, "server received the client's message");

        // Server echoes; client reads.
        let leftover = server_app_tx.write_all(received).await;
        assert!(leftover.is_empty());
        let echoed = read_exact(&mut client_app_reply_rx, MESSAGE.len()).await;
        assert_eq!(echoed, MESSAGE, "client received the echo");
        println!(
            "application data delivered both ways ({} bytes each)",
            MESSAGE.len()
        );

        // Shutdown: close both write directions; every direction future
        // must resolve cleanly (close_notify, not truncation). The pumps
        // run detached inside the TLS component, so sequential awaits
        // cannot deadlock.
        drop(client_app_tx);
        drop(server_app_tx);
        for (name, result) in [
            ("client send", client_send_done.await),
            ("server receive", server_recv_done.await),
            ("server send", server_send_done.await),
            ("client receive", client_recv_done.await),
        ] {
            match result {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("{name} direction failed: {}", e.to_debug_string());
                    return Err(());
                }
            }
        }
        println!("clean close_notify shutdown in both directions");
        println!("tls loopback OK");
        Ok(())
    }
}

wasip3::cli::command::export!(Component);

/// Reads from `stream` until `len` bytes have arrived (the transforms may
/// deliver data in arbitrary chunks).
async fn read_exact(stream: &mut wit_bindgen::StreamReader<u8>, len: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(len);
    while data.len() < len {
        let (status, chunk) = stream.read(Vec::with_capacity(len - data.len())).await;
        data.extend_from_slice(&chunk);
        if matches!(status, StreamResult::Dropped | StreamResult::Cancelled) {
            break;
        }
    }
    data
}
