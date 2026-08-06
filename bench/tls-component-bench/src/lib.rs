//! Benchmark guest for the composed `polymorph:tls` component.
//!
//! The component-boundary counterpart of `tls-bench bulk`/`handshake`:
//! where that binary runs rustls in-process, this guest pushes the same
//! work through the composed component's streams, so the difference
//! between the two (under the same runtime) is the cost of
//! componentization — canonical-ABI copies and async plumbing — on top
//! of being in wasm at all.
//!
//! Wiring is the loopback pattern: connector and acceptor in one guest,
//! each side's ciphertext output passed directly as the other's
//! transport input. The suite is whatever the component negotiates
//! (the enforced delivery exposes no suite configuration; profile
//! preference order applies).
//!
//! ```text
//! tls-component-bench <bulk-batch-mib> <handshake-batch>
//! ```
//!
//! Output rows match `tls-bench`:
//!
//! ```text
//! bench,component-bulk,negotiated,MB/s,<median>,<min>,<max>
//! bench,component-handshake,ed25519,handshakes/s,<median>,<min>,<max>
//! ```

use std::time::Instant;

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

/// Application write size, matching `tls-bench bulk`.
const CHUNK: usize = 32 * 1024;

/// Batches per measurement; the reported figure is the median batch.
const BATCHES: usize = 5;

struct Component;

impl wasip3::exports::cli::run::Guest for Component {
    async fn run() -> Result<(), ()> {
        let args: Vec<String> = std::env::args().collect();
        let (bulk_mib, handshakes): (usize, usize) = match args.as_slice() {
            [_, mib, hs] => match (mib.parse(), hs.parse()) {
                (Ok(mib), Ok(hs)) => (mib, hs),
                _ => return usage(&args),
            },
            _ => return usage(&args),
        };

        bulk(bulk_mib * 1024 * 1024).await;
        handshake(handshakes).await;
        Ok(())
    }
}

fn usage(args: &[String]) -> Result<(), ()> {
    eprintln!(
        "usage: {} <bulk-batch-mib> <handshake-batch>",
        args.first()
            .map(String::as_str)
            .unwrap_or("tls-component-bench"),
    );
    Err(())
}

wasip3::cli::command::export!(Component);

fn median_row(name: &str, detail: &str, unit: &str, mut rates: Vec<f64>) {
    rates.sort_by(|a, b| a.total_cmp(b));
    println!(
        "bench,{name},{detail},{unit},{:.1},{:.1},{:.1}",
        rates[rates.len() / 2],
        rates[0],
        rates[rates.len() - 1],
    );
}

/// One connected loopback pair, application endpoints only.
async fn connect() -> (
    wit_bindgen::StreamWriter<u8>,
    wit_bindgen::StreamReader<u8>,
    Connector,
    Acceptor,
) {
    let identity = Identity::ed25519(&[LEAF_DER.to_vec()], LEAF_KEY_P8).expect("fixture identity");
    let connector = Connector::new(&[CA_DER.to_vec()]);
    let acceptor = Acceptor::new(&identity);

    let (client_app_tx, client_app_rx) = wit_stream::new();
    let (client_ct, _client_send_done) = connector.send(client_app_rx);
    let (server_app_rx, _server_recv_done) = acceptor.receive(client_ct);

    let (_server_app_tx, server_app_reply_rx) = wit_stream::new();
    let (server_ct, _server_send_done) = acceptor.send(server_app_reply_rx);
    let (_client_app_reply_rx, _client_recv_done) = connector.receive(server_ct);

    let (client_info, server_info) = join!(
        connector.connect("localhost".to_string(), vec![]),
        acceptor.accept(vec![]),
    );
    client_info.expect("handshake (client)");
    server_info.expect("handshake (server)");

    (client_app_tx, server_app_rx, connector, acceptor)
}

/// Client→server plaintext throughput through the composed transforms.
async fn bulk(batch_bytes: usize) {
    let (mut tx, mut rx, _connector, _acceptor) = connect().await;

    let push_batch = async |tx: &mut wit_bindgen::StreamWriter<u8>,
                            rx: &mut wit_bindgen::StreamReader<u8>| {
        let start = Instant::now();
        let chunks = batch_bytes / CHUNK;
        let write = async {
            for _ in 0..chunks {
                let leftover = tx.write_all(vec![0xa5u8; CHUNK]).await;
                assert!(leftover.is_empty(), "cleartext stream rejected a chunk");
            }
        };
        let read = async {
            let mut received = 0usize;
            while received < chunks * CHUNK {
                let (status, chunk) = rx.read(Vec::with_capacity(CHUNK)).await;
                received += chunk.len();
                assert!(
                    !matches!(status, StreamResult::Dropped | StreamResult::Cancelled)
                        || received >= chunks * CHUNK,
                    "stream ended early",
                );
            }
        };
        join!(write, read);
        (chunks * CHUNK) as f64 / start.elapsed().as_secs_f64() / 1e6
    };

    // Warmup, then measured batches.
    push_batch(&mut tx, &mut rx).await;
    let mut rates = Vec::with_capacity(BATCHES);
    for _ in 0..BATCHES {
        rates.push(push_batch(&mut tx, &mut rx).await);
    }
    median_row("component-bulk", "negotiated", "MB/s", rates);
}

/// Full handshakes through the composed component, fresh resources per
/// connection.
async fn handshake(batch: usize) {
    let run_batch = async || {
        let start = Instant::now();
        for _ in 0..batch {
            let _ = connect().await;
        }
        batch as f64 / start.elapsed().as_secs_f64()
    };

    run_batch().await;
    let mut rates = Vec::with_capacity(BATCHES);
    for _ in 0..BATCHES {
        rates.push(run_batch().await);
    }
    median_row("component-handshake", "ed25519", "handshakes/s", rates);
}
