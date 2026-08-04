//! The connection pump: rustls in the middle, component-model streams at
//! the edges.
//!
//! Each connection runs three cooperative tasks sharing the rustls
//! connection state (single-threaded; borrows are never held across
//! await points):
//!
//! - the *reader* task moves transport bytes into rustls and decrypted
//!   application data out to the consumer;
//! - the *writer* task moves consumer application data into rustls and
//!   triggers `close_notify` when the consumer finishes writing;
//! - the *transmit* task serializes rustls's outgoing TLS records —
//!   produced by both other tasks — onto the ciphertext stream.
//!
//! The handshake methods (`connect`/`accept`) await a one-shot signal the
//! first two tasks raise when rustls leaves the handshaking state, or an
//! error if the connection dies first.

use std::cell::RefCell;
use std::io::{Read, Write};
use std::rc::Rc;

use futures::channel::{mpsc, oneshot};
use futures::StreamExt;
use wit_bindgen::{FutureReader, FutureWriter, StreamReader, StreamResult, StreamWriter};

use crate::component::exports::lann::tls::types::{ConnectionInfo, Error};
use crate::{wit_future, wit_stream, HandshakeOutcome, TlsError};

/// Stream-read hop size, both directions.
const CHUNK: usize = 16 * 1024;

/// Stream ends handed over by `send`/`receive` before the handshake call.
#[derive(Default)]
pub(crate) struct Wired {
    cleartext_in: Option<StreamReader<u8>>,
    ciphertext_out: Option<StreamWriter<u8>>,
    send_done: Option<FutureWriter<Result<(), Error>>>,
    ciphertext_in: Option<StreamReader<u8>>,
    cleartext_out: Option<StreamWriter<u8>>,
    recv_done: Option<FutureWriter<Result<(), Error>>>,
}

impl Wired {
    pub(crate) fn wire_send(
        &mut self,
        cleartext: StreamReader<u8>,
    ) -> (StreamReader<u8>, FutureReader<Result<(), Error>>) {
        let (ct_tx, ct_rx) = wit_stream::new();
        let (done_tx, done_rx) = wit_future::new(|| Ok(()));
        self.cleartext_in = Some(cleartext);
        self.ciphertext_out = Some(ct_tx);
        self.send_done = Some(done_tx);
        (ct_rx, done_rx)
    }

    pub(crate) fn wire_receive(
        &mut self,
        ciphertext: StreamReader<u8>,
    ) -> (StreamReader<u8>, FutureReader<Result<(), Error>>) {
        let (pt_tx, pt_rx) = wit_stream::new();
        let (done_tx, done_rx) = wit_future::new(|| Ok(()));
        self.ciphertext_in = Some(ciphertext);
        self.cleartext_out = Some(pt_tx);
        self.recv_done = Some(done_tx);
        (pt_rx, done_rx)
    }

    pub(crate) fn take_complete(&mut self) -> Option<CompleteWiring> {
        Some(CompleteWiring {
            cleartext_in: self.cleartext_in.take()?,
            ciphertext_out: self.ciphertext_out.take()?,
            send_done: self.send_done.take()?,
            ciphertext_in: self.ciphertext_in.take()?,
            cleartext_out: self.cleartext_out.take()?,
            recv_done: self.recv_done.take()?,
        })
    }
}

pub(crate) struct CompleteWiring {
    cleartext_in: StreamReader<u8>,
    ciphertext_out: StreamWriter<u8>,
    send_done: FutureWriter<Result<(), Error>>,
    ciphertext_in: StreamReader<u8>,
    cleartext_out: StreamWriter<u8>,
    recv_done: FutureWriter<Result<(), Error>>,
}

type HandshakeSender = oneshot::Sender<Result<HandshakeOutcome, String>>;

/// Signals handshake completion (or failure) to the pending
/// `connect`/`accept` call, exactly once.
#[derive(Clone)]
struct Handshake(Rc<RefCell<Option<HandshakeSender>>>);

impl Handshake {
    fn check(&self, conn: &mut rustls::Connection) {
        if conn.is_handshaking() {
            return;
        }
        if let Some(tx) = self.0.borrow_mut().take() {
            let outcome = HandshakeOutcome {
                alpn_protocol: conn.alpn_protocol().map(|p| p.to_vec()),
                server_name: match conn {
                    rustls::Connection::Server(server) => server.server_name().map(str::to_string),
                    rustls::Connection::Client(_) => None,
                },
            };
            let _ = tx.send(Ok(outcome));
        }
    }

    fn fail(&self, message: String) {
        if let Some(tx) = self.0.borrow_mut().take() {
            let _ = tx.send(Err(message));
        }
    }
}

type SharedConnection = Rc<RefCell<rustls::Connection>>;
type CiphertextSink = mpsc::UnboundedSender<Vec<u8>>;

/// Drains rustls's pending outgoing TLS records into the transmit queue.
fn drain_tls_writes(conn: &mut rustls::Connection, sink: &CiphertextSink) {
    while conn.wants_write() {
        let mut buf = Vec::with_capacity(CHUNK);
        match conn.write_tls(&mut buf) {
            Ok(0) => break,
            Ok(_) => {
                let _ = sink.unbounded_send(buf);
            }
            Err(_) => break,
        }
    }
}

/// Reads all currently-decryptable application data.
fn read_available_plaintext(conn: &mut rustls::Connection) -> (Vec<u8>, bool) {
    let mut plaintext = Vec::new();
    let mut clean_eof = false;
    let mut buf = [0u8; CHUNK];
    loop {
        match conn.reader().read(&mut buf) {
            Ok(0) => {
                clean_eof = true;
                break;
            }
            Ok(n) => plaintext.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Transport closed without close_notify; the caller
                // decides how to report it.
                break;
            }
            Err(_) => break,
        }
    }
    (plaintext, clean_eof)
}

/// Runs a connection over its wired streams; resolves at handshake
/// completion and leaves the data pumps running detached.
pub(crate) async fn run(
    conn: rustls::Connection,
    wiring: CompleteWiring,
) -> Result<ConnectionInfo, Error> {
    let conn: SharedConnection = Rc::new(RefCell::new(conn));
    let (ct_sink, ct_source) = mpsc::unbounded::<Vec<u8>>();
    let (hs_tx, hs_rx) = oneshot::channel();
    let handshake = Handshake(Rc::new(RefCell::new(Some(hs_tx))));

    // The client's first flight exists before any input arrives.
    drain_tls_writes(&mut conn.borrow_mut(), &ct_sink);

    wit_bindgen::spawn_local(reader_task(
        conn.clone(),
        wiring.ciphertext_in,
        wiring.cleartext_out,
        ct_sink.clone(),
        wiring.recv_done,
        handshake.clone(),
    ));
    wit_bindgen::spawn_local(writer_task(
        conn.clone(),
        wiring.cleartext_in,
        ct_sink,
        wiring.send_done,
        handshake.clone(),
    ));
    wit_bindgen::spawn_local(transmit_task(ct_source, wiring.ciphertext_out));

    match hs_rx.await {
        Ok(Ok(outcome)) => Ok(outcome.into()),
        Ok(Err(message)) => Err(TlsError::resource(message)),
        Err(_) => Err(TlsError::resource("connection closed during handshake")),
    }
}

/// Transport bytes → rustls → decrypted application data.
///
/// Terminal ordering is a contract: every stream end this direction owns
/// is released before the verdict is delivered. The verdict write is a
/// rendezvous with the consumer, and a consumer is entitled to read the
/// cleartext stream to its close before looking at the future.
async fn reader_task(
    conn: SharedConnection,
    mut ciphertext_in: StreamReader<u8>,
    mut cleartext_out: StreamWriter<u8>,
    ct_sink: CiphertextSink,
    recv_done: FutureWriter<Result<(), Error>>,
    handshake: Handshake,
) {
    let mut clean_close = false;
    let verdict = loop {
        let (status, buf) = ciphertext_in.read(Vec::with_capacity(CHUNK)).await;
        if !buf.is_empty() {
            let (plaintext, failed): (Vec<u8>, Option<String>) = {
                let mut conn = conn.borrow_mut();
                let mut cursor: &[u8] = &buf;
                let mut failure = None;
                while !cursor.is_empty() {
                    match conn.read_tls(&mut cursor) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(e) => {
                            failure = Some(format!("transport read failed: {e}"));
                            break;
                        }
                    }
                    match conn.process_new_packets() {
                        Ok(io_state) => {
                            drain_tls_writes(&mut conn, &ct_sink);
                            if io_state.peer_has_closed() {
                                clean_close = true;
                            }
                        }
                        Err(e) => {
                            // Flush the alert rustls queued for the peer.
                            drain_tls_writes(&mut conn, &ct_sink);
                            failure = Some(format!("TLS error: {e}"));
                            break;
                        }
                    }
                }
                handshake.check(&mut conn);
                let (plaintext, eof) = read_available_plaintext(&mut conn);
                clean_close |= eof;
                (plaintext, failure)
            };
            if !plaintext.is_empty() {
                let _ = cleartext_out.write_all(plaintext).await;
            }
            if let Some(message) = failed {
                handshake.fail(message.clone());
                break Err(TlsError::resource(message));
            }
            if clean_close {
                break Ok(());
            }
        }
        if matches!(status, StreamResult::Dropped | StreamResult::Cancelled) {
            if clean_close {
                break Ok(());
            }
            handshake.fail("transport closed during handshake".into());
            break Err(TlsError::resource(
                "transport closed without TLS close_notify (possible truncation)",
            ));
        }
    };
    drop(ciphertext_in);
    drop(cleartext_out);
    drop(ct_sink);
    let _ = recv_done.write(verdict).await;
}

/// Consumer application data → rustls → transmit queue.
///
/// Terminal ordering as in [`reader_task`]: the transmit-queue sink is
/// released before the verdict rendezvous, so `close_notify` and the
/// ciphertext stream's closure reach the transport regardless of when
/// (or whether) the consumer reads the future.
async fn writer_task(
    conn: SharedConnection,
    mut cleartext_in: StreamReader<u8>,
    ct_sink: CiphertextSink,
    send_done: FutureWriter<Result<(), Error>>,
    handshake: Handshake,
) {
    let verdict = loop {
        let (status, buf) = cleartext_in.read(Vec::with_capacity(CHUNK)).await;
        if !buf.is_empty() {
            let write_error = {
                let mut conn = conn.borrow_mut();
                match conn.writer().write_all(&buf) {
                    Ok(()) => {
                        drain_tls_writes(&mut conn, &ct_sink);
                        handshake.check(&mut conn);
                        None
                    }
                    Err(e) => Some(e),
                }
            };
            if let Some(e) = write_error {
                break Err(TlsError::resource(format!("write failed: {e}")));
            }
        }
        if matches!(status, StreamResult::Dropped | StreamResult::Cancelled) {
            {
                let mut conn = conn.borrow_mut();
                conn.send_close_notify();
                drain_tls_writes(&mut conn, &ct_sink);
            }
            break Ok(());
        }
    };
    drop(cleartext_in);
    drop(ct_sink);
    let _ = send_done.write(verdict).await;
}

/// Transmit queue → ciphertext stream, in order.
async fn transmit_task(
    mut ct_source: mpsc::UnboundedReceiver<Vec<u8>>,
    mut ciphertext_out: StreamWriter<u8>,
) {
    while let Some(bytes) = ct_source.next().await {
        let _ = ciphertext_out.write_all(bytes).await;
    }
    // Both producers are gone; dropping the writer closes the stream.
}
