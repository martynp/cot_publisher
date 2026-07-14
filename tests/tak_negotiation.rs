// SPDX-License-Identifier: MIT
// Copyright (c) 2021-2025 Martyn P <martyn@datasync.dev>

//! Integration tests driving `CotPublisher::new_takserver` against a hand-speaking mock
//! TAK server, covering the "Streaming Connection Protocol Negotiation" state machine
//! described in `takproto/README.md` end to end through the crate's public API.

use std::time::Duration;

use cot_publisher::{CotPublisher, TakServerSetting};
use prost::Message as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

fn settings() -> TakServerSetting<'static> {
    TakServerSetting {
        tls: false,
        client_credentials: None,
        ignore_invalid: false,
        verify_hostname: true,
        auto_reconnect: false,
        reconnect_delay: 1,
    }
}

async fn listener_and_url() -> (TcpListener, Url) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = Url::parse(&format!("http://{addr}")).unwrap();
    (listener, url)
}

/// Reads bytes off `stream` until a `</event>` token is found, mirroring the Traditional
/// Protocol framing rule the crate itself uses.
async fn read_xml_event(stream: &mut TcpStream) -> String {
    const TOKEN: &[u8] = b"</event>";
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if buf.len() >= TOKEN.len() {
            if let Some(pos) = buf.windows(TOKEN.len()).position(|w| w == TOKEN) {
                return String::from_utf8_lossy(&buf[..pos + TOKEN.len()]).into_owned();
            }
        }
        let n = stream.read(&mut chunk).await.expect("read failed");
        assert!(n > 0, "connection closed before a full event was received");
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Reads one binary TAK Protocol Streaming frame (magic byte + varint length + payload)
/// and decodes it as a `TakMessage`.
async fn read_binary_frame(stream: &mut TcpStream) -> cot_publisher::tak_proto::TakMessage {
    let magic = stream.read_u8().await.unwrap();
    assert_eq!(magic, 0xbf, "expected TAK protocol magic byte");

    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    loop {
        let byte = stream.read_u8().await.unwrap();
        result |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }

    let mut payload = vec![0u8; result as usize];
    stream.read_exact(&mut payload).await.unwrap();
    cot_publisher::tak_proto::TakMessage::decode(payload.as_slice()).unwrap()
}

fn support_event_xml(protouid: &str) -> String {
    format!(
        "<?xml version='1.0' encoding='UTF-8'?>\n\
         <event version='2.0' uid='{protouid}' type='t-x-takp-v' time='2026-01-01T00:00:00.000Z' start='2026-01-01T00:00:00.000Z' stale='2026-01-01T00:00:00.000Z' how='m-g'>\
         <point lat='0.0' lon='0.0' hae='0.0' ce='999999' le='999999'/>\
         <detail><TakControl><TakProtocolSupport version='1'/></TakControl></detail>\
         </event>"
    )
}

fn response_event_xml(status: bool) -> String {
    format!(
        "<?xml version='1.0' encoding='UTF-8'?>\n\
         <event version='2.0' uid='resp-uid' type='t-x-takp-r' time='2026-01-01T00:00:00.000Z' start='2026-01-01T00:00:00.000Z' stale='2026-01-01T00:00:00.000Z' how='m-g'>\
         <point lat='0.0' lon='0.0' hae='0.0' ce='999999' le='999999'/>\
         <detail><TakControl><TakResponse status='{status}'/></TakControl></detail>\
         </event>"
    )
}

/// Server never advertises TAK Protocol support - the client should keep exchanging
/// plain CoT XML (README steps 1-4) rather than assuming binary framing.
#[tokio::test]
async fn no_advertisement_keeps_sending_plain_xml() {
    let (listener, url) = listener_and_url().await;

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let xml = read_xml_event(&mut socket).await;
        assert!(xml.starts_with("<?xml"));
        assert!(xml.contains("type='a-f-G-U'"));
        assert!(!xml.contains("t-x-takp"));
    });

    let publisher = CotPublisher::new_takserver(url, settings());

    // No sleep needed here - create_cot()/publish_checked() enqueue onto the publisher's
    // mpsc channel regardless of connection state, and publish_checked() itself already
    // awaits the write confirmation, so there's nothing left for a fixed delay to buy us.
    let cot = publisher.create_cot("no-ad-uid", "a-f-G-U").unwrap();
    cot.publish_checked().await.unwrap();

    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server task timed out")
        .unwrap();
}

/// Server advertises support, the client requests the upgrade reusing the advertised
/// protouid, and the server accepts - subsequent traffic must switch to binary TAK
/// Protocol Streaming framing (README steps 3, 5, 6, 7a).
#[tokio::test]
async fn accepted_negotiation_switches_to_binary_framing() {
    let (listener, url) = listener_and_url().await;
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();

        socket
            .write_all(support_event_xml("server-assigned-uid").as_bytes())
            .await
            .unwrap();

        let request = read_xml_event(&mut socket).await;
        assert!(request.contains("type='t-x-takp-q'"));
        assert!(request.contains("uid='server-assigned-uid'"));

        socket
            .write_all(response_event_xml(true).as_bytes())
            .await
            .unwrap();
        ready_tx.send(()).unwrap();

        let msg = read_binary_frame(&mut socket).await;
        let control = msg.tak_control.expect("tak_control should be set");
        assert_eq!(control.min_proto_version, 1);
        assert_eq!(control.max_proto_version, 1);
        let event = msg.cot_event.expect("cot_event should be set");
        assert_eq!(event.uid, "binary-uid");
    });

    let publisher = CotPublisher::new_takserver(url, settings());
    ready_rx.await.expect("server dropped ready signal");

    let cot = publisher.create_cot("binary-uid", "a-f-G-U").unwrap();
    cot.publish_checked().await.unwrap();

    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server task timed out")
        .unwrap();
}

/// Server pipelines its TakResponse XML and the leading byte of the very next binary
/// frame in a single write. TCP doesn't respect message boundaries, so the client's
/// XmlEventReader can (and here, reliably does) read past the "</event>" token in one
/// syscall, buffering that trailing byte as "leftover" ahead of switching to binary
/// framing. That leftover byte - the real start of the binary frame stream - must be
/// consumed before anything further is read from the live socket, or the reader
/// desyncs: it ends up treating a later, unrelated byte (here, the frame's length byte)
/// as if it were a fresh magic byte, which never matches and tears the connection down.
/// This test fails without the leftover-first fix in `spawn_binary_reader`.
#[tokio::test]
async fn pipelined_response_and_binary_frame_leftover_is_processed_first() {
    let (listener, url) = listener_and_url().await;
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();

        socket
            .write_all(support_event_xml("pipeline-uid").as_bytes())
            .await
            .unwrap();

        let request = read_xml_event(&mut socket).await;
        assert!(request.contains("type='t-x-takp-q'"));

        // A minimal well-formed binary frame representing the very first frame the
        // server sends once binary streaming begins.
        let heartbeat = cot_publisher::tak_proto::TakMessage {
            tak_control: Some(cot_publisher::tak_proto::TakControl {
                min_proto_version: 1,
                max_proto_version: 1,
                contact_uid: "server-uid".into(),
                extension_ids: vec![],
            }),
            cot_event: None,
        };
        let mut payload = Vec::new();
        heartbeat.encode(&mut payload).unwrap();
        assert!(
            payload.len() < 0x80,
            "test relies on the frame length encoding as a single varint byte"
        );

        // Write the TakResponse immediately followed by just the magic byte of the next
        // binary frame, in a single write - this is what makes the client's
        // XmlEventReader scoop up that extra byte past the "</event>" boundary as
        // "leftover" rather than it arriving later as a fresh read off the live socket.
        let mut first_write = response_event_xml(true).into_bytes();
        first_write.push(0xbf); // TAK protocol magic byte - start of the next frame
        socket.write_all(&first_write).await.unwrap();

        // Delay the rest of the frame so the magic byte above is guaranteed to already
        // be sitting in the client's leftover buffer - not still readable fresh off the
        // live socket - by the time binary framing begins.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut rest = vec![payload.len() as u8]; // single-byte varint length
        rest.extend_from_slice(&payload);
        socket.write_all(&rest).await.unwrap();
        ready_tx.send(()).unwrap();

        // If the leftover byte above was mishandled, the client will already have torn
        // the connection down with a framing-desync error and will never reach here.
        let msg = read_binary_frame(&mut socket).await;
        let event = msg.cot_event.expect("cot_event should be set");
        assert_eq!(event.uid, "pipeline-published-uid");
    });

    let mut publisher = CotPublisher::new_takserver(url, settings());
    ready_rx.await.expect("server dropped ready signal");

    tokio::time::timeout(Duration::from_secs(2), async {
        publisher
            .check_connected()
            .await
            .expect("connection should stay healthy after the pipelined leftover frame");
    })
    .await
    .expect("check_connected timed out");

    let cot = publisher
        .create_cot("pipeline-published-uid", "a-f-G-U")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), cot.publish_checked())
        .await
        .expect("publish_checked timed out")
        .expect("publish should succeed once the leftover frame is handled correctly");

    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server task timed out")
        .unwrap();
}

/// Server advertises support but denies the client's request - the connection must fall
/// back to plain XML CoT (README step 7b) rather than switching to binary framing or
/// erroring out.
#[tokio::test]
async fn denied_negotiation_falls_back_to_xml() {
    let (listener, url) = listener_and_url().await;
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();

        socket
            .write_all(support_event_xml("deny-uid").as_bytes())
            .await
            .unwrap();

        let request = read_xml_event(&mut socket).await;
        assert!(request.contains("type='t-x-takp-q'"));

        socket
            .write_all(response_event_xml(false).as_bytes())
            .await
            .unwrap();
        ready_tx.send(()).unwrap();

        let next = read_xml_event(&mut socket).await;
        assert!(next.contains("type='a-f-G-U'"));
        assert!(!next.contains("t-x-takp"));
    });

    let publisher = CotPublisher::new_takserver(url, settings());
    ready_rx.await.expect("server dropped ready signal");

    let cot = publisher.create_cot("xml-uid", "a-f-G-U").unwrap();
    cot.publish_checked().await.unwrap();

    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server task timed out")
        .unwrap();
}

/// Server closes the connection while the client is waiting for the TakResponse - this
/// must surface as a connection failure (not silently hang, and not be treated as
/// "denied"), since `auto_reconnect` is off the publish task should end in an error
/// state that `check_connected()` reports.
#[tokio::test]
async fn disconnect_during_response_wait_is_connection_loss() {
    let (listener, url) = listener_and_url().await;

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();

        socket
            .write_all(support_event_xml("drop-uid").as_bytes())
            .await
            .unwrap();

        let request = read_xml_event(&mut socket).await;
        assert!(request.contains("type='t-x-takp-q'"));

        // Close without ever sending a TakResponse
        drop(socket);
    });

    let mut publisher = CotPublisher::new_takserver(url, settings());

    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server task timed out")
        .unwrap();

    // Poll (bounded) until the client notices the closed connection and finishes the
    // task, instead of sleeping a fixed guess - avoids flaking under CI load while still
    // failing promptly if the disconnect is never detected.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if publisher.check_connected().await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("publisher did not report disconnect within timeout");
}
