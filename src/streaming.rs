// SPDX-License-Identifier: MIT
// Copyright (c) 2021-2026 Martyn P <martyn@datasync.dev>

//! Implements the TAK Protocol "Streaming Connection Protocol Negotiation" handshake
//! described in `takproto/README.md`, and the two per-connection publish loops that
//! result from it: plain Traditional Protocol XML, and binary TAK Protocol Streaming
//! framing.
//!
//! Note: this module only implements the streaming (TAK server) side of protocol
//! negotiation. The separate "Mesh Network Protocol Negotiation" rules (peer min/max
//! version tracking over multicast) are not implemented - multicast publishing always
//! sends TAK Protocol v1 payloads unconditionally.

use std::borrow::Cow;
use std::time::Duration;

use prost::Message as _;
use quick_xml::escape::escape;
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::Receiver;

use crate::{
    get_time, get_varint, handle_error, rpc_from_cot, CotSender, CursorOnTarget, PublishError,
    TCP_MAGIC,
};

/// How long to wait for the server to advertise TAK Protocol support (README step 3)
/// before giving up and staying in plain XML mode for the life of the connection. The
/// spec doesn't mandate a value for this side of the wait; real TAK servers typically
/// advertise within a second or two of the connection opening.
const ADVERTISEMENT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for the server's TakResponse after sending a TakRequest (README step
/// 6). The spec requires the client wait "at least one minute" before giving up.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(65);

/// Outcome of the negotiation handshake for a single connection
pub(crate) enum NegotiationOutcome {
    /// Server accepted the TAK Protocol upgrade (README step 7a) - switch to binary
    /// streaming framing
    Binary,
    /// Server never advertised support, advertised no version this crate implements, or
    /// denied the request (README step 7b) - stay on plain XML CoT for this connection
    PlainXml,
    /// The publisher was dropped (mpsc channel closed) during negotiation - shut down
    /// cleanly rather than treating this as a connection failure
    Shutdown,
}

/// The server's TakProtocolSupport advertisement (README step 3)
struct TakProtocolSupportInfo {
    protouid: String,
    versions: Vec<u32>,
}

enum AdvertisementResult {
    Found(TakProtocolSupportInfo),
    TimedOut,
    Shutdown,
}

/// Upper bound on how many bytes `XmlEventReader` will buffer while assembling a single
/// `<event>...</event>` document before giving up. Real CoT events are at most a few KiB;
/// this is generous headroom against a hostile or misbehaving peer that never sends the
/// closing token, which would otherwise grow the buffer (and the process's memory)
/// without bound.
const MAX_XML_EVENT_SIZE: usize = 1024 * 1024; // 1 MiB

/// Reads a byte stream one `<event>...</event>` document at a time, using the same
/// framing rule the README defines for the Traditional Protocol: search for the token
/// "</event>" and break apart immediately after it.
pub(crate) struct XmlEventReader<R> {
    reader: R,
    buffer: Vec<u8>,
}

impl<R: AsyncRead + Unpin> XmlEventReader<R> {
    pub(crate) fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: Vec::new(),
        }
    }

    /// Returns the next complete `<event>...</event>` document, or `Ok(None)` on a clean
    /// connection close. Cancel safe: any bytes read before the returned future is
    /// dropped remain buffered in `self` for the next call to resume from.
    pub(crate) async fn next_event(&mut self) -> std::io::Result<Option<String>> {
        loop {
            if let Some(end) = find_event_end(&self.buffer) {
                let doc: Vec<u8> = self.buffer.drain(..end).collect();
                return Ok(Some(String::from_utf8_lossy(&doc).into_owned()));
            }

            if self.buffer.len() >= MAX_XML_EVENT_SIZE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "XML event exceeded the {MAX_XML_EVENT_SIZE} byte limit without a closing </event> token"
                    ),
                ));
            }

            let mut chunk = [0u8; 4096];
            let n = self.reader.read(&mut chunk).await?;
            if n == 0 {
                return Ok(None);
            }
            self.buffer.extend_from_slice(&chunk[..n]);
        }
    }

    /// Returns the inner reader plus any unconsumed leftover bytes (bytes already read
    /// off the socket past the last complete `</event>`), for use when transitioning to
    /// binary framing so nothing already buffered is lost.
    pub(crate) fn into_parts(self) -> (R, Vec<u8>) {
        (self.reader, self.buffer)
    }
}

fn find_event_end(buffer: &[u8]) -> Option<usize> {
    const TOKEN: &[u8] = b"</event>";
    if buffer.len() < TOKEN.len() {
        return None;
    }
    buffer
        .windows(TOKEN.len())
        .position(|w| w == TOKEN)
        .map(|i| i + TOKEN.len())
}

/// Implements README steps 1-6 of "Streaming Connection Protocol Negotiation".
pub(crate) async fn negotiate_tak_protocol<R, W>(
    xml_reader: &mut XmlEventReader<R>,
    write_half: &mut W,
    receiver: &mut Receiver<CotSender>,
) -> Result<NegotiationOutcome, PublishError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let support = match wait_for_advertisement(xml_reader, write_half, receiver).await? {
        AdvertisementResult::Found(info) if info.versions.contains(&1) => info,
        AdvertisementResult::Found(_) | AdvertisementResult::TimedOut => {
            return Ok(NegotiationOutcome::PlainXml);
        }
        AdvertisementResult::Shutdown => return Ok(NegotiationOutcome::Shutdown),
    };

    // Step 5: request the upgrade, reusing the server-provided protouid (never minting
    // our own - see the correctness note on build_tak_request_xml).
    let request_xml = build_tak_request_xml(&support.protouid, 1);
    write_xml(write_half, &request_xml).await?;

    // Step 6: wait for the TakResponse. Per spec the client MUST NOT send additional CoT
    // XML while waiting, so any CoT messages that arrive during this (up to 65s) window
    // are buffered locally rather than written immediately or ignored outright - ignoring
    // the receiver entirely would mean a CotPublisher dropped during this window goes
    // unnoticed for up to the full timeout. Buffered messages are flushed, using whichever
    // framing the negotiation resolves to, the moment a response (or shutdown) is seen.
    let mut buffered: Vec<CotSender> = Vec::new();
    match tokio::time::timeout(
        RESPONSE_TIMEOUT,
        wait_for_response(xml_reader, receiver, &mut buffered),
    )
    .await
    {
        Ok(Ok(ResponseOutcome::Accepted)) => {
            flush_buffered_binary(write_half, buffered).await?;
            Ok(NegotiationOutcome::Binary)
        }
        Ok(Ok(ResponseOutcome::Denied)) => {
            flush_buffered_xml(write_half, buffered).await?; // step 7b
            Ok(NegotiationOutcome::PlainXml)
        }
        // All Senders were dropped while we were waiting - nothing left to negotiate for.
        // Any messages buffered above are dropped along with their response senders,
        // which is observable to callers still awaiting publish_checked() as a channel
        // closed error, consistent with the publisher having gone away.
        Ok(Ok(ResponseOutcome::Shutdown)) => Ok(NegotiationOutcome::Shutdown),
        Ok(Err(e)) => Err(PublishError::ConnectionError(format!(
            "TAK server connection lost while awaiting protocol response: {e}"
        ))),
        // Spec: "the client SHALL disconnect as the entire negotiation is in an
        // indeterminate state" if no response arrives in time.
        Err(_) => Err(PublishError::ConnectionError(
            "Timed out waiting for TAK server protocol response".into(),
        )),
    }
}

async fn wait_for_advertisement<R, W>(
    xml_reader: &mut XmlEventReader<R>,
    write_half: &mut W,
    receiver: &mut Receiver<CotSender>,
) -> Result<AdvertisementResult, PublishError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let deadline = tokio::time::sleep(ADVERTISEMENT_TIMEOUT);
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            // Deliberately not `biased` - a server flooding junk XML events must not be
            // able to starve the timeout or outgoing-send branches below.
            event = xml_reader.next_event() => {
                match event {
                    Ok(Some(xml)) => {
                        if let Some(info) = parse_tak_protocol_support_event(&xml) {
                            return Ok(AdvertisementResult::Found(info));
                        }
                        // Traditional CoT XML unrelated to negotiation - ignore and keep waiting
                    }
                    Ok(None) => {
                        return Err(PublishError::ConnectionError(
                            "TAK server connection closed during negotiation".into(),
                        ));
                    }
                    Err(e) => {
                        return Err(PublishError::ConnectionError(format!(
                            "TAK server connection lost during negotiation: {e}"
                        )));
                    }
                }
            }

            cot_msg = receiver.recv() => {
                // Steps 1-4 explicitly allow (and require) normal CoT XML exchange while
                // waiting for the server's advertisement.
                let Some((cot, response_sender)) = cot_msg else {
                    return Ok(AdvertisementResult::Shutdown);
                };
                let xml = cot_to_xml(&cot);
                match write_xml(write_half, &xml).await {
                    Ok(()) => {
                        if let Some(sender) = response_sender {
                            sender.send(Ok(())).ok();
                        }
                    }
                    Err(e) => {
                        if let Some(sender) = response_sender {
                            sender.send(Err(e)).ok();
                        }
                    }
                }
            }

            _ = &mut deadline => {
                return Ok(AdvertisementResult::TimedOut);
            }
        }
    }
}

/// Outcome of waiting for the server's TakResponse (README step 6).
enum ResponseOutcome {
    /// `status='true'` (README step 7a) - switch to binary streaming framing
    Accepted,
    /// `status='false'` (README step 7b) - stay on plain XML CoT
    Denied,
    /// The publisher was dropped (mpsc channel closed) while waiting
    Shutdown,
}

/// Waits for the server's TakResponse, servicing `receiver` in the meantime so a
/// CotPublisher drop is noticed promptly instead of only after the (up to 65s) response
/// timeout elapses. Per spec the client MUST NOT send additional CoT XML while waiting,
/// so any messages received are appended to `buffered` rather than written - the caller
/// flushes them once this resolves.
async fn wait_for_response<R: AsyncRead + Unpin>(
    xml_reader: &mut XmlEventReader<R>,
    receiver: &mut Receiver<CotSender>,
    buffered: &mut Vec<CotSender>,
) -> std::io::Result<ResponseOutcome> {
    loop {
        tokio::select! {
            // Deliberately not `biased` - a server flooding junk XML events must not be
            // able to starve the receiver branch below.
            event = xml_reader.next_event() => {
                match event? {
                    Some(xml) => {
                        if let Some(status) = parse_tak_response_event(&xml) {
                            return Ok(if status {
                                ResponseOutcome::Accepted
                            } else {
                                ResponseOutcome::Denied
                            });
                        }
                        // Not the response yet - the server MAY still send other
                        // traditional CoT while it prepares its reply; ignore and keep
                        // waiting.
                    }
                    None => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "connection closed while awaiting TAK protocol response",
                        ));
                    }
                }
            }

            cot_msg = receiver.recv() => {
                let Some(msg) = cot_msg else {
                    return Ok(ResponseOutcome::Shutdown);
                };
                buffered.push(msg);
            }
        }
    }
}

/// Flushes CoT messages buffered while awaiting the TakResponse (see `wait_for_response`)
/// as plain Traditional Protocol XML, for use when negotiation resolved to
/// `NegotiationOutcome::PlainXml`. Confirms each message to its `publish_checked()`
/// caller (if any) exactly once, in order, mirroring the write/confirm pairing in
/// `run_plain_xml_publish_loop`.
async fn flush_buffered_xml<W: AsyncWrite + Unpin>(
    write_half: &mut W,
    buffered: Vec<CotSender>,
) -> Result<(), PublishError> {
    for (cot, response_sender) in buffered {
        let xml = cot_to_xml(&cot);
        let result = write_xml(write_half, &xml).await;
        if let Some(sender) = response_sender {
            sender.send(result.clone()).ok();
        }
        result?;
    }
    Ok(())
}

/// Flushes CoT messages buffered while awaiting the TakResponse (see `wait_for_response`)
/// as binary TAK Protocol Streaming frames, for use when negotiation resolved to
/// `NegotiationOutcome::Binary`. Confirms each message to its `publish_checked()` caller
/// (if any) exactly once, in order, mirroring the encode/write/confirm pairing in
/// `run_binary_publish_loop`.
async fn flush_buffered_binary<W: AsyncWrite + Unpin>(
    write_half: &mut W,
    buffered: Vec<CotSender>,
) -> Result<(), PublishError> {
    for (cot, response_sender) in buffered {
        let message = rpc_from_cot(&cot);
        let mut message_buffer = Vec::with_capacity(message.encoded_len());
        let conversion_result = message
            .encode(&mut message_buffer)
            .map_err(|e| {
                std::io::Error::other(format!("Failed encoding COT message to protobuf: {e}"))
            })
            .inspect_err(|e| handle_error(e.to_string().as_str()));

        // Ignore this message if we can't encode it - not a connection failure
        if let Err(e) = conversion_result {
            if let Some(sender) = response_sender {
                sender
                    .send(Err(PublishError::SendError(e.to_string())))
                    .ok();
            }
            continue;
        }

        let result = write_binary_frame(write_half, &message_buffer).await;
        if let Some(sender) = response_sender {
            sender.send(result.clone()).ok();
        }
        result?;
    }
    Ok(())
}

/// Runs the publish loop for a connection that stayed on (or fell back to) plain
/// Traditional Protocol XML for its entire lifetime.
pub(crate) async fn run_plain_xml_publish_loop<R, W>(
    mut xml_reader: XmlEventReader<R>,
    mut write_half: W,
    receiver: &mut Receiver<CotSender>,
) -> Result<(), PublishError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            // Deliberately not `biased` - a server flooding junk XML events must not be
            // able to starve the outgoing-send branch below.
            event = xml_reader.next_event() => {
                match event {
                    // Discarded - this crate has no public API to surface incoming CoT to
                    // callers. Still read so the socket doesn't back up and disconnects
                    // are noticed promptly.
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        return Err(PublishError::ConnectionError(
                            "TAK server connection closed".into(),
                        ));
                    }
                    Err(e) => {
                        return Err(PublishError::ConnectionError(format!(
                            "TAK server connection lost: {e}"
                        )));
                    }
                }
            }

            cot_msg = receiver.recv() => {
                let Some((cot, response_sender)) = cot_msg else {
                    return Ok(());
                };
                let xml = cot_to_xml(&cot);
                match write_xml(&mut write_half, &xml).await {
                    Ok(()) => {
                        if let Some(sender) = response_sender {
                            sender.send(Ok(())).ok();
                        }
                    }
                    Err(e) => {
                        if let Some(sender) = response_sender {
                            sender.send(Err(e.clone())).ok();
                        }
                        return Err(e);
                    }
                }
            }
        }
    }
}

/// Runs the publish loop for a connection that upgraded to binary TAK Protocol Streaming
/// framing. A background task owns the read half and watches for the connection dying;
/// decoupling the read from `select!` avoids the cancel-safety pitfalls of reading a
/// length-delimited binary frame piecemeal inside a loop that gets re-polled from scratch
/// each iteration.
pub(crate) async fn run_binary_publish_loop<R, W>(
    read_half: R,
    leftover: Vec<u8>,
    mut write_half: W,
    receiver: &mut Receiver<CotSender>,
) -> Result<(), PublishError>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
{
    // `_reader_task` is only held for its Drop side effect: aborting the background
    // reader task (and releasing the socket read half it owns) the moment this function
    // returns, on any exit path below, instead of leaving it detached indefinitely.
    let (_reader_task, mut death_rx) = spawn_binary_reader(read_half, leftover);

    loop {
        tokio::select! {
            biased;

            death = &mut death_rx => {
                let reason = death
                    .map(|e| e.to_string())
                    .unwrap_or_else(|_| "reader task ended unexpectedly".into());
                return Err(PublishError::ConnectionError(format!(
                    "TAK server connection lost: {reason}"
                )));
            }

            cot_msg = receiver.recv() => {
                let Some((cot, response_sender)) = cot_msg else {
                    return Ok(());
                };

                let message = rpc_from_cot(&cot);
                let mut message_buffer = Vec::with_capacity(message.encoded_len());
                let conversion_result = message
                    .encode(&mut message_buffer)
                    .map_err(|e| {
                        std::io::Error::other(format!("Failed encoding COT message to protobuf: {e}"))
                    })
                    .inspect_err(|e| handle_error(e.to_string().as_str()));

                // Ignore this message if we can't encode it - not a connection failure
                if let Err(e) = conversion_result {
                    if let Some(sender) = response_sender {
                        sender.send(Err(PublishError::SendError(e.to_string()))).ok();
                    }
                    continue;
                }

                match write_binary_frame(&mut write_half, &message_buffer).await {
                    Ok(()) => {
                        if let Some(sender) = response_sender {
                            sender.send(Ok(())).ok();
                        }
                    }
                    Err(e) => {
                        if let Some(sender) = response_sender {
                            sender.send(Err(e.clone())).ok();
                        }
                        return Err(e);
                    }
                }
            }
        }
    }
}

/// Aborts the wrapped `JoinHandle` when dropped. Used to tie the background binary-frame
/// reader task's lifetime to that of `run_binary_publish_loop`, so the task (and the
/// socket read half it owns) can't outlive the loop that spawned it.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn spawn_binary_reader<R>(
    read_half: R,
    leftover: Vec<u8>,
) -> (AbortOnDrop, tokio::sync::oneshot::Receiver<std::io::Error>)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    // `leftover` holds bytes already read off the socket during XML negotiation (the
    // start of the binary frame stream) - it must be drained before anything further is
    // read from `read_half`, or those bytes are lost.
    let handle = tokio::spawn(async move {
        let mut reader = std::io::Cursor::new(leftover).chain(read_half);
        loop {
            if let Err(e) = read_one_binary_frame(&mut reader).await {
                let _ = tx.send(e);
                return;
            }
        }
    });
    (AbortOnDrop(handle), rx)
}

/// Reads and discards one TAK Protocol Streaming frame (magic byte + varint length +
/// payload). There is no public API in this crate to route decoded incoming CotEvents
/// anywhere, so payloads are only read far enough to detect connection loss/desync.
async fn read_one_binary_frame<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<()> {
    let magic = reader.read_u8().await?;
    if magic != TCP_MAGIC[0] {
        return Err(std::io::Error::other(
            "Unexpected byte on TAK protocol stream (expected magic byte)",
        ));
    }

    let mut remaining = read_varint_u32(reader).await? as usize;
    let mut discard = [0u8; 4096];
    while remaining > 0 {
        let n = remaining.min(discard.len());
        reader.read_exact(&mut discard[..n]).await?;
        remaining -= n;
    }
    Ok(())
}

/// Reads an unsigned varint per "TAK Protocol Varint Encoding" in the README.
async fn read_varint_u32<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<u32> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    loop {
        let byte = reader.read_u8().await?;
        let low_bits = (byte & 0x7f) as u32;
        // A u32 has exactly 4 bits of room left once 28 bits (4 continuation bytes) are
        // already used - the 5th byte contributing anything above that would otherwise be
        // silently shifted out of range rather than reported as an error.
        if shift == 28 && low_bits > 0x0f {
            return Err(std::io::Error::other(
                "Varint value exceeds u32 range (overlong encoding)",
            ));
        }
        result |= low_bits << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 32 {
            return Err(std::io::Error::other("Varint length too large"));
        }
    }
}

async fn write_binary_frame<W: AsyncWrite + Unpin>(
    write_half: &mut W,
    message_buffer: &[u8],
) -> Result<(), PublishError> {
    write_half.write_all(&TCP_MAGIC).await.map_err(|e| {
        PublishError::SendError(format!("Failed to send COT message magic byte: {e}"))
    })?;
    write_half
        .write_all(&get_varint(message_buffer.len() as u32))
        .await
        .map_err(|e| PublishError::SendError(format!("Failed to send COT message size: {e}")))?;
    write_half
        .write_all(message_buffer)
        .await
        .map_err(|e| PublishError::SendError(format!("Failed to send COT message data: {e}")))?;
    write_half
        .flush()
        .await
        .map_err(|e| PublishError::SendError(format!("Failed to flush output buffer: {e}")))?;
    Ok(())
}

async fn write_xml<W: AsyncWrite + Unpin>(
    write_half: &mut W,
    xml: &str,
) -> Result<(), PublishError> {
    write_half
        .write_all(xml.as_bytes())
        .await
        .map_err(|e| PublishError::SendError(format!("Failed to send CoT XML message: {e}")))?;
    write_half
        .flush()
        .await
        .map_err(|e| PublishError::SendError(format!("Failed to flush output buffer: {e}")))?;
    Ok(())
}

fn esc(s: &str) -> Cow<'_, str> {
    escape(s)
}

/// Builds a Traditional Protocol CoT XML document for a `CursorOnTarget`, per the
/// README's "Traditional Protocol" framing rule: prefaced by an `<?xml ...?>` header,
/// followed by a newline, followed by the complete `<event>`, with no trailing newline
/// (the next message must start immediately with its own `<?xml ...?>` header).
pub(crate) fn cot_to_xml(cot: &CursorOnTarget) -> String {
    let now = get_time();
    let send_time = format_cot_time(now);
    let stale_time = format_cot_time(now + cot.stale_time_ms);

    let (lat, lon, hae, ce, le) = cot
        .position
        .as_ref()
        .map(|p| (p.lat, p.lng, p.hae, p.ce, p.le))
        .unwrap_or((0.0, 0.0, 0.0, 9999999.0, 9999999.0));

    let mut detail = String::new();
    if let Some(contact) = &cot.contact {
        detail.push_str(&format!(
            "<contact callsign='{}' endpoint='{}'/>",
            esc(&contact.callsign),
            esc(&contact.endpoint)
        ));
    }
    if let Some(pl) = &cot.precision_location {
        detail.push_str(&format!(
            "<precisionlocation geopointsrc='{}' altsrc='{}'/>",
            esc(&pl.geopointsrc),
            esc(&pl.altsrc)
        ));
    }
    if let Some(xml_detail) = &cot.xml_detail {
        // Already-serialized XML fragment supplied by the caller - embedded verbatim.
        detail.push_str(xml_detail);
    }

    let mut attrs = String::new();
    if !cot.access.is_empty() {
        attrs.push_str(&format!(" access='{}'", esc(&cot.access)));
    }
    if !cot.qos.is_empty() {
        attrs.push_str(&format!(" qos='{}'", esc(&cot.qos)));
    }
    if !cot.opex.is_empty() {
        attrs.push_str(&format!(" opex='{}'", esc(&cot.opex)));
    }

    format!(
        "<?xml version='1.0' encoding='UTF-8'?>\n\
         <event version='2.0' uid='{uid}' type='{ty}' time='{send_time}' start='{send_time}' stale='{stale_time}' how='{how}'{attrs}>\
         <point lat='{lat}' lon='{lon}' hae='{hae}' ce='{ce}' le='{le}'/>\
         <detail>{detail}</detail>\
         </event>",
        uid = esc(&cot.uid),
        ty = esc(&cot.r#type),
        how = esc(&cot.how),
    )
}

/// Builds the `t-x-takp-q` (TakRequest) control event for README negotiation step 5.
///
/// Correctness note: per the spec, "protouid... The server generates this [...] the
/// client re-uses it" - the client must never mint its own UID here, only reuse whatever
/// `uid` the server supplied in its `t-x-takp-v` advertisement (see
/// `parse_tak_protocol_support_event`).
pub(crate) fn build_tak_request_xml(protouid: &str, version: u32) -> String {
    let t = format_cot_time(get_time());
    format!(
        "<?xml version='1.0' encoding='UTF-8'?>\n\
         <event version='2.0' uid='{uid}' type='t-x-takp-q' time='{t}' start='{t}' stale='{t}' how='m-g'>\
         <point lat='0.0' lon='0.0' hae='0.0' ce='9999999.0' le='9999999.0'/>\
         <detail><TakControl><TakRequest version='{version}'/></TakControl></detail>\
         </event>",
        uid = esc(protouid),
    )
}

/// Converts ms-since-epoch into the ISO-8601 timestamp format used by the CoT schema
/// (e.g. "2026-07-13T12:34:56.789Z").
fn format_cot_time(epoch_ms: u64) -> String {
    let secs = epoch_ms / 1000;
    let ms = epoch_ms % 1000;
    let days = (secs / 86400) as i64;
    let secs_of_day = secs % 86400;
    let hour = secs_of_day / 3600;
    let min = (secs_of_day % 3600) / 60;
    let sec = secs_of_day % 60;

    let (y, m, d) = civil_from_days(days);

    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}.{ms:03}Z")
}

/// Howard Hinnant's `civil_from_days` algorithm: converts a day count (days since
/// 1970-01-01) into a proleptic-Gregorian (year, month, day) civil date. Avoids pulling
/// in a date/time crate for this one conversion.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn attr_value(e: &BytesStart, key: &[u8]) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| a.key.as_ref() == key)
        .and_then(|a| {
            a.normalized_value(XmlVersion::Implicit1_0)
                .ok()
                .map(|c| c.into_owned())
        })
}

/// Parses a `t-x-takp-v` (TakProtocolSupport) advertisement event (README step 3).
/// Returns `None` for anything else, or for a malformed/non-conforming advertisement
/// (missing uid, or no advertised versions) - callers treat that the same as "no
/// advertisement seen" rather than inventing values to fill the gap.
fn parse_tak_protocol_support_event(xml: &str) -> Option<TakProtocolSupportInfo> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut protouid: Option<String> = None;
    let mut versions = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => match e.name().as_ref() {
                b"event" => {
                    if attr_value(&e, b"type").as_deref() != Some("t-x-takp-v") {
                        return None;
                    }
                    protouid = attr_value(&e, b"uid");
                }
                b"TakProtocolSupport" => {
                    if let Some(v) = attr_value(&e, b"version").and_then(|v| v.parse::<u32>().ok())
                    {
                        versions.push(v);
                    }
                }
                _ => {}
            },
            Ok(_) => {}
            Err(_) => return None,
        }
    }

    let protouid = protouid.filter(|u| !u.is_empty())?;
    if versions.is_empty() {
        return None;
    }
    Some(TakProtocolSupportInfo { protouid, versions })
}

/// Parses a `t-x-takp-r` (TakResponse) event (README step 6). Returns `None` for
/// anything else or a malformed response.
fn parse_tak_response_event(xml: &str) -> Option<bool> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut is_response_event = false;
    let mut status = None;

    loop {
        match reader.read_event() {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => match e.name().as_ref() {
                b"event" => {
                    if attr_value(&e, b"type").as_deref() != Some("t-x-takp-r") {
                        return None;
                    }
                    is_response_event = true;
                }
                b"TakResponse" => {
                    status = attr_value(&e, b"status").map(|s| s == "true");
                }
                _ => {}
            },
            Ok(_) => {}
            Err(_) => return None,
        }
    }

    if !is_response_event {
        return None;
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_cot_time_epoch() {
        assert_eq!(format_cot_time(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn format_cot_time_with_ms() {
        assert_eq!(format_cot_time(3_661_123), "1970-01-01T01:01:01.123Z");
    }

    #[test]
    fn format_cot_time_leap_day() {
        assert_eq!(
            format_cot_time(1_709_164_800_000),
            "2024-02-29T00:00:00.000Z"
        );
    }

    #[tokio::test]
    async fn varint_round_trips_with_encoder() {
        for value in [0u32, 1, 127, 128, 300, 16384, u32::MAX] {
            let encoded = get_varint(value);
            let mut cursor = std::io::Cursor::new(encoded);
            let decoded = read_varint_u32(&mut cursor).await.unwrap();
            assert_eq!(decoded, value);
        }
    }

    #[tokio::test]
    async fn varint_rejects_overlong_final_byte() {
        // Four continuation bytes (shift reaches 28) followed by a final byte of 0x1f:
        // the low 4 bits (0xf) would fit in the remaining room of a u32, but the 5th bit
        // (0x10) would silently be shifted out rather than reported as an error.
        let bytes = [0xff, 0xff, 0xff, 0xff, 0x1f];
        let mut cursor = std::io::Cursor::new(bytes);
        let err = read_varint_u32(&mut cursor).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
    }

    #[tokio::test]
    async fn xml_event_reader_splits_on_event_boundary() {
        let (mut client, server) = tokio::io::duplex(64);
        let mut reader = XmlEventReader::new(server);

        tokio::spawn(async move {
            client
                .write_all(b"<event a='1'></event><eve")
                .await
                .unwrap();
            client.write_all(b"nt b='2'></event>").await.unwrap();
        });

        let first = reader.next_event().await.unwrap().unwrap();
        assert_eq!(first, "<event a='1'></event>");
        let second = reader.next_event().await.unwrap().unwrap();
        assert_eq!(second, "<event b='2'></event>");
    }

    #[tokio::test]
    async fn xml_event_reader_returns_none_on_clean_close() {
        let (client, server) = tokio::io::duplex(64);
        drop(client);
        let mut reader = XmlEventReader::new(server);
        assert!(reader.next_event().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn xml_event_reader_errors_when_no_closing_tag_within_max_size() {
        // A hostile/broken peer that never sends "</event>" must not be able to grow
        // XmlEventReader's buffer without bound.
        let (mut client, server) = tokio::io::duplex(128 * 1024);
        let mut reader = XmlEventReader::new(server);

        tokio::spawn(async move {
            let chunk = vec![b'a'; 64 * 1024];
            // Comfortably more than MAX_XML_EVENT_SIZE, still with no "</event>" token.
            for _ in 0..20 {
                if client.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });

        let err = reader.next_event().await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    // Sample copied verbatim from takproto/README.md (whitespace added there for
    // readability; parsing must be indifferent to whitespace/formatting).
    const SUPPORT_EVENT: &str = r"<event version='2.0' uid='protouid' type='t-x-takp-v' time='TIME' start='TIME' stale='TIME' how='m-g'>
  <point lat='0.0' lon='0.0' hae='0.0' ce='999999' le='999999'/>
  <detail>
    <TakControl>
      <TakProtocolSupport version='1'>
        <DetailExt id='extId' supportsAll='true'/>
      </TakProtocolSupport>
    </TakControl>
  </detail>
</event>";

    const RESPONSE_EVENT_TRUE: &str = r"<event version='2.0' uid='protouid' type='t-x-takp-r' time='TIME' start='TIME' stale='TIME' how='m-g'>
  <point lat='0.0' lon='0.0' hae='0.0' ce='999999' le='999999'/>
  <detail>
    <TakControl>
      <TakResponse status='true'/>
    </TakControl>
  </detail>
</event>";

    #[test]
    fn parses_tak_protocol_support_event() {
        let info = parse_tak_protocol_support_event(SUPPORT_EVENT).unwrap();
        assert_eq!(info.protouid, "protouid");
        assert_eq!(info.versions, vec![1]);
    }

    #[test]
    fn parses_tak_response_event() {
        assert_eq!(parse_tak_response_event(RESPONSE_EVENT_TRUE), Some(true));
    }

    #[test]
    fn unrelated_event_is_not_a_protocol_message() {
        let xml = "<event version='2.0' uid='x' type='a-f-G-U' time='TIME' start='TIME' stale='TIME' how='m-g'><point lat='0.0' lon='0.0' hae='0.0' ce='999999' le='999999'/></event>";
        assert!(parse_tak_protocol_support_event(xml).is_none());
        assert!(parse_tak_response_event(xml).is_none());
    }

    #[test]
    fn cot_to_xml_has_correct_header_and_no_trailing_newline() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let mut cot = CursorOnTarget::new("test-uid", "a-f-G-U", tx);
        cot.set_contact(Some("A & B"), Some("192.168.1.1:4242"));

        let xml = cot_to_xml(&cot);
        assert!(xml.starts_with("<?xml version='1.0' encoding='UTF-8'?>\n<event"));
        assert!(xml.ends_with("</event>"));
        assert!(!xml.ends_with("</event>\n"));

        // Round-trip through quick-xml to confirm the whole document still parses
        // (i.e. the callsign was escaped, not injected as raw markup) and that the
        // escaping happened the way we expect.
        let mut reader = Reader::from_str(&xml);
        while reader.read_event().unwrap() != Event::Eof {}
        assert!(xml.contains("A &amp; B"));
    }

    #[test]
    fn build_tak_request_xml_reuses_protouid_and_has_no_trailing_newline() {
        let xml = build_tak_request_xml("server-assigned-uid", 1);
        assert!(xml.starts_with("<?xml version='1.0' encoding='UTF-8'?>\n<event"));
        assert!(xml.contains("uid='server-assigned-uid'"));
        assert!(xml.contains("type='t-x-takp-q'"));
        assert!(xml.contains("<TakRequest version='1'/>"));
        assert!(!xml.ends_with('\n'));
    }
}
