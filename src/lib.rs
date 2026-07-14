// SPDX-License-Identifier: MIT
// Copyright (c) 2021-2026 Martyn P <martyn@datasync.dev>

//! This crate provides an interface for publishing Cursor on Target (COT) messages
//! to multicast addresses or TAK servers over TCP/TLS.
//!
//! There are two features available:
//!
//! * `blocking` - Provides a blocking interface for use in non-async applications
//! * `emit_errors` - Enables error logging using the `log` crate
//!
//! The blocking implementation runs a Tokio runtime in a separate thread to handle
//! async operations.
//!
//! The emit_errors feature allows the library to log errors using the `log` crate.
//! This is disabled by default to avoid unnecessary dependencies in applications.
//!
//! # Examples
//!
//! ## Async multicast
//!
//! ```no_run
//! use cot_publisher::CotPublisher;
//!
//! async fn example() {
//!     let publisher = CotPublisher::new_multicast("239.2.3.1".parse().unwrap(), 6969);
//!     let mut cot = publisher.create_cot("unique-uid", "a-f-G-U").unwrap();
//!     cot.set_position(51.5074, -0.1278);
//!     cot.set_contact(Some("CALLSIGN"), None);
//!     cot.publish().await.unwrap();
//! }
//! ```
//!
//! ## Blocking multicast
//!
//! Requires the `blocking` feature.
//!
//! ```no_run
//! # #[cfg(feature = "blocking")]
//! # {
//! use cot_publisher::blocking::CotPublisher;
//!
//! let publisher = CotPublisher::new_multicast("239.2.3.1".parse().unwrap(), 6969);
//! let mut cot = publisher.create_cot("unique-uid", "a-f-G-U").unwrap();
//! cot.set_position(51.5074, -0.1278);
//! cot.set_contact(Some("CALLSIGN"), None);
//! cot.blocking_publish().unwrap();
//! # }
//! ```

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use prost::Message;
use url::Url;
use varint_rs::VarintWriter;

#[cfg(feature = "blocking")]
pub mod blocking;
mod connection;
mod cursor_on_target;
mod keys;
mod streaming;

// Re-export modules for library users
pub use crate::connection::TakServerSetting;
pub use cursor_on_target::*;
pub use keys::{Credentials, Source};

const UDP_MAGIC: [u8; 3] = [0xbf, 0x01, 0xbf]; // Magic bytes for UDP TAK_PROTO
const TCP_MAGIC: [u8; 1] = [0xbf]; // Magic byte for TCP TAK_PROTO
pub(crate) const BROADCAST_CHANNEL_SIZE: usize = 1000; // Size of the broadcast channel buffer

/// Errors that can occur during publishing
#[derive(Debug, Clone, thiserror::Error)]
pub enum PublishError {
    #[error("Error sending COT message: {0}")]
    SendError(String),
    #[error("Connection error: {0}")]
    ConnectionError(String),
}

/// Type alias for the complex channel sender type
pub(crate) type CotSender = (
    CursorOnTarget,
    Option<tokio::sync::oneshot::Sender<Result<(), PublishError>>>,
);

// Publishes COT messages to multicast or TCP targets
pub struct CotPublisher {
    broadcast_sender: Option<tokio::sync::mpsc::Sender<CotSender>>,
    publish_task: Option<tokio::task::JoinHandle<Result<(), PublishError>>>,
    // Tracks whether a live connection is currently established. Always true for
    // multicast (which is connectionless); for TAK server publishers this reflects
    // whether the task is mid-reconnect vs actively connected.
    connected: Arc<AtomicBool>,
}

/// Tak_proto definition build using build.rs stage
pub mod tak_proto {
    include!(concat!(
        env!("OUT_DIR"),
        "/atakmap.commoncommo.protobuf.v1.rs"
    ));
}

impl Drop for CotPublisher {
    fn drop(&mut self) {
        // Dropping the sender will close the channel and stop the task
        drop(self.broadcast_sender.take());
        if let Some(task) = self.publish_task.take() {
            task.abort();
        }
    }
}

impl CotPublisher {
    /// Create a new publisher using multicast
    ///
    /// # Arguments
    ///
    /// * `address` - IP Address destination for, usually 239.2.3.1
    /// * `port` - Port to address packets to, usually 6969
    ///
    pub fn new_multicast(address: IpAddr, port: u16) -> Self {
        CotPublisher::new_multicast_bind(address, port, IpAddr::from([0; 8]))
    }

    /// Create a new publisher using multicast with defined bind target, this can be used to
    /// attach the multicast server to a specific interface
    ///
    /// # Arguments
    ///
    /// * `address` - IP Address destination for, usually 239.2.3.1
    /// * `port` - Port to address packets to, usually 6969
    /// * `bind_address` - Local IP address for interface to bind to
    ///
    pub fn new_multicast_bind(address: IpAddr, port: u16, bind_address: IpAddr) -> Self {
        let (sender, receiver) = tokio::sync::mpsc::channel::<CotSender>(BROADCAST_CHANNEL_SIZE);
        Self {
            broadcast_sender: Some(sender),
            publish_task: Some(tokio::task::spawn(multicast_publisher_task(
                address,
                port,
                bind_address,
                receiver,
            ))),
            // Multicast is connectionless - always considered "connected" while the task runs
            connected: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Create a new publisher using multicast with defined bind target, this can be used to
    /// attach the multicast server to a specific interface.
    ///
    /// This version allows customization of the broadcast channel capacity.
    ///
    /// # Arguments
    ///
    /// * `address` - IP Address destination for, usually 239.2.3.1
    /// * `port` - Port to address packets to, usually 6969
    /// * `bind_address` - Local IP address for interface to bind to
    /// * `channel_capacity` - Size of the broadcast channel buffer
    ///
    pub fn new_multicast_bind_custom_channel_capacity(
        address: IpAddr,
        port: u16,
        bind_address: IpAddr,
        channel_capacity: usize,
    ) -> Self {
        let (sender, receiver) = tokio::sync::mpsc::channel::<CotSender>(channel_capacity);
        Self {
            broadcast_sender: Some(sender),
            publish_task: Some(tokio::task::spawn(multicast_publisher_task(
                address,
                port,
                bind_address,
                receiver,
            ))),
            // Multicast is connectionless - always considered "connected" while the task runs
            connected: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Create a new publisher using TAK server over TCP/TLS
    ///
    /// # Arguments
    ///
    /// * `url` - URL of the TAK server, e.g. takserver.example.com:8080
    /// * `settings` - Settings for the TAK server connection, including credentials
    ///
    pub fn new_takserver(url: Url, settings: TakServerSetting<'static>) -> Self {
        let (sender, receiver) = tokio::sync::mpsc::channel::<CotSender>(BROADCAST_CHANNEL_SIZE);
        let connected = Arc::new(AtomicBool::new(false));
        Self {
            broadcast_sender: Some(sender),
            publish_task: Some(tokio::task::spawn(takserver_publisher_task_reconnect(
                url,
                settings,
                receiver,
                connected.clone(),
            ))),
            connected,
        }
    }

    /// Create a new publisher using TAK server over TCP/TLS
    ///
    /// # Arguments
    ///
    /// * `url` - URL of the TAK server, e.g. takserver.example.com:8080
    /// * `settings` - Settings for the TAK server connection, including credentials
    /// * `channel_capacity` - Size of the broadcast channel buffer
    ///
    pub fn new_takserver_custom_channel_capacity(
        url: Url,
        settings: TakServerSetting<'static>,
        channel_capacity: usize,
    ) -> Self {
        let (sender, receiver) = tokio::sync::mpsc::channel::<CotSender>(channel_capacity);
        let connected = Arc::new(AtomicBool::new(false));
        Self {
            broadcast_sender: Some(sender),
            publish_task: Some(tokio::task::spawn(takserver_publisher_task_reconnect(
                url,
                settings,
                receiver,
                connected.clone(),
            ))),
            connected,
        }
    }

    /// Check if the publisher is still connected and the task is running
    ///
    /// This should be called periodically to ensure the connection is still alive    
    ///
    pub async fn check_connected(&mut self) -> Result<(), PublishError> {
        // The task has already been 'reaped'
        if self.publish_task.is_none() {
            return Err(PublishError::ConnectionError(
                "Task has already completed".into(),
            ));
        }

        // Happy path - task is still running and actively connected
        #[allow(clippy::collapsible_if)] // For MSRV compatibility
        if let Some(task) = &self.publish_task {
            if !task.is_finished() {
                if self.connected.load(Ordering::Relaxed) {
                    return Ok(());
                }
                return Err(PublishError::ConnectionError(
                    "Reconnecting to TAK server".into(),
                ));
            }
        }

        // Task has finished - join it and surface whatever error it produced
        let task_result = self
            .publish_task
            .take()
            .expect("Task was None...")
            .await
            .map_err(|e| {
                PublishError::ConnectionError(format!("Failed joining publish task: {e}"))
            })?;

        match task_result {
            // The task should never return Ok(()) while this CotPublisher (and its
            // broadcast_sender) is still alive, but handle it defensively
            Ok(()) => Err(PublishError::ConnectionError(
                "Publish task stopped unexpectedly".into(),
            )),
            Err(e) => Err(e),
        }
    }

    /// Create a new CursorOnTarget for publishing
    ///
    /// # Arguments
    ///
    /// * `uid` - Unique identifier for the COT message
    /// * `r#type` - Type of the COT message
    ///
    pub fn create_cot<S: AsRef<str> + ToString>(
        &self,
        uid: S,
        r#type: S,
    ) -> Result<CursorOnTarget, std::io::Error> {
        if let Some(broadcast_sender) = &self.broadcast_sender {
            Ok(CursorOnTarget::new(uid, r#type, broadcast_sender.clone()))
        } else {
            Err(std::io::Error::other("Broadcast sender not available"))
        }
    }

    /// Copy an existing CursorOnTarget and attach the publisher's sender to it
    ///
    /// # Arguments
    ///
    /// * `cot` - Reference to the CursorOnTarget to copy
    ///
    pub fn copy_cot(&self, cot: &CursorOnTarget) -> Result<CursorOnTarget, std::io::Error> {
        if let Some(broadcast_sender) = &self.broadcast_sender {
            Ok(cot.clone().with_sender(broadcast_sender.clone()))
        } else {
            Err(std::io::Error::other("Broadcast sender not available"))
        }
    }
}

/// Source represents either a file path or a direct string input for PEM data
///
/// # Arguments
///
/// * `address` - IP Address destination for, usually 239.2.3.1
/// * `port` - Port to address packets to, usually 6969
/// * `bind_address` - Local IP address for interface to bind to
/// * `receiver` - Mpsc receiver for COT messages to publish
///
pub(crate) async fn multicast_publisher_task(
    address: IpAddr,
    port: u16,
    bind_address: IpAddr,
    mut receiver: tokio::sync::mpsc::Receiver<CotSender>,
) -> Result<(), PublishError> {
    let socket = tokio::net::UdpSocket::bind(format!("{bind_address}:0"))
        .await
        .map_err(|e| PublishError::SendError(format!("Binding to {bind_address}: {e}")))
        .inspect_err(|e| handle_error(e.to_string().as_str()))?;

    socket
        .set_broadcast(true)
        .map_err(|e| {
            PublishError::SendError(format!("Failed setting broadcast on {bind_address}: {e}"))
        })
        .inspect_err(|e| handle_error(e.to_string().as_str()))?;

    let destination = format!("{address}:{port}");

    // Loop exits (and the task returns) once every Sender has been dropped and recv() yields None
    while let Some((cot, response_sender)) = receiver.recv().await {
        let message = rpc_from_cot(&cot);

        let mut message_buffer = Vec::with_capacity(message.encoded_len());

        let conversion_result = message
            .encode(&mut message_buffer)
            .map_err(|e| {
                std::io::Error::other(format!("Failed encoding COT message to protobuf: {e}"))
            })
            .inspect_err(|e| {
                handle_error(e.to_string().as_str());
            });

        // Ignore this message if we can't encode it
        if let Err(e) = conversion_result {
            if let Some(sender) = response_sender {
                sender
                    .send(Err(PublishError::SendError(e.to_string())))
                    .ok();
            }
            continue;
        }

        // If this Socket IO fails, we assume the connection is broken and exit the task
        let mut buffer = UDP_MAGIC.to_vec(); // Magic
        buffer.append(&mut message_buffer);
        let result = socket
            .send_to(&buffer, &destination)
            .await
            .map_err(|e| std::io::Error::other(format!("Failed to send COT message data: {e}")))
            .inspect_err(|e| {
                handle_error(e.to_string().as_str());
            });

        if let Some(sender) = response_sender {
            match result {
                Ok(_) => {
                    sender.send(Ok(())).ok();
                }
                Err(e) => {
                    sender
                        .send(Err(PublishError::SendError(e.to_string())))
                        .ok();
                }
            }
        }
    }

    Ok(())
}

/// Wrapper to enable automatic reconnect logic for the task to manage connection to TAK server
/// and publish COT messages
///
/// # Arguments
///
/// * `url` - URL of the TAK server, e.g. takserver.example.com:8080
/// * `settings` - Settings for the TAK server connection, including credentials
/// * `receiver` - Mpsc receiver for COT messages to publish
/// * `connected` - Shared flag reflecting whether a connection is currently established
///
async fn takserver_publisher_task_reconnect(
    url: Url,
    settings: TakServerSetting<'static>,
    mut receiver: tokio::sync::mpsc::Receiver<CotSender>,
    connected: Arc<AtomicBool>,
) -> Result<(), PublishError> {
    loop {
        let mut task_result =
            takserver_publisher_task(url.clone(), &settings, &mut receiver, &connected).await;

        // Whether the task exited cleanly or with an error, no connection is live anymore
        connected.store(false, Ordering::Relaxed);

        // Ok(()) only happens once every Sender has been dropped and the channel has
        // closed for good - there is nothing left to reconnect for, so shut down.
        if task_result.is_ok() {
            return task_result;
        }

        if let Err(e) = &mut task_result {
            handle_error(e.to_string().as_str());

            if settings.auto_reconnect {
                #[cfg(feature = "emit_errors")]
                log::warn!(
                    "Connection to TAK Server lost, reconnecting in {} seconds...",
                    settings.reconnect_delay
                );
                tokio::time::sleep(std::time::Duration::from_secs(settings.reconnect_delay)).await;
            } else {
                return task_result;
            }
        }
    }
}

/// Task to manage connection to TAK server and publish COT messages
///
/// # Arguments
///
/// * `url` - URL of the TAK server, e.g. takserver.example.com:8080
/// * `settings` - Settings for the TAK server connection, including credentials
/// * `receiver` - Mpsc receiver for COT messages to publish
/// * `connected` - Shared flag set once the connection handshake completes successfully
///
pub(crate) async fn takserver_publisher_task(
    url: Url,
    settings: &TakServerSetting<'static>,
    receiver: &mut tokio::sync::mpsc::Receiver<CotSender>,
    connected: &Arc<AtomicBool>,
) -> Result<(), PublishError> {
    let stream = match connection::create_connection(url, settings).await {
        Ok(s) => s,
        Err(e) => {
            let message = format!("Failed to connect to TAK server: {e}");
            return Err(PublishError::ConnectionError(message));
        }
    };

    // The connection is live as soon as it's established - per the Traditional Protocol
    // and negotiation steps 1-4, plain CoT XML can be exchanged immediately, before any
    // TAK Protocol upgrade is negotiated (or even attempted).
    connected.store(true, Ordering::Relaxed);

    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut xml_reader = streaming::XmlEventReader::new(read_half);

    match streaming::negotiate_tak_protocol(&mut xml_reader, &mut write_half, receiver).await? {
        streaming::NegotiationOutcome::Shutdown => Ok(()),
        streaming::NegotiationOutcome::Binary => {
            let (read_half, leftover) = xml_reader.into_parts();
            streaming::run_binary_publish_loop(read_half, leftover, write_half, receiver).await
        }
        streaming::NegotiationOutcome::PlainXml => {
            streaming::run_plain_xml_publish_loop(xml_reader, write_half, receiver).await
        }
    }
}

/// Converts a CursorOnTarget struct to a tak_proto::TakMessage protobuf message
///
/// # Arguments
///
/// * `cot` - Reference to the CursorOnTarget struct to convert
///
fn rpc_from_cot(cot: &CursorOnTarget) -> tak_proto::TakMessage {
    // When no position has been set, lat/lng fall back to Null Island (0, 0) - but ce/le
    // must signal "unknown accuracy" (9999999, the CoT convention) rather than "perfect
    // fix", which is how TAK/ATAK would otherwise render a bare 0.0/0.0 position.
    let pos = cot.position.as_ref().unwrap_or(&Position {
        lat: 0.0,
        lng: 0.0,
        hae: 0.0,
        ce: 9999999.0,
        le: 9999999.0,
    });

    let time = get_time();
    tak_proto::TakMessage {
        tak_control: Some(tak_proto::TakControl {
            min_proto_version: 1, // Hard coded as this is the only version supported
            max_proto_version: 1, // Hard coded as this is the only version supported
            contact_uid: cot.uid.to_owned(),
            extension_ids: Vec::new(), // No extensions supported at this time
        }),
        cot_event: Some(tak_proto::CotEvent {
            r#type: cot.r#type.to_owned(),
            access: cot.access.to_owned(),
            qos: cot.qos.to_owned(),
            opex: cot.opex.to_owned(),
            uid: cot.uid.to_owned(),
            send_time: time,
            start_time: time,
            stale_time: time + cot.stale_time_ms,
            how: cot.how.to_owned(),
            lat: pos.lat,
            lon: pos.lng,
            hae: pos.hae,
            ce: pos.ce,
            le: pos.le,
            detail: Some(tak_proto::Detail {
                xml_detail: cot.xml_detail.to_owned().unwrap_or("".into()),
                contact: cot.contact.as_ref().map(|c| tak_proto::Contact {
                    endpoint: c.endpoint.to_owned(),
                    callsign: c.callsign.to_owned(),
                }),
                group: None,
                precision_location: cot.precision_location.as_ref().map(|p| {
                    tak_proto::PrecisionLocation {
                        geopointsrc: p.geopointsrc.to_owned(),
                        altsrc: p.altsrc.to_owned(),
                    }
                }),
                status: None,
                takv: None,
                track: None,
                extension_details: Vec::new(), // No extension details supported at this time
            }),
            caveat: "".into(),
            releasable_to: "".into(),
        }),
    }
}

/// Get the current time of the system in milliseconds since UNIX epoch
fn get_time() -> u64 {
    let now = std::time::SystemTime::now();
    let since_the_epoch = now
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards before the epoch"); // Should never happen
    since_the_epoch.as_millis() as u64
}

/// Converts a u32 size to a varint byte vector
fn get_varint(size: u32) -> Vec<u8> {
    // Message size
    let mut size_buffer: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(Vec::with_capacity(4));
    size_buffer
        .write_u32_varint(size)
        .expect("Failed to write varint"); // Should never happen
    size_buffer.into_inner()
}

#[cfg(feature = "emit_errors")]
/// Emit errors to log when feature is enabled
fn handle_error(e: &str) {
    log::error!("{}", e);
}

#[cfg(not(feature = "emit_errors"))]
/// Placeholder when error emission is disabled
fn handle_error(_: &str) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_from_cot_advertises_protocol_version_1() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let cot = CursorOnTarget::new("test-uid", "a-f-G-U", tx);

        let message = rpc_from_cot(&cot);
        let control = message.tak_control.expect("tak_control should be set");
        assert_eq!(control.min_proto_version, 1);
        assert_eq!(control.max_proto_version, 1);
    }

    #[test]
    fn rpc_from_cot_maps_position_and_accuracy_fields() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let mut cot = CursorOnTarget::new("test-uid", "a-f-G-U", tx);
        cot.position = Some(Position {
            lat: 51.5074,
            lng: -0.1278,
            hae: 42.0,
            ce: 5.0,
            le: 3.0,
        });

        let message = rpc_from_cot(&cot);
        let event = message.cot_event.expect("cot_event should be set");
        // Position uses `lng`, the wire format uses `lon` - make sure the rename lines up
        assert_eq!(event.lat, 51.5074);
        assert_eq!(event.lon, -0.1278);
        assert_eq!(event.hae, 42.0);
        assert_eq!(event.ce, 5.0);
        assert_eq!(event.le, 3.0);
    }

    #[test]
    fn rpc_from_cot_missing_position_reports_unknown_accuracy() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let cot = CursorOnTarget::new("test-uid", "a-f-G-U", tx);

        let message = rpc_from_cot(&cot);
        let event = message.cot_event.expect("cot_event should be set");
        // No position set: lat/lon fall back to Null Island, but ce/le must signal
        // "unknown accuracy" (9999999, the CoT convention) rather than "perfect fix"
        // (0.0), which is how TAK/ATAK would otherwise render the position.
        assert_eq!(event.lat, 0.0);
        assert_eq!(event.lon, 0.0);
        assert_eq!(event.ce, 9999999.0);
        assert_eq!(event.le, 9999999.0);
    }

    #[test]
    fn rpc_from_cot_computes_stale_time_from_stale_time_ms() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let mut cot = CursorOnTarget::new("test-uid", "a-f-G-U", tx);
        cot.stale_time_ms = 5_000;

        let message = rpc_from_cot(&cot);
        let event = message.cot_event.expect("cot_event should be set");
        assert_eq!(event.stale_time, event.send_time + 5_000);
        assert_eq!(event.stale_time, event.start_time + 5_000);
    }

    #[test]
    fn rpc_from_cot_maps_identity_and_contact_fields() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let mut cot = CursorOnTarget::new("test-uid", "a-f-G-U", tx);
        cot.how = "m-g".into();
        cot.set_contact(Some("CALLSIGN"), Some("192.168.1.1:4242:tcp"));

        let message = rpc_from_cot(&cot);
        let control = message.tak_control.expect("tak_control should be set");
        let event = message.cot_event.expect("cot_event should be set");
        let contact = event
            .detail
            .expect("detail should be set")
            .contact
            .expect("contact should be set");

        assert_eq!(control.contact_uid, "test-uid");
        assert_eq!(event.uid, "test-uid");
        assert_eq!(event.r#type, "a-f-G-U");
        assert_eq!(event.how, "m-g");
        assert_eq!(contact.callsign, "CALLSIGN");
        assert_eq!(contact.endpoint, "192.168.1.1:4242:tcp");
    }
}
