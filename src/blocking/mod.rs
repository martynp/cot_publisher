// SPDX-License-Identifier: MIT
// Copyright (c) 2021-2026 Martyn P <martyn@datasync.dev>

//! Blocking Cursor on Target Publisher implementation

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use tokio::runtime::Runtime;
use url::Url;

use crate::{connection::TakServerSetting, CotSender, CursorOnTarget, PublishError};

/// Blocking version of CotPublisher that runs a Tokio runtime in a separate thread
pub struct CotPublisher {
    cot_sender: Option<tokio::sync::mpsc::Sender<CotSender>>,
    thread: Option<thread::JoinHandle<Result<(), PublishError>>>,
    // Tracks whether a live connection is currently established. Always true for
    // multicast (which is connectionless); for TAK server publishers this reflects
    // whether the task is mid-reconnect vs actively connected.
    connected: Arc<AtomicBool>,
}

impl Drop for CotPublisher {
    fn drop(&mut self) {
        // Dropping the sender closes the channel, letting the publisher task's
        // receive loop exit cleanly so the background thread can be joined below
        // instead of being left running.
        drop(self.cot_sender.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
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
        Self::new_multicast_bind(address, port, IpAddr::from([0; 8]))
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
        let (sender, receiver) =
            tokio::sync::mpsc::channel::<CotSender>(crate::BROADCAST_CHANNEL_SIZE);

        let thread_handle = thread::spawn(move || {
            let runtime = Runtime::new().expect("Failed to create Tokio runtime");

            runtime.block_on(crate::multicast_publisher_task(
                address,
                port,
                bind_address,
                receiver,
            ))
        });

        Self {
            cot_sender: Some(sender),
            thread: Some(thread_handle),
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

        let thread_handle = thread::spawn(move || {
            let runtime = Runtime::new().expect("Failed to create Tokio runtime");

            runtime.block_on(crate::multicast_publisher_task(
                address,
                port,
                bind_address,
                receiver,
            ))
        });

        Self {
            cot_sender: Some(sender),
            thread: Some(thread_handle),
            // Multicast is connectionless - always considered "connected" while the task runs
            connected: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Create a new TAK server publisher
    ///
    /// # Arguments
    ///
    /// * `url` - URL for the TAK server
    /// * `settings` - TAK server settings
    ///
    pub fn new_takserver(url: Url, settings: TakServerSetting<'static>) -> Self {
        let (sender, receiver) =
            tokio::sync::mpsc::channel::<CotSender>(crate::BROADCAST_CHANNEL_SIZE);
        let connected = Arc::new(AtomicBool::new(false));
        let task_connected = connected.clone();

        let thread_handle = thread::spawn(move || {
            let runtime = Runtime::new().expect("Failed to create Tokio runtime");

            runtime.block_on(crate::takserver_publisher_task_reconnect(
                url,
                settings,
                receiver,
                task_connected,
            ))
        });

        Self {
            cot_sender: Some(sender),
            thread: Some(thread_handle),
            connected,
        }
    }

    /// Create a new TAK server publisher with custom channel capacity
    ///
    /// # Arguments
    ///
    /// * `url` - URL for the TAK server
    /// * `settings` - TAK server settings
    /// * `channel_capacity` - Size of the broadcast channel buffer
    ///
    pub fn new_takserver_custom_channel_capacity(
        url: Url,
        settings: TakServerSetting<'static>,
        channel_capacity: usize,
    ) -> Self {
        let (sender, receiver) = tokio::sync::mpsc::channel::<CotSender>(channel_capacity);
        let connected = Arc::new(AtomicBool::new(false));
        let task_connected = connected.clone();

        let thread_handle = thread::spawn(move || {
            let runtime = Runtime::new().expect("Failed to create Tokio runtime");

            runtime.block_on(crate::takserver_publisher_task_reconnect(
                url,
                settings,
                receiver,
                task_connected,
            ))
        });

        Self {
            cot_sender: Some(sender),
            thread: Some(thread_handle),
            connected,
        }
    }

    /// Check if the publisher is still connected and the task is running
    ///
    /// This should be called periodically to ensure the connection is still alive
    ///
    pub fn check_connected(&mut self) -> Result<(), PublishError> {
        // The task has already been 'reaped'
        if self.thread.is_none() {
            return Err(PublishError::ConnectionError(
                "Task has already completed".into(),
            ));
        }

        // Happy path - task is still running and actively connected
        #[allow(clippy::collapsible_if)] // For MSRV compatibility
        if let Some(thread) = &self.thread {
            if !thread.is_finished() {
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
            .thread
            .take()
            .expect("Task was None...")
            .join()
            .map_err(|e| {
                PublishError::ConnectionError(format!("Failed joining publish thread: {e:?}"))
            })?;

        match task_result {
            // The task should never return Ok(()) while this CotPublisher (and its
            // cot_sender) is still alive, but handle it defensively
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
        if let Some(sender) = &self.cot_sender {
            Ok(CursorOnTarget::new(uid, r#type, sender.clone()))
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
        if let Some(sender) = &self.cot_sender {
            Ok(cot.clone().with_sender(sender.clone()))
        } else {
            Err(std::io::Error::other("Broadcast sender not available"))
        }
    }
}
