// SPDX-License-Identifier: MIT
// Copyright (c) 2021-2025 Martyn P <martyn@datasync.dev>

//! This module provides a Cursor on Target (COT) message structure and related types.;

use crate::{CotSender, PublishError};

/// Cursor on Target (COT) message structure and related types
#[derive(Debug, Default)]
pub struct CursorOnTarget {
    /// Time in milliseconds after which this COT message should be considered stale
    pub stale_time_ms: u64,
    /// Unique identifier for this COT entity
    pub uid: String,
    /// Contact information including callsign and endpoint
    pub contact: Option<Contact>,
    /// COT type hierarchy (e.g., "a-f-G-E-V-C" for friendly ground equipment)
    pub r#type: String,
    /// Optional XML detail block for additional COT data
    pub xml_detail: Option<String>,
    /// Geographic position of the entity
    pub position: Option<Position>,
    /// Precision location metadata including source information
    pub precision_location: Option<PrecisionLocation>,
    /// How this COT was generated (e.g., "m-g" for machine-generated)
    pub how: String,
    /// Access restrictions for this COT message
    pub access: String,
    /// Quality of service level
    pub qos: String,
    /// Operational expertise or operational context
    pub opex: String,

    publish_sender: Option<tokio::sync::mpsc::Sender<CotSender>>,
}

/// Contact information for a COT entity
#[derive(Clone, Debug, Default)]
pub struct Contact {
    /// Network endpoint (IP address, hostname, or other communication address)
    pub endpoint: String,
    /// Human-readable callsign or identifier for the entity
    pub callsign: String,
}

/// Geographic position information for a COT entity
#[derive(Clone, Debug, Default)]
pub struct Position {
    /// Latitude in decimal degrees (WGS-84)
    pub lat: f64,
    /// Longitude in decimal degrees (WGS-84)
    pub lng: f64,
    /// Height Above Ellipsoid in meters (WGS-84)
    pub hae: f64,
    /// Circular Error - horizontal position accuracy in meters (with 90% confidence)
    pub ce: f64,
    /// Linear Error - vertical position accuracy in meters (with 90% confidence)
    pub le: f64,
}

/// Precision location metadata describing the source of position data
///
/// Provides information about how the position and altitude were determined.
#[derive(Clone, Debug, Default)]
pub struct PrecisionLocation {
    /// Altitude source (e.g., "GPS", "BARO", "USER")
    pub altsrc: String,
    /// Geopoint source (e.g., "GPS", "USER", "CALCULATED")
    pub geopointsrc: String,
}

impl Clone for CursorOnTarget {
    fn clone(&self) -> Self {
        Self {
            stale_time_ms: self.stale_time_ms,
            uid: self.uid.clone(),
            contact: self.contact.clone(),
            r#type: self.r#type.clone(),
            xml_detail: self.xml_detail.clone(),
            position: self.position.clone(),
            precision_location: self.precision_location.clone(),
            how: self.how.clone(),
            access: self.access.clone(),
            qos: self.qos.clone(),
            opex: self.opex.clone(),
            publish_sender: None,
        }
    }
}

impl CursorOnTarget {
    /// Creates a new Cursor on Target message with default values
    ///
    /// # Arguments
    ///
    /// * `uid` - Unique identifier for this COT entity
    /// * `r#type` - COT type hierarchy (e.g., "a-f-G-E-V-C" for friendly ground equipment)
    /// * `publisher` - mpsc sender for publishing this COT message to subscribers
    ///
    pub fn new<S: AsRef<str> + ToString>(
        uid: S,
        r#type: S,
        publisher: tokio::sync::mpsc::Sender<CotSender>,
    ) -> Self {
        Self {
            uid: uid.to_string(),
            r#type: r#type.to_string(),
            stale_time_ms: 60 * 1000,
            how: "m-g".into(),
            publish_sender: Some(publisher),
            ..Default::default()
        }
    }

    /// Sets or replaces the mpsc sender for this COT message (builder pattern)
    ///
    /// # Arguments
    ///
    /// * `sender` - mpsc sender for publishing this COT message to subscribers
    ///
    pub(crate) fn with_sender(mut self, sender: tokio::sync::mpsc::Sender<CotSender>) -> Self {
        self.publish_sender = Some(sender);
        self
    }

    /// Publishes this COT message to all subscribers via the mpsc channel
    ///
    /// Clones the current COT message and sends it to all active subscribers.
    /// The publish sender must be set either via [`new`](Self::new) or
    /// [`with_sender`](Self::with_sender) before calling this method.
    ///
    /// # Errors
    ///
    /// Returns an `std::io::Error` if:
    /// - The publish sender has not been configured
    /// - The mpsc channel fails to send (all receivers dropped)
    /// - The mpsc channel is full (should not happen with sufficient buffer size)
    ///
    pub async fn publish(&self) -> Result<(), PublishError> {
        self.publish_sender
            .as_ref()
            .ok_or(PublishError::SendError("Publish sender is not set".into()))?
            .send((self.clone(), None))
            .await
            .map_err(|e| PublishError::SendError(e.to_string()))
    }

    /// Publishes this COT message to all subscribers via the mpsc channel
    ///
    /// Clones the current COT message and sends it to all active subscribers.
    /// The publish sender must be set either via [`new`](Self::new) or
    /// [`with_sender`](Self::with_sender) before calling this method.
    ///
    /// # Errors
    ///
    /// Returns an `std::io::Error` if:
    /// - The publish sender has not been configured
    /// - The mpsc channel fails to send (all receivers dropped)
    /// - The mpsc channel is full (should not happen with sufficient buffer size)
    ///
    #[cfg(feature = "blocking")]
    pub fn blocking_publish(&self) -> Result<(), PublishError> {
        self.publish_sender
            .as_ref()
            .ok_or(PublishError::SendError("Publish sender is not set".into()))?
            .blocking_send((self.clone(), None))
            .map_err(|e| PublishError::SendError(e.to_string()))
    }

    /// Publishes this COT message to all subscribers via the mpsc channel
    /// and waits for confirmation of the COT being sent
    ///
    /// # Errors
    ///
    /// Returns an `std::io::Error` if:
    /// - The publish sender has not been configured
    /// - The mpsc channel fails to send (all receivers dropped)
    /// - The mpsc channel is full (should not happen with sufficient buffer size)
    ///
    pub async fn publish_checked(&self) -> Result<(), PublishError> {
        let (response_sender, response_receiver) =
            tokio::sync::oneshot::channel::<Result<(), PublishError>>();

        self.publish_sender
            .as_ref()
            .ok_or(PublishError::SendError("Publish sender is not set".into()))?
            .send((self.clone(), Some(response_sender)))
            .await
            .map_err(|e| PublishError::SendError(e.to_string()))?;

        response_receiver
            .await
            .map_err(|e| PublishError::SendError(e.to_string()))?
    }

    /// Publishes this COT message to all subscribers via the mpsc channel
    /// and waits for confirmation of the COT being sent
    ///
    /// # Errors
    ///
    /// Returns an `std::io::Error` if:
    /// - The publish sender has not been configured
    /// - The mpsc channel fails to send (all receivers dropped)
    /// - The mpsc channel is full (should not happen with sufficient buffer size)
    ///
    #[cfg(feature = "blocking")]
    pub fn blocking_publish_checked(&self) -> Result<(), PublishError> {
        let (response_sender, response_receiver) =
            tokio::sync::oneshot::channel::<Result<(), PublishError>>();

        self.publish_sender
            .as_ref()
            .ok_or(PublishError::SendError("Publish sender is not set".into()))?
            .blocking_send((self.clone(), Some(response_sender)))
            .map_err(|e| PublishError::SendError(e.to_string()))?;

        response_receiver
            .blocking_recv()
            .map_err(|e| PublishError::SendError(e.to_string()))?
    }

    /// Sets or clears the contact information for this COT entity
    ///
    /// If both `callsign` and `endpoint` are `None`, the contact is cleared.
    ///
    /// # Arguments
    ///
    /// * `callsign` - Optional human-readable callsign or identifier
    /// * `endpoint` - Optional network endpoint (IP address, hostname, etc.)
    ///
    pub fn set_contact(&mut self, callsign: Option<&str>, endpoint: Option<&str>) {
        if callsign.is_none() && endpoint.is_none() {
            self.contact = None;
            return;
        }

        self.contact = Some(Contact {
            endpoint: endpoint.unwrap_or("").into(),
            callsign: callsign.unwrap_or("").into(),
        });
    }

    /// Sets or clears the XML detail block for this COT message
    ///
    /// The XML detail block can contain additional COT-specific data in XML format.
    ///
    /// # Arguments
    ///
    /// * `xml_detail` - Optional XML string containing additional COT detail information
    ///
    pub fn set_xml_detail(&mut self, xml_detail: Option<&str>) {
        self.xml_detail = xml_detail.map(|v| v.into());
    }

    /// Sets the basic position (latitude and longitude) for this COT entity
    ///
    /// If a position already exists, only the latitude and longitude are updated.
    /// Otherwise, creates a new position with `hae`, `ce`, and `le` set to 0.0.
    ///
    /// # Arguments
    ///
    /// * `lat` - Latitude in decimal degrees (WGS-84)
    /// * `lng` - Longitude in decimal degrees (WGS-84)
    ///
    pub fn set_position(&mut self, lat: f64, lng: f64) {
        if let Some(pos) = self.position.as_mut() {
            pos.lat = lat;
            pos.lng = lng;
        } else {
            self.position = Some(Position {
                lat,
                lng,
                hae: 0.0,
                ce: 0.0,
                le: 0.0,
            });
        }
    }

    /// Sets the complete position including altitude and accuracy for this COT entity
    ///
    /// Creates or replaces the position with all fields specified.
    ///
    /// # Arguments
    ///
    /// * `lat` - Latitude in decimal degrees (WGS-84)
    /// * `lng` - Longitude in decimal degrees (WGS-84)
    /// * `hae` - Height Above Ellipsoid in meters (WGS-84)
    /// * `ce` - Circular Error - horizontal position accuracy in meters (90% confidence)
    /// * `le` - Linear Error - vertical position accuracy in meters (90% confidence)
    ///
    pub fn set_position_extended(&mut self, lat: f64, lng: f64, hae: f64, ce: f64, le: f64) {
        self.position = Some(Position {
            lat,
            lng,
            hae,
            ce,
            le,
        });
    }

    /// Sets or clears the precision location metadata for this COT entity
    ///
    /// If both `geopointsrc` and `altsrc` are `None`, the precision location is cleared.
    ///
    /// # Arguments
    ///
    /// * `geopointsrc` - Optional geopoint source (e.g., "GPS", "USER", "CALCULATED")
    /// * `altsrc` - Optional altitude source (e.g., "GPS", "BARO", "USER")
    ///
    pub fn set_precision_location(&mut self, geopointsrc: Option<&str>, altsrc: Option<&str>) {
        if geopointsrc.is_none() && altsrc.is_none() {
            self.precision_location = None;
            return;
        }

        self.precision_location = Some(PrecisionLocation {
            altsrc: altsrc.unwrap_or("").into(),
            geopointsrc: geopointsrc.unwrap_or("").into(),
        });
    }

    /// Sets the unique identifier (UID) for this COT entity
    /// 
    /// # Arguments
    /// 
    /// * `uid` - Unique identifier string
    ///
    pub fn set_uid(&mut self, uid: &str) {
        self.uid = uid.into();
    }
}
