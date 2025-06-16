use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslStream, SslVerifyMode};
use prost::Message;
use std::{
    io::{Read, Write},
    net::{IpAddr, TcpStream, UdpSocket},
};
use url::Url;

// Publishes COT messages to multicast or TCP targets
#[derive(Default)]
pub struct CotPublisher {
    multicast: Option<(IpAddr, u16)>,
    tak_server_ip_address: Option<(IpAddr, u16)>,
    tak_server_domain: Option<Url>,

    tak_server_settings: Option<TakServerSetting>,
    stale_time_ms: u64,
    uid: String,
    contact: Option<Contact>,
    r#type: String,
    xml_detail: Option<String>,
    position: Option<Position>,
    precision_location: Option<PrecisionLocation>,

    pub how: String,
    pub access: String,
    pub qos: String,
    pub opex: String,

    /* Sockets */
    multicast_socket: Option<UdpSocket>,
    tak_server_socket: Option<StreamOptions>,
}

const PROTOCOL_CHANGE: &str = r"
    <event version='2.0' uid='protouid' type='t-x-takp-q' time='TIME' start='TIME' stale='TIME' how='m-g'>
      <point lat='0.0' lon='0.0' hae='0.0' ce='999999' le='999999'/>
      <detail>
        <TakControl>
          <TakRequest version='1'/>
        </TakControl>
      </detail>
    </event>\n\n";

pub mod tak_proto {
    include!(concat!(
        env!("OUT_DIR"),
        "/atakmap.commoncommo.protobuf.v1.rs"
    ));
}

pub struct TakServerSetting {
    pub tls: bool,
    pub client_key: PEM,
    pub client_cert: PEM,
    pub root_cert: PEM,
    pub ignore_invalid: bool,
    pub verify_hostname: bool,
}

pub enum PEM {
    None,
    File(String),
    String(String),
}

struct Contact {
    pub endpoint: String,
    pub callsign: String,
}

struct Position {
    pub lat: f64,
    pub lng: f64,
    pub hae: f64,
    pub ce: f64,
    pub le: f64,
}

struct PrecisionLocation {
    pub altsrc: String,
    pub geopointsrc: String,
}

enum StreamOptions {
    Tls(SslStream<TcpStream>),
    Tcp(TcpStream),
}

impl CotPublisher {
    pub fn new(uid: &str, r#type: &str) -> Self {
        Self {
            uid: uid.into(),
            r#type: r#type.into(),
            stale_time_ms: 60 * 1000,
            how: "m-g".into(),

            multicast_socket: None,
            tak_server_socket: None,

            ..Default::default()
        }
    }

    /// Set multicast address
    ///
    /// # Arguments
    ///
    /// * `address` - IpAddress to send multicast packet to, normally 239.2.3.1
    /// * `port` - Port to use to send packet, normally 6969
    ///
    pub fn set_multicast(&mut self, address: IpAddr, port: u16) {
        self.clear_multicast();
        self.multicast = Some((address, port));
    }

    /// Clear the multicast destination details - disables multicast
    ///
    pub fn clear_multicast(&mut self) {
        self.multicast = None;
        self.multicast_socket = None;
    }

    pub fn set_tak_server_domain(&mut self, domain: Url) {
        self.clear_tak_server();
        self.tak_server_ip_address = None;
        self.tak_server_domain = Some(domain);
    }

    pub fn set_tak_server_ip_address(&mut self, address: IpAddr, port: u16) {
        self.clear_tak_server();
        self.tak_server_domain = None;
        self.tak_server_ip_address = Some((address, port));
    }

    pub fn clear_tak_server(&mut self) {
        if let Some(socket) = self.tak_server_socket.as_mut() {
            match socket {
                StreamOptions::Tls(socket) => {
                    socket.shutdown().ok();
                }
                StreamOptions::Tcp(socket) => {
                    socket.shutdown(std::net::Shutdown::Both).ok();
                }
            }
        }

        self.tak_server_ip_address = None;
        self.tak_server_socket = None;
    }

    pub fn set_tak_server_tls_settings(&mut self, settings: Option<TakServerSetting>) {
        self.tak_server_settings = settings
    }

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

    pub fn set_xml_detail(&mut self, xml_detail: Option<&str>) {
        self.xml_detail = xml_detail.map(|v| v.into());
    }

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

    pub fn set_position_extended(&mut self, lat: f64, lng: f64, hae: f64, ce: f64, le: f64) {
        self.position = Some(Position {
            lat,
            lng,
            hae,
            ce,
            le,
        });
    }

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

    pub fn connect(&mut self) {
        self.tak_server_socket = self.tak_server_connect();
    }

    pub fn publish(&mut self) {
        if self.multicast.is_none() && self.tak_server_ip_address.is_none() {
            // Nothing to do
            return;
        }

        let message = self.create_cot();
        let mut message_buffer = Vec::with_capacity(message.encoded_len());
        message.encode(&mut message_buffer).unwrap();

        if let Some(multicast) = self.multicast.as_ref() {
            if self.multicast_socket.is_none() {
                self.multicast_socket = CotPublisher::multicast_connect();
            }

            if let Some(socket) = self.multicast_socket.as_mut() {
                let mut buffer = vec![0xbf, 0x01, 0xbf]; // Magic
                buffer.append(&mut message_buffer);
                socket.send_to(&buffer, multicast).unwrap();
            }
        }

        if self.tak_server_ip_address.is_some() {
            if self.tak_server_socket.is_none() {
                self.tak_server_socket = self.tak_server_connect();
            }

            if let Some(option) = &mut self.tak_server_socket {
                match option {
                    StreamOptions::Tls(stream) => {
                        // Magic
                        stream.write_all(&[0xbf]).ok();
                        stream
                            .write_all(&CotPublisher::get_varint(message_buffer.len() as u32))
                            .ok();
                        // Message
                        stream.write_all(&message_buffer).ok();
                    }
                    StreamOptions::Tcp(stream) => {
                        // Magic
                        stream.write_all(&[0xbf]).ok();
                        stream
                            .write_all(&CotPublisher::get_varint(message_buffer.len() as u32))
                            .ok();
                        // Message
                        stream.write_all(&message_buffer).ok();
                    }
                }
            }
        }
    }

    fn multicast_connect() -> Option<UdpSocket> {
        match UdpSocket::bind("192.168.240.1:0") {
            Ok(v) => Some(v),
            Err(e) => {
                log::warn!("Unable to bind to {}: {}", "0.0.0.0:0", e);
                None
            }
        }
    }

    fn tak_server_connect(&self) -> Option<StreamOptions> {
        if self.tak_server_ip_address.is_none() && self.tak_server_domain.is_none() {
            log::info!("Attempted to connect to tak_server but tak_server settings are not set");
            return None;
        }

        let tak_server = if let Some(ip_address) = self.tak_server_ip_address {
            format!(
                "{}:{}",
                ip_address.0,
                ip_address.1
            )
        } else if let Some(domain) = &self.tak_server_domain {
            domain.to_string()
        } else {
            "Unreachable".into()
        };

        let mut stream = match TcpStream::connect(tak_server.to_owned()) {
            Ok(v) => v,
            Err(e) => {
                log::warn!(
                    "Unable to connect to {}:{}: {}",
                    self.tak_server_ip_address.as_ref().unwrap().0,
                    self.tak_server_ip_address.as_ref().unwrap().1,
                    e
                );
                return None;
            }
        };

        let server_settings = match self.tak_server_settings.as_ref() {
            Some(settings) => settings,
            None => &TakServerSetting {
                tls: false,
                client_key: PEM::None,
                client_cert: PEM::None,
                root_cert: PEM::None,
                ignore_invalid: true,
                verify_hostname: false,
            },
        };

        if !server_settings.tls {
            stream.write_all(PROTOCOL_CHANGE.as_bytes()).ok();
            return Some(StreamOptions::Tcp(stream));
        }

        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();

        match &server_settings.root_cert {
            PEM::File(cert) => {
                if let Err(e) = builder.set_ca_file(cert) {
                    log::warn!("Unable to set ca_file for tak_server connection: {}", e);
                    return None;
                }
            }
            PEM::String(cert) => {
                use openssl::x509::{store::X509StoreBuilder, X509};
                let certs = X509::stack_from_pem(cert.as_bytes()).unwrap();
                let mut store = X509StoreBuilder::new().unwrap();
                certs.iter().for_each(|cert| {
                    store.add_cert(cert.clone()).unwrap();
                });
                if let Err(e) = builder.set_verify_cert_store(store.build()) {
                    log::warn!(
                        "Unable to set certificate_store for tak_server connection: {}",
                        e
                    );
                    return None;
                }
            }
            PEM::None => (),
        }

        match &server_settings.client_cert {
            PEM::File(cert) => {
                if let Err(e) = builder.set_certificate_file(cert, SslFiletype::PEM) {
                    log::warn!(
                        "Unable to set client certificate for tak_server connection: {}",
                        e
                    );
                    return None;
                }
            }
            PEM::String(cert) => {
                use openssl::x509::X509;
                let cert = X509::from_pem(cert.as_bytes()).unwrap();
                if let Err(e) = builder.set_certificate(&cert) {
                    log::warn!(
                        "Unable to set client certificate for tak_server connection: {}",
                        e
                    );
                    return None;
                }
            }
            PEM::None => (),
        }

        match &server_settings.client_key {
            PEM::File(key) => {
                if let Err(e) = builder.set_private_key_file(key, SslFiletype::PEM) {
                    log::warn!(
                        "Unable to set client private key for tak_server connection: {}",
                        e
                    );
                    return None;
                }
            }
            PEM::String(key) => {
                use openssl::pkey::PKey;
                let key = PKey::private_key_from_pem(key.as_bytes()).unwrap();
                if let Err(e) = builder.set_private_key(&key) {
                    log::warn!(
                        "Unable to set client private key for tak_server connection: {}",
                        e
                    );
                    return None;
                }
            }
            PEM::None => (),
        }

        if server_settings.verify_hostname {
            builder.set_verify(SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        } else {
            builder.set_verify(SslVerifyMode::NONE);
        }

        let connector = builder.build();

        let mut stream = match connector.connect(&tak_server, stream) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("Unable to create tak_server connection: {}", e);
                return None;
            }
        };
        stream
            .get_mut()
            .set_read_timeout(Some(std::time::Duration::from_millis(100)))
            .ok();
        stream.write_all(PROTOCOL_CHANGE.as_bytes()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));

        let mut res = vec![];
        if let Ok(bytes) = stream.read_vectored(&mut res) {
            if bytes > 0 {
                dbg!(bytes);
            }
        }

        Some(StreamOptions::Tls(stream))
    }

    fn create_cot(&self) -> tak_proto::TakMessage {
        let pos = self.position.as_ref().unwrap_or(&Position {
            lat: 0.0,
            lng: 0.0,
            hae: 0.0,
            ce: 0.0,
            le: 0.0,
        });

        let time = CotPublisher::get_time();
        tak_proto::TakMessage {
            tak_control: Some(tak_proto::TakControl {
                min_proto_version: 2,
                max_proto_version: 2,
                contact_uid: self.uid.to_owned(),
            }),
            cot_event: Some(tak_proto::CotEvent {
                r#type: self.r#type.to_owned(),
                access: self.access.to_owned(),
                qos: self.qos.to_owned(),
                opex: self.opex.to_owned(),
                uid: self.uid.to_owned(),
                send_time: time,
                start_time: time,
                stale_time: time + self.stale_time_ms,
                how: self.how.to_owned(),
                lat: pos.lat,
                lon: pos.lng,
                hae: pos.hae,
                ce: pos.ce,
                le: pos.le,
                detail: Some(tak_proto::Detail {
                    xml_detail: self.xml_detail.to_owned().unwrap_or("".into()),
                    contact: self.contact.as_ref().map(|c| tak_proto::Contact {
                        endpoint: c.endpoint.to_owned(),
                        callsign: c.callsign.to_owned(),
                    }),
                    group: None,
                    precision_location: self.precision_location.as_ref().map(|p| {
                        tak_proto::PrecisionLocation {
                            geopointsrc: p.geopointsrc.to_owned(),
                            altsrc: p.altsrc.to_owned(),
                        }
                    }),
                    status: None,
                    takv: None,
                    track: None,
                }),
            }),
        }
    }

    fn get_time() -> u64 {
        let now = std::time::SystemTime::now();
        let since_the_epoch = now
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards");
        since_the_epoch.as_millis() as u64
    }
    fn get_varint(size: u32) -> Vec<u8> {
        use varint_rs::VarintWriter;
        // Message size
        let mut size_buffer: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(Vec::with_capacity(4));
        size_buffer.write_u32_varint(size).unwrap();
        size_buffer.into_inner()
    }
}
