
# COT Publisher

A Rust library for publishing Cursor on Target (COT) messages to multicast networks and TAK Servers. 

This library provides both async and blocking interfaces for integrating COT functionality into Rust applications

## Features

The crate supports publishing COT messages through two transport mechanisms:

 * **Multicast Publishing** 
 * **TLS/mTLS Publishing** (TAK Server etc.)
 * Async and Blocking API's


## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
cot_publisher = "2.0.0-rc1"
```

For blocking operations, enable the blocking feature:

```toml
[dependencies]
cot_publisher = { version = "2.0.0-rc1", features = ["blocking"] }
```

## Basic Usage

### Async Multicast Publishing

```rust
use cot_publisher::CotPublisher;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create publisher for standard TAK multicast address
    let publisher = CotPublisher::new_multicast("239.2.3.1".parse()?, 6969);
    
    // Create a COT message with unique identifier and type
    let mut cot = publisher.create_cot("my-device-001", "a-f-G-E-V-C")?;
    
    // Set position and contact information
    cot.set_position(51.5074, -0.1278); // London coordinates
    cot.set_contact(Some("CALLSIGN-1"), Some("192.168.1.100:8080"));
    
    // Publish the message
    cot.publish().await?;
    
    Ok(())
}
```

### Blocking Multicast Publishing

```rust
use cot_publisher::blocking::CotPublisher;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let publisher = CotPublisher::new_multicast("239.2.3.1".parse()?, 6969);
    let mut cot = publisher.create_cot("my-device-001", "a-f-G-E-V-C")?;
    
    cot.set_position(51.5074, -0.1278);
    cot.set_contact(Some("CALLSIGN-1"), None);
    
    cot.blocking_publish()?;
    
    Ok(())
}
```

### TAK Server Connection with TLS

```rust
use cot_publisher::{CotPublisher, Credentials, Source, TakServerSetting};
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load client certificates
    let credentials = Credentials::from_unencrypted_pem(
        Source::File("/path/to/client-cert.pem".to_string()),
        Source::File("/path/to/client-key.pem".to_string()),
    )?;
    
    // Configure TLS settings
    let settings = TakServerSetting {
        tls: true,
        client_credentials: Some(credentials),
        root_cert: Some(Source::File("/path/to/ca-cert.pem".to_string())),
        ignore_invalid: false,
        verify_hostname: true,
        auto_reconnect: true,
    };
    
    // Connect to TAK Server
    let tak_server_url = Url::parse("https://takserver.example.com:8089")?;
    let mut publisher = CotPublisher::new_takserver(tak_server_url, settings);
    
    // Wait for connection establishment
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    
    // Create and publish COT message
    let mut cot = publisher.create_cot("takserver-client-001", "a-f-G-E-V-C")?;
    cot.set_position(40.7128, -74.0060); // New York coordinates
    cot.set_contact(Some("NYC-BASE"), None);
    
    cot.publish().await?;
    
    Ok(())
}
```

## COT Message Types

The COT type field follows the standard COT taxonomy. Common types include:

- `a-f-G-E-V-C`: Ground friendly unit, equipment, vehicle, combat
- `a-f-G-E-V-M`: Ground friendly unit, equipment, vehicle, medical  
- `a-f-G-I`: Ground friendly unit, installations
- `a-h-G`: Ground hostile unit
- `a-n-G`: Ground neutral unit
- `a-u-G`: Ground unknown unit

## Extended Position Information

```rust
// Set position with altitude and accuracy information
cot.set_position_extended(
    51.5074,    // latitude
    -0.1278,    // longitude  
    100.0,      // altitude (HAE - Height Above Ellipsoid)
    10.0,       // circular error (CE)
    15.0        // linear error (LE)
);

// Add precision location source information
cot.set_precision_location(Some("GPS"), Some("GPS"));
```

## Custom XML Details

COT messages support custom XML detail sections for application-specific data:

```rust
cot.set_xml_detail(Some(r#"
<custom>
    <sensor type="thermal" status="active"/>
    <battery level="85" voltage="12.4"/>
</custom>
"#));
```

## Certificate Management for TAK Server

When connecting to TAK Server, you need client certificates. TAK Server typically generates certificates protected with the password "atakatak". 

It is possible to provide the password as part of the connection `Credential` or remove password protection using:

```bash
openssl rsa -in client.key -out client-nopass.key
```

Certificates can be loaded from files or embedded as strings in your application:

```rust
// From files
let credentials = Credentials::from_unencrypted_pem(
    Source::File("client-cert.pem".to_string()),
    Source::File("client-key.pem".to_string()),
)?;

// From strings (useful for embedded certificates)
let cert_pem = include_str!("../certs/client-cert.pem");
let key_pem = include_str!("../certs/client-key.pem");

let credentials = Credentials::from_unencrypted_pem(
    Source::String(cert_pem.to_string()),
    Source::String(key_pem.to_string()),
)?;
```

## TAK Server Configuration

To accept COT messages, configure TAK Server with a streaming data feed (in many cases a mTLS connection is enabled by default):

1. Navigate to Configuration → Inputs and Data Feeds → Add Streaming Data Feed
2. Select "Secure Streaming TCP (TLS) CoT or Protobuf" as the protocol
3. Configure the desired port
4. Create client certificates using the TAK Server makeCert script

## Error Handling

Enable error logging by adding the `emit_errors` feature:

```toml
[dependencies]
cot_publisher = { version = "2.0.0-rc1", features = ["emit_errors"] }
```

When enabled logs are emitted via the `log` crate. 

## Examples

The repository includes several complete examples:

- `simple_multicast.rs`: Basic multicast publishing with position updates
- `blocking_multicast.rs`: Blocking interface demonstration  
- `takserver_connection.rs`: TAK Server connection with TLS certificates

Run examples with:

```bash
cargo run --example simple_multicast
cargo run --features blocking --example blocking_multicast
```

The takserver example requires certificate / key information to be added before it can be used.

## License

This project is licensed under the MIT License.
