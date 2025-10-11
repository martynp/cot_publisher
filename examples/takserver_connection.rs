// SPDX-License-Identifier: MIT
// Copyright (c) 2021-2025 Martyn P <martyn@datasync.dev>

//! TAK Server connection example
//!
//! This example demonstrates connecting to a TAK Server over TLS with client certificates.
//! Run with: cargo run --example takserver_connection

use cot_publisher::{CotPublisher, Credentials, Source, TakServerSetting};
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging (optional)
    env_logger::init();

    // Configure TAK Server connection
    // Replace these with your actual TAK Server details
    let tak_server_url = Url::parse("https://takserver.example.com:8089")?;

    // Option 1: Load certificates from files
    let credentials = Credentials::from_unencrypted_pem(
        Source::File("/path/to/client-cert.pem".to_string()),
        Source::File("/path/to/client-key.pem".to_string()),
    )?;

    // Option 2: Use certificates from strings (useful for embedded certs)
    // Uncomment to use:
    /*
    let cert_pem = r#"
-----BEGIN CERTIFICATE-----
... your certificate here ...
-----END CERTIFICATE-----
"#;

    let key_pem = r#"
-----BEGIN PRIVATE KEY-----
... your private key here ...
-----END PRIVATE KEY-----
"#;

    let credentials = Credentials::from_unencrypted_pem(
        Source::String(cert_pem.to_string()),
        Source::String(key_pem.to_string()),
    )?;
    */

    // Configure TLS settings
    let settings = TakServerSetting {
        tls: true,
        client_credentials: Some(credentials),
        root_cert: Some(Source::File("/path/to/truststore-root.pem".to_string())),
        // WARNING: Setting these to true disables important security checks!
        // Only use in development environments with self-signed certificates
        ignore_invalid: false,
        verify_hostname: true,
        auto_reconnect: true,
    };

    println!("Connecting to TAK Server at {}", tak_server_url);

    // Create TAK Server publisher
    let mut publisher = CotPublisher::new_takserver(tak_server_url, settings);

    // Wait a moment for connection to establish
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Check if connected
    match publisher.check_connected().await {
        Ok(_) => println!("Successfully connected to TAK Server"),
        Err(e) => {
            eprintln!("Failed to connect to TAK Server: {}", e);
            return Err(e.into());
        }
    }

    // Create and publish a CoT message
    let mut cot = publisher.create_cot("takserver-example-001", "a-f-G-E-V-C")?;

    // Set position (New York City coordinates as example)
    cot.set_position_extended(40.7128, -74.0060, 10.0, 5.0, 5.0);
    cot.set_contact(Some("TAK-CLIENT-1"), Some("192.168.1.50:4242"));
    cot.set_precision_location(Some("GPS"), Some("GPS"));

    // Publish to TAK Server
    cot.publish().await?;
    println!("Published CoT message to TAK Server");

    // Publish multiple updates
    for i in 1..=10 {
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        // Check connection is still alive
        if let Err(e) = publisher.check_connected().await {
            eprintln!("Connection lost: {}", e);
            break;
        }

        // Simulate movement
        let new_lat = 40.7128 + (i as f64 * 0.0005);
        let new_lng = -74.0060 + (i as f64 * 0.0005);

        cot.set_position_extended(new_lat, new_lng, 10.0, 5.0, 5.0);

        cot.publish().await?;
        println!(
            "Published update {} to TAK Server - Position: {:.4}, {:.4}",
            i, new_lat, new_lng
        );
    }

    println!("TAK Server example completed successfully!");

    Ok(())
}
