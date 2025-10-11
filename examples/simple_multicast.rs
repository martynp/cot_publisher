// SPDX-License-Identifier: MIT
// Copyright (c) 2021-2025 Martyn P <martyn@datasync.dev>

//! Simple multicast CoT publisher example
//!
//! This example demonstrates publishing CoT messages to a multicast address.
//! 
//! Run with: cargo run --example simple_multicast

use cot_publisher::CotPublisher;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Create a multicast publisher
    // Standard multicast address for TAK: 239.2.3.1:6969
    let publisher = CotPublisher::new_multicast("239.2.3.1".parse()?, 6969);

    println!("Publishing CoT messages to multicast 239.2.3.1:6969");

    // Create a CoT message
    let mut cot = publisher.create_cot("example-uid-001", "a-f-G-E-V-C")?;

    // Set position (latitude, longitude)
    // Example: London coordinates
    cot.set_position(51.5074, -0.1278);

    // Set contact information
    cot.set_contact(Some("EXAMPLE-1"), Some("192.168.1.100:8080"));

    // Set extended position with altitude and accuracy
    // lat, lng, hae (height above ellipsoid), ce (circular error), le (linear error)
    cot.set_position_extended(51.5074, -0.1278, 100.0, 10.0, 15.0);

    // Add precision location metadata
    cot.set_precision_location(Some("GPS"), Some("GPS"));

    // Optionally add custom XML detail
    cot.set_xml_detail(Some(
        r#"<custom>
            <attribute key="example">value</attribute>
        </custom>"#,
    ));

    // Publish the message
    cot.publish().await?;
    println!("Published CoT message for UID: example-uid-001");

    // Keep publishing updates every 5 seconds
    for i in 1..=5 {
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        let mut cot = publisher.create_cot("example-uid-001", "a-f-G-E-V-C")?;
        
        // Simulate movement by slightly changing position
        let new_lat = 51.5074 + (i as f64 * 0.001);
        let new_lng = -0.1278 + (i as f64 * 0.001);
        
        cot.set_position_extended(new_lat, new_lng, 100.0, 10.0, 15.0);
        cot.set_contact(Some("EXAMPLE-1"), Some("192.168.1.100:8080"));
        cot.set_precision_location(Some("GPS"), Some("GPS"));

        cot.publish().await?;
        println!("Published update {} - Position: {:.4}, {:.4}", i, new_lat, new_lng);
    }

    println!("Example completed successfully!");

    Ok(())
}
