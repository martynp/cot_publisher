// SPDX-License-Identifier: MIT
// Copyright (c) 2021-2025 Martyn P <martyn@datasync.dev>

//! Blocking multicast CoT publisher example
//!
//! This example demonstrates using the blocking API to publish CoT messages
//! to a multicast address without requiring an async runtime in your main code.
//!
//! Run with: cargo run --example blocking_multicast --features blocking

use cot_publisher::blocking::CotPublisher;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Create a blocking multicast publisher
    // Standard multicast address for TAK: 239.2.3.1:6969
    let publisher = CotPublisher::new_multicast("239.2.3.1".parse()?, 6969);

    println!("Publishing CoT messages to multicast 239.2.3.1:6969 (blocking mode)");

    // Create a CoT message
    let mut cot = publisher.create_cot("blocking-example-001", "a-f-G-E-S")?;

    // Set initial position and contact info
    cot.set_position(37.7749, -122.4194);
    cot.set_contact(Some("BLOCKING-1"), Some("192.168.1.200:8080"));
    cot.set_position_extended(37.7749, -122.4194, 50.0, 8.0, 10.0);
    cot.set_precision_location(Some("GPS"), Some("GPS"));

    // Publish the message
    cot.blocking_publish_checked()?;

    println!("Published initial CoT message");

    // Simulate a simple application loop
    println!("Updating position every 2 seconds...");

    for i in 1..=10 {
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Simulate movement
        let new_lat = 37.7749 + (i as f64 * 0.0008);
        let new_lng = -122.4194 - (i as f64 * 0.0008);

        cot.set_position_extended(new_lat, new_lng, 50.0, 8.0, 10.0);
        cot.set_contact(Some("BLOCKING-1"), Some("192.168.1.200:8080"));
        cot.set_precision_location(Some("GPS"), Some("GPS"));

        // Optionally add custom XML with status information
        let xml_detail = format!(
            r#"<status>
                <update_number>{}</update_number>
                <battery>{}%</battery>
            </status>"#,
            i,
            100 - (i * 5) // Simulate battery drain
        );
        cot.set_xml_detail(Some(&xml_detail));

        cot.blocking_publish()?;
        println!("Update {}/10 - Position: {:.4}, {:.4}", i, new_lat, new_lng);
    }

    println!("Blocking example completed successfully!");

    // Give the internal async runtime a moment to flush any pending messages
    std::thread::sleep(std::time::Duration::from_millis(100));

    Ok(())
}
