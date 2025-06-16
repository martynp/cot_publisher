
A Rust Cursor-On-Target generator for multicast and streaming data interfaces (TakServer).

# TakServer Setup

Add a new streaming data field, go `Configuration` -> `Inputs and Data Feeds` -> `Add Streaming Data Feed`.

Give the interface a name and select `Secure Streaming TCP (TLS) CoT or Protobuf` as the protocol. Select a port and select `Save`.

Create a user in the TakServer UI, then in the takserver console use the makeCert script:

```
cd /opt/tak/certs
sh -c "source ./makeCert.sh client [username]"
```

(replace [username] with the user just created)

The key and certificate for the user will be in the `/opt/tag/cert/files` directory.

TakServer generates user keys which are protected by the `atakatak` password, this can be removed using:

```
openssl rsa -in user.key -out user-nopass.key
```


# Example - Multicast Only

```rust
let mut publisher = CotPublisher::new(
    "test-uid-1234",
    "a-f-G-U-C",
);
publisher.set_multicast(
    "239.2.3.1"
        .parse::<Ipv4Addr>()
        .expect("Failed to parse")
        .into(),
    6969,
);
publisher.publish();
```

# Example - TakServer stream using TLS credentials from files

```rust
let mut publisher = CotPublisher::new(
    "test-uid-1234",
    "a-f-G-U-C",
    None,
    Some(("192.168.0.2", 9000)),
);

let ca_file = "[path_to]/truststore-intermediate-CA.pem";
let client_cert = "[path_to]/user.pem";
let client_key = "[path_to]/user-nopass.key";

publisher.set_tak_server_tls_settings(Some(TakServerSettings {
    tls: true,
    client_key: PEM::File(client_key.into()),
    client_cert: PEM::File(client_cert.into()),
    root_cert: PEM::File(ca_file.into()),
    ignore_invalid: false,
    verify_hostname: false,
}));

publisher.connect();
publisher.publish();

// Required if `publisher` is dropped to ensure message is actually sent
//std::thread::sleep(std::time::Duration::from_millis(100));
```

# Example - TakServer stream using TLS credentials from strings

```rust
let mut publisher = CotPublisher::new(
    "test-uid-1234",
    "a-f-G-U-C",
    None,
    Some(("192.168.0.2", 9000)),
);

let ca_file = r#"
Bag Attributes
    friendlyName: intermediate-CA
subject=C = US, ST = STATE, L = CITY, O = TAK, OU = ORG_UNIT, CN = intermediate-CA
issuer=C = US, ST = STATE, L = CITY, O = TAK, OU = ORG_UNIT, CN = takserver-CA
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
        "#;

let key = r#"
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
"#;

let cert = r#"
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
"#;

publisher.set_tak_server_tls_settings(Some(TakServerSettings {
    tls: true,
    client_key: PEM::String(key.into()),
    client_cert: PEM::String(cert.into()),
    root_cert: PEM::String(ca_file_content.into()),
    ignore_invalid: false,
    verify_hostname: false,
}));

publisher.connect();
publisher.publish();

// Required if `publisher` is dropped to ensure message is actually sent
//std::thread::sleep(std::time::Duration::from_millis(100));
```

# Example - Set position

```rust

let mut publisher = CotPublisher::new(
    "test-uid-1234",
    "a-f-G-U-C",
    Some("239.2.3.1:6969"),
    None,
);

publisher.set_contact(Some("MYTHING"), None);
publisher.set_position(10.0, 10.0);
publisher.set_xml_detail(Some("<custom somekey='somevalue'/>"));
publisher.publish();

```
