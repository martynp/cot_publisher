# Examples

This directory contains example implementations demonstrating how to use the `cot_publisher` crate.

## Available Examples

### 1. Simple Multicast (`simple_multicast.rs`)

Demonstrates publishing CoT messages to a multicast address using the async API.

**Run:**
```bash
cargo run --example simple_multicast
```

**Features:**
- Basic multicast publishing
- Position updates with movement simulation
- Contact information and precision location
- Custom XML details

### 2. TAK Server Connection (`takserver_connection.rs`)

Demonstrates connecting to a TAK Server over TLS with client certificate authentication.

**Run:**
```bash
cargo run --example takserver_connection
```

**Setup Required:**
- Update the TAK Server URL in the example
- Provide valid client certificate and key files
- Provide the TAK Server root CA certificate

**Features:**
- TLS/mTLS connection to TAK Server
- Connection health checking
- Multiple message publishing
- Certificate loading from files or strings

### 3. Blocking Multicast (`blocking_multicast.rs`)

Demonstrates using the blocking API for applications that don't use async/await.

**Run:**
```bash
cargo run --example blocking_multicast --features blocking
```

**Features:**
- Synchronous/blocking API usage
- No async runtime required in user code
- Standard `std::thread::sleep` usage
- Position updates with custom XML details

## Configuration

### Multicast Address

The standard TAK multicast address is `239.2.3.1:6969`. You can change this to any valid multicast address in the examples.

### TAK Server Connection

For the `takserver_connection` example, you'll need:

1. **Client Certificate** (`client-cert.pem`)
2. **Client Private Key** (`client-key.pem`) - should be unencrypted or use `from_encrypted_pem()`
3. **Root CA Certificate** (`truststore-root.pem`)

These can be generated using the TAK Server's `makeCert.sh` script:

```bash
cd /opt/tak/certs
sh -c "source ./makeCert.sh client [username]"
```

To remove password protection from the key:
```bash
openssl rsa -in user.key -out user-nopass.key
```

## CoT Type Codes

Common CoT type codes used in the examples:

- `a-f-G-E-V-C` - Friendly Ground Equipment (Vehicle/Car)
- `a-f-G-E-S` - Friendly Ground Equipment (Sensor)
- `a-f-G-U-C` - Friendly Ground Unit (Combat)

Format: `a-[affiliation]-[dimension]-[function]-[subcategory]`

## Logging

All examples support logging via the `env_logger` crate. Set the `RUST_LOG` environment variable:

```bash
RUST_LOG=info cargo run --example simple_multicast
RUST_LOG=debug cargo run --example takserver_connection
```

## Testing Multicast

To test multicast reception, you can use tools like:

- **ATAK** (Android Team Awareness Kit)
- **WinTAK** (Windows TAK client)
- **iTAK** (iOS TAK client)
- **tcpdump** for raw packet inspection:
  ```bash
  sudo tcpdump -i any -n "dst host 239.2.3.1 and port 6969"
  ```

## Common Issues

### Multicast not received
- Check firewall settings
- Ensure multicast routing is enabled
- Verify network interface supports multicast
- Use `new_multicast_bind()` to specify interface

### TAK Server connection fails
- Verify server URL and port
- Check certificate paths
- Ensure certificates are valid and not expired
- Try `ignore_invalid: true` for testing (not for production!)

### Blocking example doesn't compile
- Make sure to enable the `blocking` feature:
  ```bash
  cargo run --example blocking_multicast --features blocking
  ```
