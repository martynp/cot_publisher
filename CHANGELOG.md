# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.1.0] - 2026-07-14

### Added

- Synced vendored TAK protocol definitions (`cotevent.proto`, `detail.proto`,
  `takcontrol.proto`) with upstream, adding `CotEvent.caveat`,
  `CotEvent.releasableTo`, `TakControl.extension_ids`, and
  `Detail.extension_details`. `rpc_from_cot` updated to populate the new
  required fields with empty defaults.
- `CotPublisher::check_connected()` now distinguishes "connected" from
  "reconnecting" for TAK server publishers, instead of only knowing whether
  the background task is alive.
- TAK server connections now implement the real "Streaming Connection
  Protocol Negotiation" handshake from `takproto/README.md`: the client
  waits for the server's `TakProtocolSupport` advertisement before
  requesting an upgrade, reuses the server-provided protouid, and waits for
  the server's `TakResponse` before switching to binary TAK Protocol
  Streaming framing. Connections to servers that never advertise support
  (or that deny the request) now correctly stay on plain CoT XML for their
  lifetime instead of assuming binary framing. Added `quick-xml` as a
  dependency to parse/build the negotiation XML.
- The blocking `CotPublisher` now exposes `check_connected()` and actually
  tracks live connection state (previously it only knew whether the
  background thread was alive), matching the async API.
- A GitHub Actions CI workflow (`.github/workflows/ci.yml`) now builds,
  tests, lints (clippy), and format-checks the crate on every push/PR to
  `main`, with an additional MSRV (1.85.1) build check.

### Changed

- `check_connected()` now returns the real error from a failed publish task
  instead of a generic message.
- Protobuf encode failures now notify `publish_checked()` /
  `blocking_publish_checked()` callers with the real cause instead of
  silently dropping the message.
- Unknown/unset position and accuracy values are now emitted using the CoT
  convention of `9999999` for `ce`/`le` instead of `0.0`, matching how
  TAK clients interpret "no accuracy information available".
- The `blocking_multicast` example is now feature-gated in `Cargo.toml`
  (`required-features = ["blocking"]`), so `cargo build --all-targets` with
  default features no longer fails trying to compile it.
- README code examples audited and fixed so they compile against the
  current public API (missing `reconnect_delay` field, `Source` vs
  `Option<Source>` mismatch, undefined variable in the embedded-certificate
  snippet, and stale `2.0.0-rc1`/`2.0.0-rc2` version pins).

### Fixed

- Fixed a panic in `Credentials::from_encrypted_pem` on a wrong password or
  unsupported key format.
- Fixed `blocking::CotPublisher` leaking a busy-spinning background thread
  on drop.
- Fixed a reconnect-storm bug where a closed channel could cause endless
  TAK server reconnect attempts.
- Fixed TAK server publishing sending a malformed, non-conformant control
  message on connect: the literal placeholder text `uid='protouid'` and
  `time='TIME'` from the README's illustrative example was being sent
  verbatim instead of a real reused protouid and real timestamps, with no
  `<?xml ...?>` header and a trailing newline the spec forbids after
  `</event>`. Superseded by the real negotiation handshake (see Added).
- Fixed `TakControl.min_proto_version`/`max_proto_version` being hardcoded
  to `2`, contradicting the rest of the implementation (the UDP mesh header
  and the TAK Protocol negotiation both use version `1`, and the README
  only defines TAK Protocol Payload Version 1). Now correctly `1`.
- Fixed `TakServerSetting::verify_hostname` to actually take effect. When
  `false` (and `ignore_invalid` is not set), the server certificate chain
  of trust and expiry are still validated, but the hostname/SAN match is
  skipped - previously this field was read nowhere and had no effect.
- Fixed binary-stream leftover-buffer ordering that could corrupt framing
  when the server pipelines its negotiation response together with binary
  TAK Protocol frames in the same TCP segment.
- Fixed a leaked background reader task and socket after binary-mode
  shutdown.
- Bounded the XML read buffer during negotiation against unbounded memory
  growth from a misbehaving or malicious server.
- Fixed overlong-varint length parsing in the binary TAK Protocol framing.
- Fixed a `select!`-starvation bug where a flood of incoming reads could
  prevent outgoing publishes (or vice versa) from ever being polled.
- The publisher drop is now noticed while waiting for the negotiation
  response, instead of blocking until a server reply (or timeout) arrives.

## [2.0.0] - 2025-11-04

Version 2 rewrite of the crate.

### Added

- Async and blocking `CotPublisher` APIs for both multicast UDP and TAK
  Server (TCP/TLS) publishing.
- TLS/mTLS support for TAK Server connections, including loading client
  certificates and keys from files or in-memory PEM strings
  (`Credentials::from_unencrypted_pem` / `from_encrypted_pem`).
- Protobuf-based TAK Protocol message encoding via vendored/generated
  `cotevent.proto`, `detail.proto`, and `takcontrol.proto` definitions.
- Automatic reconnect handling for TAK Server connections.
- `emit_errors` feature for optional error logging via the `log` crate.

### Changed

- Substantial rewrite of the public API compared to the 1.x line (see the
  2.0.0-rc1/rc2 pre-releases for interim history).
