# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Synced vendored TAK protocol definitions (`cotevent.proto`, `detail.proto`,
  `takcontrol.proto`) with upstream, adding `CotEvent.caveat`,
  `CotEvent.releasableTo`, `TakControl.extension_ids`, and
  `Detail.extension_details`. `rpc_from_cot` updated to populate the new
  required fields with empty defaults.
- `CotPublisher::check_connected()` now distinguishes "connected" from
  "reconnecting" for TAK server publishers, instead of only knowing whether
  the background task is alive.

### Changed

- `check_connected()` now returns the real error from a failed publish task
  instead of a generic message.
- Protobuf encode failures now notify `publish_checked()` /
  `blocking_publish_checked()` callers with the real cause instead of
  silently dropping the message.

### Fixed

- Fixed a panic in `Credentials::from_encrypted_pem` on a wrong password or
  unsupported key format.
- Fixed `blocking::CotPublisher` leaking a busy-spinning background thread
  on drop.
- Fixed a reconnect-storm bug where a closed channel could cause endless
  TAK server reconnect attempts.

### Deprecated

- `TakServerSetting::verify_hostname` — never read, has no effect. Hostname
  verification is only controllable via `ignore_invalid`.
