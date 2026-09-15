# Changelog — `armature-azure`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

### Security

- The `servicebus` feature no longer depends on `azure_messaging_servicebus` 0.21 and the legacy `azure_core` 0.21 it requires. That `azure_core` writes the outgoing `authorization` header — a live SAS token — to logs whenever debug or trace logging is enabled (RUSTSEC-2026-0275); it also pulled in `http-types` 2.12 (RUSTSEC-2026-0174) and `rand` 0.7 (RUSTSEC-2026-0097). Service Bus now talks to the REST API directly and never logs headers or credentials; errors carry only the method, path and status.

### Changed

- **Breaking:** `ServiceBusClient::queue`/`topic` return this crate's `QueueClient`/`TopicClient` instead of the SDK's, and `azure_messaging_servicebus` is no longer re-exported. The operations are the same — `send_message`, `receive_and_delete_message`, `peek_lock_message`, `peek_lock_message2` — with these differences: `TopicClient::topic_sender`/`subscription_receiver` return `Result`; `PeekLockResponse::body` returns `&str`, `status` returns `u16`, `headers` replaces the generic `custom_properties`, and `delete_message` returns `()`; `BrokerProperties` fields other than `delivery_count` are `Option`s and timestamps are `SystemTime`; `SettableBrokerProperties::scheduled_enqueue_time_utc` is a `SystemTime`. Errors are `AzureError` (`Auth` for 401/403, `Service` for other statuses, `Network` for transport failures).
- Added `ServiceBusClient::with_endpoint` to target the Service Bus emulator or a test server, and `has_message` on `PeekLockResponse`.
- The `servicebus` feature's HTTP transport moved from `reqwest` 0.12 to 0.13 (rustls only).
