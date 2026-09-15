# Changelog — `armature-azure`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

## [0.3.0] - 2026-09-15

### Security

- Settle requests (`delete_message`, `unlock_message`, `renew_message_lock`) only go to a lock location on the entity's own origin and path; a `Location` header pointing anywhere else is refused, so a hostile or misconfigured endpoint cannot collect a SAS token. The HTTP client does not follow redirects.
- The `servicebus` feature no longer depends on `azure_messaging_servicebus` 0.21 and the legacy `azure_core` 0.21 it requires. That `azure_core` writes the outgoing `authorization` header — a live SAS token — to logs whenever debug or trace logging is enabled (RUSTSEC-2026-0275); it also pulled in `http-types` 2.12 (RUSTSEC-2026-0174) and `rand` 0.7 (RUSTSEC-2026-0097). Service Bus now talks to the REST API directly and never logs headers or credentials; errors carry only the method, path and status.

### Changed

- **Breaking:** `ServiceBusClient::queue`/`topic` return this crate's `QueueClient`/`TopicClient` instead of the SDK's, and `azure_messaging_servicebus` is no longer re-exported. Differences from the SDK types:
  - `peek_lock_message2` is renamed `peek_lock`; `receive_and_delete_message` and `peek_lock_message` keep their names.
  - `TopicClient::topic_sender` is unchanged in shape; `subscription_receiver` returns `Result` (the subscription name is validated).
  - `PeekLockResponse::body` returns `&str`, `status` returns `u16`, `broker_properties` returns `Option<&BrokerProperties>` (borrowed, not cloned), `headers` replaces the generic `custom_properties`, and `delete_message` returns `()`.
  - `BrokerProperties` fields other than `delivery_count` are `Option`s and timestamps are `SystemTime`; `SettableBrokerProperties::scheduled_enqueue_time_utc` is a `SystemTime`.
  - `BrokerProperties`, `SendMessageOptions` and `SettableBrokerProperties` are `#[non_exhaustive]`: build the latter two with `new()` and their setters (`content_type`, `broker_properties`, `custom_property`; one setter per broker property).
  - Errors are `AzureError`: `Auth` for 401/403, the new `Http { status, message }` for other statuses, `Network` for transport failures.
- **Breaking:** `AzureError` gains the `Http { status, message }` variant, with `status()` and `is_retryable()` (true for transport failures and 408/429/500/502/503/504).
- Added `ServiceBusClient::with_endpoint` to target the Service Bus emulator or a test server. It returns `Result` and accepts only `https`, or `http` on a loopback host.
- Added `PeekLockResponse::has_message`.
- Peek-lock waits shorter than a second are rounded up to one second instead of being sent as `timeout=0`.
- The `servicebus` feature's HTTP transport moved from `reqwest` 0.12 to 0.13 (rustls only).

