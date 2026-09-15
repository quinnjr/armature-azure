//! Azure Service Bus client over the Service Bus REST API.
//!
//! Requests go straight to `https://<namespace>.servicebus.windows.net` and are
//! authenticated with a Shared Access Signature (SAS) generated per request from
//! the policy name + key. This replaces the legacy `azure_messaging_servicebus`
//! 0.21 SDK, whose `azure_core` 0.21 writes the outgoing `authorization` header —
//! a live SAS token — to logs whenever debug or trace logging is enabled
//! (RUSTSEC-2026-0275). Nothing in this module logs request headers or
//! credentials, and error messages carry only the method, path and status.
//!
//! [`ServiceBusClient`] is namespace-scoped and vends per-entity clients:
//! [`QueueClient`] for queues and [`TopicClient`] for topics, whose
//! [`TopicSender`] publishes and whose [`SubscriptionReceiver`] consumes from a
//! subscription.

use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, LOCATION};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

use crate::{AzureError, Result};

/// Lifetime of each generated SAS token.
const SAS_TTL: Duration = Duration::from_secs(3_600);

/// Per-request timeout, so a hung or unreachable namespace cannot block callers
/// indefinitely. Peek-lock requests add their server-side wait on top.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

const BROKER_PROPERTIES: &str = "brokerproperties";

/// Longest error-body excerpt copied into an [`AzureError`].
const ERROR_BODY_LIMIT: usize = 512;

/// Per-service configuration for Service Bus, read from
/// `AzureConfig::service_config("servicebus")` when no
/// `servicebus_connection_string` is set.
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceBusServiceConfig {
    /// Service Bus namespace (falls back to `AzureConfig::servicebus_namespace`).
    #[serde(default)]
    pub namespace: Option<String>,
    /// Shared Access Signature policy name (e.g. `RootManageSharedAccessKey`).
    pub policy_name: String,
    /// Shared Access Signature key.
    pub shared_access_key: String,
}

/// Namespace-scoped Azure Service Bus client.
///
/// Clone-cheap: it holds a pooled `reqwest::Client` and the SAS material, and
/// builds a [`QueueClient`]/[`TopicClient`] per entity on request.
#[derive(Clone)]
pub struct ServiceBusClient {
    namespace: String,
    policy_name: String,
    shared_access_key: String,
    endpoint: String,
    http: reqwest::Client,
}

impl ServiceBusClient {
    fn build_http_client() -> reqwest::Client {
        reqwest::Client::builder()
            .build()
            // Building only fails if the TLS backend cannot be initialized.
            .expect("failed to build Service Bus HTTP client")
    }

    /// Create a client from an explicit namespace + SAS policy.
    pub fn new(
        namespace: impl Into<String>,
        policy_name: impl Into<String>,
        shared_access_key: impl Into<String>,
    ) -> Self {
        let namespace = namespace.into();
        let endpoint = format!("https://{namespace}.servicebus.windows.net");
        Self {
            namespace,
            policy_name: policy_name.into(),
            shared_access_key: shared_access_key.into(),
            endpoint,
            http: Self::build_http_client(),
        }
    }

    /// Parse a Service Bus connection string of the form
    /// `Endpoint=sb://<namespace>.servicebus.windows.net/;SharedAccessKeyName=<policy>;SharedAccessKey=<key>`.
    pub fn from_connection_string(conn: &str) -> Result<Self> {
        let mut endpoint = None;
        let mut policy_name = None;
        let mut shared_access_key = None;

        for part in conn.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            // Split on the FIRST '=' only: the base64 SAS key itself may contain '='.
            let (key, value) = part.split_once('=').ok_or_else(|| {
                // Only reached when the segment has no '=', so it is unstructured and
                // could be a bare, unpadded SAS key. Never echo the raw segment into
                // the error (and thus logs) — report a redacted placeholder instead.
                AzureError::Config(
                    "invalid Service Bus connection string segment (missing '='): <redacted>"
                        .to_string(),
                )
            })?;
            match key.trim().to_ascii_lowercase().as_str() {
                "endpoint" => endpoint = Some(value.trim().to_string()),
                "sharedaccesskeyname" => policy_name = Some(value.trim().to_string()),
                "sharedaccesskey" => shared_access_key = Some(value.trim().to_string()),
                _ => {}
            }
        }

        let endpoint = endpoint.ok_or_else(|| {
            AzureError::Config("Service Bus connection string missing 'Endpoint'".to_string())
        })?;
        let namespace = parse_namespace(&endpoint)?;
        let policy_name = policy_name.ok_or_else(|| {
            AzureError::Config(
                "Service Bus connection string missing 'SharedAccessKeyName'".to_string(),
            )
        })?;
        let shared_access_key = shared_access_key.ok_or_else(|| {
            AzureError::Config(
                "Service Bus connection string missing 'SharedAccessKey'".to_string(),
            )
        })?;

        Ok(Self::new(namespace, policy_name, shared_access_key))
    }

    /// Send requests to `endpoint` instead of
    /// `https://<namespace>.servicebus.windows.net`, e.g. the Service Bus
    /// emulator or a local test server.
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into().trim_end_matches('/').to_string();
        self
    }

    /// The Service Bus namespace this client targets.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Get a [`QueueClient`] for the named queue.
    pub fn queue(&self, queue: impl Into<String>) -> Result<QueueClient> {
        let queue = queue.into();
        Ok(QueueClient {
            entity: Entity::new(self.clone(), &queue, None)?,
            queue,
        })
    }

    /// Get a [`TopicClient`] for the named topic.
    pub fn topic(&self, topic: impl Into<String>) -> Result<TopicClient> {
        let topic = topic.into();
        Entity::new(self.clone(), &topic, None)?;
        Ok(TopicClient {
            client: self.clone(),
            topic,
        })
    }

    /// Build the `Authorization` header value for a request under `scope`.
    fn authorization(&self, scope: &str) -> Result<HeaderValue> {
        let expiry = SystemTime::now()
            .checked_add(SAS_TTL)
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .ok_or_else(|| AzureError::Auth("system clock is before the UNIX epoch".to_string()))?;
        let token = sas_token(scope, &self.policy_name, &self.shared_access_key, expiry);
        let mut value = HeaderValue::from_str(&token)
            .map_err(|_| AzureError::Auth("SAS token is not a valid header value".to_string()))?;
        value.set_sensitive(true);
        Ok(value)
    }
}

impl std::fmt::Debug for ServiceBusClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceBusClient")
            .field("namespace", &self.namespace)
            .field("policy_name", &self.policy_name)
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

/// Build a Service Bus SAS token (`SharedAccessSignature sr=..&sig=..&se=..&skn=..`)
/// for the resource URI `scope`, valid until the UNIX time `expiry`.
fn sas_token(scope: &str, policy_name: &str, key: &str, expiry: u64) -> String {
    let sr: String = url::form_urlencoded::byte_serialize(scope.as_bytes()).collect();
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .expect("HMAC-SHA256 accepts keys of any length");
    mac.update(format!("{sr}\n{expiry}").as_bytes());
    let sig = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    let sig: String = url::form_urlencoded::byte_serialize(sig.as_bytes()).collect();
    let skn: String = url::form_urlencoded::byte_serialize(policy_name.as_bytes()).collect();
    format!("SharedAccessSignature sr={sr}&sig={sig}&se={expiry}&skn={skn}")
}

/// A queue, topic or topic subscription addressed through one namespace client.
#[derive(Clone)]
struct Entity {
    client: ServiceBusClient,
    /// Entity root, e.g. `https://ns.servicebus.windows.net/orders`; the SAS scope.
    root: Url,
}

impl Entity {
    fn new(client: ServiceBusClient, name: &str, subscription: Option<&str>) -> Result<Self> {
        validate_name("entity", name)?;
        if let Some(sub) = subscription {
            validate_name("subscription", sub)?;
        }
        let mut root = Url::parse(&client.endpoint).map_err(|e| {
            AzureError::Config(format!(
                "invalid Service Bus endpoint '{}': {e}",
                client.endpoint
            ))
        })?;
        {
            let mut segments = root.path_segments_mut().map_err(|()| {
                AzureError::Config(format!(
                    "Service Bus endpoint '{}' cannot carry a path",
                    client.endpoint
                ))
            })?;
            segments.pop_if_empty().extend(name.split('/'));
            if let Some(sub) = subscription {
                segments.extend(["subscriptions", sub]);
            }
        }
        Ok(Self { client, root })
    }

    fn url(&self, tail: &[&str]) -> Url {
        let mut url = self.root.clone();
        url.path_segments_mut()
            .expect("entity root is a hierarchical URL")
            .extend(tail);
        url
    }

    fn scope(&self) -> &str {
        self.root.as_str()
    }

    async fn execute(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Option<String>,
        timeout: Duration,
    ) -> Result<reqwest::Response> {
        execute(
            &self.client,
            self.scope(),
            method,
            url,
            headers,
            body,
            timeout,
        )
        .await
    }

    async fn send_message(&self, body: &str, options: Option<SendMessageOptions>) -> Result<()> {
        let headers = options.unwrap_or_default().to_headers()?;
        self.execute(
            Method::POST,
            self.url(&["messages"]),
            headers,
            Some(body.to_string()),
            REQUEST_TIMEOUT,
        )
        .await?;
        Ok(())
    }

    async fn receive_and_delete_message(&self) -> Result<String> {
        let response = self
            .execute(
                Method::DELETE,
                self.url(&["messages", "head"]),
                HeaderMap::new(),
                None,
                REQUEST_TIMEOUT,
            )
            .await?;
        read_body(response).await
    }

    async fn peek_lock(&self, timeout: Option<Duration>) -> Result<reqwest::Response> {
        let mut url = self.url(&["messages", "head"]);
        let mut request_timeout = REQUEST_TIMEOUT;
        if let Some(wait) = timeout {
            url.query_pairs_mut()
                .append_pair("timeout", &wait.as_secs().to_string());
            request_timeout += wait;
        }
        self.execute(Method::POST, url, HeaderMap::new(), None, request_timeout)
            .await
    }

    async fn peek_lock_message(&self, timeout: Option<Duration>) -> Result<String> {
        read_body(self.peek_lock(timeout).await?).await
    }

    async fn peek_lock_message2(&self, timeout: Option<Duration>) -> Result<PeekLockResponse> {
        let response = self.peek_lock(timeout).await?;
        let status = response.status().as_u16();
        let lock_location = match response.headers().get(LOCATION) {
            Some(value) => {
                let location = value.to_str().map_err(|_| {
                    AzureError::Service("Service Bus lock location is not valid UTF-8".to_string())
                })?;
                Some(Url::parse(location).map_err(|e| {
                    AzureError::Service(format!("invalid Service Bus lock location: {e}"))
                })?)
            }
            None => None,
        };
        let broker_properties = match response.headers().get(BROKER_PROPERTIES) {
            Some(value) => {
                let raw = value.to_str().map_err(|_| {
                    AzureError::Service("BrokerProperties header is not valid UTF-8".to_string())
                })?;
                Some(serde_json::from_str(raw).map_err(|e| {
                    AzureError::Serialization(format!("invalid BrokerProperties header: {e}"))
                })?)
            }
            None => None,
        };
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.as_str().to_string(), v.to_string()))
            })
            .collect();
        let body = read_body(response).await?;
        Ok(PeekLockResponse {
            body,
            headers,
            broker_properties,
            lock_location,
            status,
            entity: self.clone(),
        })
    }
}

async fn execute(
    client: &ServiceBusClient,
    scope: &str,
    method: Method,
    url: Url,
    mut headers: HeaderMap,
    body: Option<String>,
    timeout: Duration,
) -> Result<reqwest::Response> {
    headers.insert(reqwest::header::AUTHORIZATION, client.authorization(scope)?);
    let path = url.path().to_string();
    let mut request = client
        .http
        .request(method.clone(), url)
        .headers(headers)
        .timeout(timeout);
    request = match body {
        Some(body) => request.body(body),
        None => request.header(reqwest::header::CONTENT_LENGTH, "0"),
    };
    let response = request.send().await.map_err(|e| {
        AzureError::Network(format!(
            "Service Bus {method} {path} failed: {}",
            e.without_url()
        ))
    })?;
    check_status(&method, &path, response).await
}

async fn check_status(
    method: &Method,
    path: &str,
    response: reqwest::Response,
) -> Result<reqwest::Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let mut body = response.text().await.unwrap_or_default();
    if body.len() > ERROR_BODY_LIMIT {
        let mut end = ERROR_BODY_LIMIT;
        while !body.is_char_boundary(end) {
            end -= 1;
        }
        body.truncate(end);
    }
    let kind = match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => AzureError::Auth,
        _ => AzureError::Service,
    };
    Err(kind(format!(
        "Service Bus {method} {path} returned {status}: {}",
        body.trim()
    )))
}

async fn read_body(response: reqwest::Response) -> Result<String> {
    response.text().await.map_err(|e| {
        AzureError::Network(format!(
            "failed to read Service Bus response: {}",
            e.without_url()
        ))
    })
}

fn validate_name(what: &str, name: &str) -> Result<()> {
    if name.is_empty() || name.split('/').any(str::is_empty) {
        return Err(AzureError::Config(format!(
            "Service Bus {what} name '{name}' is empty or has an empty path segment"
        )));
    }
    Ok(())
}

/// Extract the namespace from a Service Bus endpoint such as
/// `sb://mybus.servicebus.windows.net/` -> `mybus`.
fn parse_namespace(endpoint: &str) -> Result<String> {
    let host = endpoint
        .rsplit("://")
        .next()
        .unwrap_or(endpoint)
        .trim_end_matches('/');
    let namespace = host.split('.').next().unwrap_or(host);
    if namespace.is_empty() {
        return Err(AzureError::Config(format!(
            "could not parse namespace from Service Bus endpoint '{endpoint}'"
        )));
    }
    Ok(namespace.to_string())
}

/// Client for a single Service Bus queue.
#[derive(Clone)]
pub struct QueueClient {
    entity: Entity,
    queue: String,
}

impl QueueClient {
    /// The queue name.
    pub fn name(&self) -> &str {
        &self.queue
    }

    /// Send a message to the queue.
    pub async fn send_message(&self, msg: &str, options: Option<SendMessageOptions>) -> Result<()> {
        self.entity.send_message(msg, options).await
    }

    /// Receive and delete the message at the head of the queue.
    ///
    /// Returns an empty string when the queue is empty.
    pub async fn receive_and_delete_message(&self) -> Result<String> {
        self.entity.receive_and_delete_message().await
    }

    /// Lock the message at the head of the queue and return its body.
    ///
    /// `timeout` is how long the service waits for a message before answering
    /// with an empty body. The lock location is discarded, so the message is
    /// redelivered once the lock expires; use
    /// [`peek_lock_message2`](Self::peek_lock_message2) to settle it.
    pub async fn peek_lock_message(&self, timeout: Option<Duration>) -> Result<String> {
        self.entity.peek_lock_message(timeout).await
    }

    /// Lock the message at the head of the queue and keep its lock, so it can be
    /// completed, abandoned or renewed through the returned [`PeekLockResponse`].
    pub async fn peek_lock_message2(&self, timeout: Option<Duration>) -> Result<PeekLockResponse> {
        self.entity.peek_lock_message2(timeout).await
    }
}

impl std::fmt::Debug for QueueClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueueClient")
            .field("queue", &self.queue)
            .field("url", &self.entity.root.as_str())
            .finish_non_exhaustive()
    }
}

/// Client for a Service Bus topic.
#[derive(Clone)]
pub struct TopicClient {
    client: ServiceBusClient,
    topic: String,
}

impl TopicClient {
    /// The topic name.
    pub fn name(&self) -> &str {
        &self.topic
    }

    /// A sender that publishes to this topic.
    pub fn topic_sender(&self) -> Result<TopicSender> {
        Ok(TopicSender {
            entity: Entity::new(self.client.clone(), &self.topic, None)?,
        })
    }

    /// A receiver for one of this topic's subscriptions.
    pub fn subscription_receiver(&self, subscription: &str) -> Result<SubscriptionReceiver> {
        Ok(SubscriptionReceiver {
            entity: Entity::new(self.client.clone(), &self.topic, Some(subscription))?,
            subscription: subscription.to_string(),
        })
    }
}

impl std::fmt::Debug for TopicClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TopicClient")
            .field("topic", &self.topic)
            .finish_non_exhaustive()
    }
}

/// Publishes messages to a topic.
#[derive(Clone)]
pub struct TopicSender {
    entity: Entity,
}

impl TopicSender {
    /// Send a message to the topic.
    pub async fn send_message(&self, msg: &str, options: Option<SendMessageOptions>) -> Result<()> {
        self.entity.send_message(msg, options).await
    }
}

impl std::fmt::Debug for TopicSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TopicSender")
            .field("url", &self.entity.root.as_str())
            .finish_non_exhaustive()
    }
}

/// Consumes messages from a topic subscription.
#[derive(Clone)]
pub struct SubscriptionReceiver {
    entity: Entity,
    subscription: String,
}

impl SubscriptionReceiver {
    /// The subscription name.
    pub fn name(&self) -> &str {
        &self.subscription
    }

    /// Receive and delete the message at the head of the subscription.
    ///
    /// Returns an empty string when the subscription is empty.
    pub async fn receive_and_delete_message(&self) -> Result<String> {
        self.entity.receive_and_delete_message().await
    }

    /// Lock the message at the head of the subscription and return its body,
    /// discarding the lock location (see [`QueueClient::peek_lock_message`]).
    pub async fn peek_lock_message(&self, timeout: Option<Duration>) -> Result<String> {
        self.entity.peek_lock_message(timeout).await
    }

    /// Lock the message at the head of the subscription and keep its lock.
    pub async fn peek_lock_message2(&self, timeout: Option<Duration>) -> Result<PeekLockResponse> {
        self.entity.peek_lock_message2(timeout).await
    }
}

impl std::fmt::Debug for SubscriptionReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubscriptionReceiver")
            .field("url", &self.entity.root.as_str())
            .finish_non_exhaustive()
    }
}

/// A message locked by a peek-lock receive, with the operations that settle it.
pub struct PeekLockResponse {
    body: String,
    headers: HashMap<String, String>,
    broker_properties: Option<BrokerProperties>,
    lock_location: Option<Url>,
    status: u16,
    entity: Entity,
}

impl PeekLockResponse {
    /// The message body (empty when no message arrived before the timeout).
    pub fn body(&self) -> &str {
        &self.body
    }

    /// The broker properties of the locked message, if a message was locked.
    pub fn broker_properties(&self) -> Option<&BrokerProperties> {
        self.broker_properties.as_ref()
    }

    /// Response headers, keyed by lower-case name. Custom message properties
    /// arrive as headers.
    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    /// The HTTP status of the receive (`201` with a message, `204` without).
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Whether a message was locked.
    pub fn has_message(&self) -> bool {
        self.lock_location.is_some()
    }

    fn lock_url(&self) -> Result<Url> {
        self.lock_location
            .clone()
            .ok_or_else(|| AzureError::Service("no Service Bus message is locked".to_string()))
    }

    async fn settle(&self, method: Method) -> Result<()> {
        self.entity
            .execute(
                method,
                self.lock_url()?,
                HeaderMap::new(),
                None,
                REQUEST_TIMEOUT,
            )
            .await?;
        Ok(())
    }

    /// Complete (delete) the locked message.
    pub async fn delete_message(&self) -> Result<()> {
        self.settle(Method::DELETE).await
    }

    /// Abandon the lock so the message becomes available again.
    pub async fn unlock_message(&self) -> Result<()> {
        self.settle(Method::PUT).await
    }

    /// Renew the lock on the message.
    pub async fn renew_message_lock(&self) -> Result<()> {
        self.settle(Method::POST).await
    }
}

impl std::fmt::Debug for PeekLockResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeekLockResponse")
            .field("status", &self.status)
            .field("broker_properties", &self.broker_properties)
            .field("has_message", &self.has_message())
            .finish_non_exhaustive()
    }
}

/// Broker properties the service reports for a received message.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct BrokerProperties {
    /// Number of times the message has been delivered.
    pub delivery_count: i32,
    /// Sequence number assigned when the message was enqueued.
    pub enqueued_sequence_number: Option<i64>,
    /// When the message was enqueued.
    #[serde(deserialize_with = "deserialize_http_date")]
    pub enqueued_time_utc: Option<SystemTime>,
    /// Lock token (peek-lock receives only).
    pub lock_token: Option<String>,
    /// When the lock expires (peek-lock receives only).
    #[serde(deserialize_with = "deserialize_http_date")]
    pub locked_until_utc: Option<SystemTime>,
    /// Message identifier.
    pub message_id: Option<String>,
    /// Sequence number.
    pub sequence_number: Option<i64>,
    /// Message state, e.g. `Active`.
    pub state: Option<String>,
    /// Time to live, in seconds.
    pub time_to_live: Option<f64>,
    /// Correlation identifier.
    pub correlation_id: Option<String>,
    /// Session identifier.
    pub session_id: Option<String>,
    /// Application label.
    pub label: Option<String>,
    /// Reply-to address.
    pub reply_to: Option<String>,
    /// Destination address.
    pub to: Option<String>,
}

/// Options for sending a message.
#[derive(Clone, Debug, Default)]
pub struct SendMessageOptions {
    /// `Content-Type` of the body.
    pub content_type: Option<String>,
    /// Broker properties to set on the message.
    pub broker_properties: Option<SettableBrokerProperties>,
    /// Custom message properties, sent as headers.
    pub custom_properties: Option<HashMap<String, String>>,
}

impl SendMessageOptions {
    fn to_headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        if let Some(content_type) = &self.content_type {
            headers.insert(CONTENT_TYPE, header_value("Content-Type", content_type)?);
        }
        if let Some(props) = &self.broker_properties {
            let json = serde_json::to_string(props)
                .map_err(|e| AzureError::Serialization(format!("BrokerProperties: {e}")))?;
            headers.insert(
                HeaderName::from_static(BROKER_PROPERTIES),
                header_value("BrokerProperties", &json)?,
            );
        }
        for (name, value) in self.custom_properties.iter().flatten() {
            let header = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                AzureError::Config(format!("invalid Service Bus custom property name '{name}'"))
            })?;
            headers.insert(header, header_value(name, value)?);
        }
        Ok(headers)
    }
}

fn header_value(name: &str, value: &str) -> Result<HeaderValue> {
    HeaderValue::from_str(value)
        .map_err(|_| AzureError::Config(format!("invalid value for Service Bus header '{name}'")))
}

/// Broker properties that can be set when sending a message.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SettableBrokerProperties {
    /// Correlation identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Session identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Message identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    /// Application label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Reply-to address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    /// Time to live.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_seconds"
    )]
    pub time_to_live: Option<Duration>,
    /// Destination address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// Enqueue the message at this time instead of immediately.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_http_date"
    )]
    pub scheduled_enqueue_time_utc: Option<SystemTime>,
    /// Session to reply to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to_session_id: Option<String>,
    /// Partition key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition_key: Option<String>,
}

fn serialize_seconds<S: Serializer>(
    value: &Option<Duration>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    match value {
        Some(duration) => serializer.serialize_f64(duration.as_secs_f64()),
        None => serializer.serialize_none(),
    }
}

fn serialize_http_date<S: Serializer>(
    value: &Option<SystemTime>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    match value {
        Some(time) => serializer.serialize_str(&httpdate::fmt_http_date(*time)),
        None => serializer.serialize_none(),
    }
}

fn deserialize_http_date<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<SystemTime>, D::Error> {
    match Option::<String>::deserialize(deserializer)? {
        Some(raw) => httpdate::parse_http_date(&raw)
            .map(Some)
            .map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string, header, header_exists, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const KEY: &str = "c2VjcmV0LWtleQ==";

    fn client_for(server: &MockServer) -> ServiceBusClient {
        ServiceBusClient::new("mybus", "RootManageSharedAccessKey", KEY).with_endpoint(server.uri())
    }

    #[test]
    fn from_connection_string_parses_namespace_policy_key() {
        let conn = "Endpoint=sb://mybus.servicebus.windows.net/;\
                    SharedAccessKeyName=RootManageSharedAccessKey;\
                    SharedAccessKey=abc123def456==";
        let client = ServiceBusClient::from_connection_string(conn).expect("parse");
        assert_eq!(client.namespace(), "mybus");
        assert_eq!(client.policy_name, "RootManageSharedAccessKey");
        // The base64 key contains '=' which must survive split_once-on-first-'='.
        assert_eq!(client.shared_access_key, "abc123def456==");
        assert_eq!(client.endpoint, "https://mybus.servicebus.windows.net");
    }

    #[test]
    fn from_connection_string_rejects_missing_key() {
        let conn = "Endpoint=sb://mybus.servicebus.windows.net/;\
                    SharedAccessKeyName=RootManageSharedAccessKey";
        assert!(ServiceBusClient::from_connection_string(conn).is_err());
    }

    #[test]
    fn builds_entity_urls() {
        let client = ServiceBusClient::new("mybus", "policy", KEY);
        let queue = client.queue("orders").expect("queue");
        assert_eq!(
            queue.entity.url(&["messages", "head"]).as_str(),
            "https://mybus.servicebus.windows.net/orders/messages/head"
        );
        let receiver = client
            .topic("events")
            .and_then(|t| t.subscription_receiver("audit"))
            .expect("receiver");
        assert_eq!(
            receiver.entity.scope(),
            "https://mybus.servicebus.windows.net/events/subscriptions/audit"
        );
        assert!(client.queue("").is_err());
        assert!(client.queue("a//b").is_err());
        assert!(
            client
                .topic("events")
                .unwrap()
                .subscription_receiver("")
                .is_err()
        );
    }

    #[test]
    fn sas_token_signs_the_encoded_scope_and_expiry() {
        let scope = "https://mybus.servicebus.windows.net/orders";
        let token = sas_token(scope, "RootManageSharedAccessKey", KEY, 1_700_000_000);

        let sr = "https%3A%2F%2Fmybus.servicebus.windows.net%2Forders";
        let mut mac = Hmac::<Sha256>::new_from_slice(KEY.as_bytes()).unwrap();
        mac.update(format!("{sr}\n1700000000").as_bytes());
        let sig = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        let sig: String = url::form_urlencoded::byte_serialize(sig.as_bytes()).collect();

        assert_eq!(
            token,
            format!(
                "SharedAccessSignature sr={sr}&sig={sig}&se=1700000000&skn=RootManageSharedAccessKey"
            )
        );
    }

    #[test]
    fn debug_output_redacts_the_key() {
        let client = ServiceBusClient::new("mybus", "policy", "super-secret-key");
        assert!(!format!("{client:?}").contains("super-secret-key"));
    }

    #[tokio::test]
    async fn send_message_posts_body_with_sas_and_broker_properties() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/orders/messages"))
            .and(header("content-type", "application/json"))
            // `header()` splits values on commas, so the JSON is asserted below.
            .and(header_exists("brokerproperties"))
            .and(header("priority", "high"))
            .and(header_exists("authorization"))
            .and(body_string(r#"{"id":1}"#))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&server)
            .await;

        let options = SendMessageOptions {
            content_type: Some("application/json".to_string()),
            broker_properties: Some(SettableBrokerProperties {
                message_id: Some("m-1".to_string()),
                label: Some("created".to_string()),
                ..Default::default()
            }),
            custom_properties: Some(HashMap::from([(
                "priority".to_string(),
                "high".to_string(),
            )])),
        };
        client_for(&server)
            .queue("orders")
            .unwrap()
            .send_message(r#"{"id":1}"#, Some(options))
            .await
            .expect("send");

        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests[0]
                .headers
                .get("brokerproperties")
                .unwrap()
                .to_str()
                .unwrap(),
            r#"{"MessageId":"m-1","Label":"created"}"#
        );
        let auth = requests[0]
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(auth.starts_with("SharedAccessSignature sr="));
        assert!(auth.contains("&skn=RootManageSharedAccessKey"));
    }

    #[tokio::test]
    async fn receive_and_delete_reads_the_queue_head() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/orders/messages/head"))
            .respond_with(ResponseTemplate::new(200).set_body_string("hello"))
            .mount(&server)
            .await;

        let body = client_for(&server)
            .queue("orders")
            .unwrap()
            .receive_and_delete_message()
            .await
            .expect("receive");
        assert_eq!(body, "hello");
    }

    #[tokio::test]
    async fn subscription_receiver_targets_the_subscription() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/events/subscriptions/audit/messages/head"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/events/messages"))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&server)
            .await;

        let topic = client_for(&server).topic("events").unwrap();
        topic
            .topic_sender()
            .unwrap()
            .send_message("evt", None)
            .await
            .expect("publish");
        let body = topic
            .subscription_receiver("audit")
            .unwrap()
            .receive_and_delete_message()
            .await
            .expect("receive");
        assert_eq!(body, "");
    }

    #[tokio::test]
    async fn peek_lock_settles_through_the_lock_location() {
        let server = MockServer::start().await;
        let lock_path = "/orders/messages/31907572-1647-43c3-8741-631acd554d6f/7da9cfd5-40d5-4bb1-8d64-ec5a52e1c547";
        Mock::given(method("POST"))
            .and(path("/orders/messages/head"))
            .and(query_param("timeout", "5"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_string("locked body")
                    .insert_header("Location", format!("{}{lock_path}", server.uri()).as_str())
                    .insert_header(
                        "BrokerProperties",
                        r#"{"DeliveryCount":2,"EnqueuedSequenceNumber":0,"EnqueuedTimeUtc":"Wed, 16 Sep 2026 12:00:00 GMT","LockToken":"7da9cfd5-40d5-4bb1-8d64-ec5a52e1c547","LockedUntilUtc":"Wed, 16 Sep 2026 12:01:00 GMT","MessageId":"m-1","SequenceNumber":11,"State":"Active","TimeToLive":922337203685.47754}"#,
                    )
                    .insert_header("priority", "high"),
            )
            .mount(&server)
            .await;
        for verb in ["DELETE", "PUT", "POST"] {
            Mock::given(method(verb))
                .and(path(lock_path))
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
                .mount(&server)
                .await;
        }

        let locked = client_for(&server)
            .queue("orders")
            .unwrap()
            .peek_lock_message2(Some(Duration::from_secs(5)))
            .await
            .expect("peek-lock");

        assert_eq!(locked.status(), 201);
        assert_eq!(locked.body(), "locked body");
        assert!(locked.has_message());
        assert_eq!(
            locked.headers().get("priority").map(String::as_str),
            Some("high")
        );
        let props = locked.broker_properties().expect("broker properties");
        assert_eq!(props.delivery_count, 2);
        assert_eq!(
            props.lock_token.as_deref(),
            Some("7da9cfd5-40d5-4bb1-8d64-ec5a52e1c547")
        );
        assert_eq!(props.sequence_number, Some(11));
        assert!(props.locked_until_utc.is_some());

        locked.renew_message_lock().await.expect("renew");
        locked.unlock_message().await.expect("unlock");
        locked.delete_message().await.expect("complete");
    }

    #[tokio::test]
    async fn empty_peek_lock_has_nothing_to_settle() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/orders/messages/head"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let locked = client_for(&server)
            .queue("orders")
            .unwrap()
            .peek_lock_message2(None)
            .await
            .expect("peek-lock");
        assert_eq!(locked.status(), 204);
        assert!(!locked.has_message());
        assert!(locked.delete_message().await.is_err());
    }

    #[tokio::test]
    async fn errors_carry_status_but_not_credentials() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/orders/messages"))
            .respond_with(
                ResponseTemplate::new(401).set_body_string("<Error><Code>401</Code></Error>"),
            )
            .mount(&server)
            .await;

        let err = client_for(&server)
            .queue("orders")
            .unwrap()
            .send_message("x", None)
            .await
            .expect_err("unauthorized");
        let text = err.to_string();
        assert!(matches!(err, AzureError::Auth(_)), "{text}");
        assert!(text.contains("401"), "{text}");
        assert!(!text.contains("SharedAccessSignature"), "{text}");
        assert!(!text.contains(KEY), "{text}");
    }
}
