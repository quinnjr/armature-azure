//! Azure Service Bus client over the Service Bus REST API.
//!
//! Requests go straight to `https://<namespace>.servicebus.windows.net` and are
//! authenticated with a Shared Access Signature (SAS) generated per request from
//! the policy name + key. This replaces the legacy `azure_messaging_servicebus`
//! 0.21 SDK, whose `azure_core` 0.21 writes the outgoing `authorization` header —
//! a live SAS token — to logs whenever debug or trace logging is enabled
//! (RUSTSEC-2026-0275). Nothing in this module logs request headers or
//! credentials, error messages carry only the method, path and status, and
//! credentials are only ever sent to the configured namespace endpoint.
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
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::{Host, Url};

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
///
/// # Delivery
///
/// Requests are not retried. A send that fails with [`AzureError::Network`] may
/// or may not have been enqueued; set [`SettableBrokerProperties::message_id`]
/// and enable duplicate detection on the entity before retrying sends.
/// [`AzureError::is_retryable`] tells transient failures (throttling, timeouts,
/// 5xx) apart from permanent ones.
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
            // Never follow redirects: a redirect is the one way a request carrying
            // a SAS token could be steered to a host other than the namespace.
            .redirect(reqwest::redirect::Policy::none())
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
    ///
    /// The endpoint must use `https`, except on a loopback host (`localhost`,
    /// `127.0.0.0/8`, `::1`), where `http` is accepted so SAS tokens never cross
    /// a network in cleartext. It may not carry a query or fragment.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Result<Self> {
        let raw = endpoint.into();
        let trimmed = raw.trim_end_matches('/');
        let url = Url::parse(trimmed).map_err(|e| {
            AzureError::Config(format!("invalid Service Bus endpoint '{trimmed}': {e}"))
        })?;
        match url.scheme() {
            "https" => {}
            "http" if is_loopback(&url) => {}
            scheme => {
                return Err(AzureError::Config(format!(
                    "Service Bus endpoint '{trimmed}' uses '{scheme}': only https, or http on a \
                     loopback host, is allowed"
                )));
            }
        }
        if url.cannot_be_a_base()
            || url.host().is_none()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(AzureError::Config(format!(
                "Service Bus endpoint '{trimmed}' must be a plain scheme://host[:port][/path] URL"
            )));
        }
        self.endpoint = trimmed.to_string();
        Ok(self)
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
        Ok(TopicClient {
            entity: Entity::new(self.clone(), &topic, None)?,
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

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
        Some(Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
        None => false,
    }
}

/// Build a Service Bus SAS token (`SharedAccessSignature sr=..&sig=..&se=..&skn=..`)
/// for the resource URI `scope`, valid until the UNIX time `expiry`.
///
/// The string to sign is the form-encoded resource URI, a newline, and the
/// expiry; the HMAC-SHA256 key is the raw bytes of the shared access key.
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

    fn subscription(&self, subscription: &str) -> Result<Self> {
        validate_name("subscription", subscription)?;
        let mut root = self.root.clone();
        root.path_segments_mut()
            .map_err(|()| {
                AzureError::Config("Service Bus entity URL cannot carry a path".to_string())
            })?
            .extend(["subscriptions", subscription]);
        Ok(Self {
            client: self.client.clone(),
            root,
        })
    }

    fn url(&self, tail: &[&str]) -> Url {
        let mut url = self.root.clone();
        if let Ok(mut segments) = url.path_segments_mut() {
            segments.extend(tail);
        }
        url
    }

    fn scope(&self) -> &str {
        self.root.as_str()
    }

    /// Accept a server-supplied lock location only if it addresses a message of
    /// this entity on the same origin, so a settle request can never carry this
    /// entity's SAS token to another host, port, scheme or entity.
    fn lock_location(&self, location: &str) -> Result<Url> {
        let url = Url::parse(location)
            .map_err(|e| AzureError::Service(format!("invalid Service Bus lock location: {e}")))?;
        let messages = format!("{}/messages/", self.root.path().trim_end_matches('/'));
        let same_origin = url.scheme() == self.root.scheme()
            && url.host_str() == self.root.host_str()
            && url.port_or_known_default() == self.root.port_or_known_default();
        if !same_origin || !url.path().starts_with(&messages) || url.fragment().is_some() {
            return Err(AzureError::Service(format!(
                "Service Bus returned a lock location outside {}; refusing to send credentials to it",
                self.root.path()
            )));
        }
        Ok(url)
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

    async fn peek_lock_request(&self, timeout: Option<Duration>) -> Result<reqwest::Response> {
        let mut url = self.url(&["messages", "head"]);
        let mut request_timeout = REQUEST_TIMEOUT;
        if let Some(wait) = timeout {
            // The service takes whole seconds; round up so a sub-second wait is
            // not silently turned into "return immediately".
            let secs = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
            url.query_pairs_mut()
                .append_pair("timeout", &secs.to_string());
            request_timeout = REQUEST_TIMEOUT.saturating_add(Duration::from_secs(secs));
        }
        self.execute(Method::POST, url, HeaderMap::new(), None, request_timeout)
            .await
    }

    async fn peek_lock_message(&self, timeout: Option<Duration>) -> Result<String> {
        read_body(self.peek_lock_request(timeout).await?).await
    }

    async fn peek_lock(&self, timeout: Option<Duration>) -> Result<PeekLockResponse> {
        let response = self.peek_lock_request(timeout).await?;
        let status = response.status().as_u16();
        let lock_location = match response.headers().get(LOCATION) {
            Some(value) => {
                let location = value.to_str().map_err(|_| {
                    AzureError::Service("Service Bus lock location is not valid UTF-8".to_string())
                })?;
                Some(self.lock_location(location)?)
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
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
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
    let mut body = match response.text().await {
        Ok(body) => body,
        Err(e) => format!("<response body unreadable: {}>", e.without_url()),
    };
    truncate_at_char_boundary(&mut body, ERROR_BODY_LIMIT);
    let message = format!(
        "Service Bus {method} {path} returned {status}: {}",
        body.trim()
    );
    Err(match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => AzureError::Auth(message),
        _ => AzureError::Http {
            status: status.as_u16(),
            message,
        },
    })
}

fn truncate_at_char_boundary(text: &mut String, limit: usize) {
    if text.len() > limit {
        let mut end = limit;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
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

/// The receive operations shared by queues and topic subscriptions, documented
/// once and generated into both [`QueueClient`] and [`SubscriptionReceiver`].
macro_rules! receive_operations {
    ($source:literal) => {
        #[doc = concat!("Receive and delete the message at the head of the ", $source, ".")]
        ///
        /// Returns an empty string when there is no message; a message with an
        /// empty body is indistinguishable from none, so use
        /// [`peek_lock`](Self::peek_lock) when that matters.
        pub async fn receive_and_delete_message(&self) -> Result<String> {
            self.entity.receive_and_delete_message().await
        }

        #[doc = concat!("Lock the message at the head of the ", $source, " and return its body.")]
        ///
        /// `timeout` is how long the service waits for a message before answering
        /// with an empty body (sent in whole seconds, rounded up). The lock
        /// location is discarded, so the message is redelivered once the lock
        /// expires; use [`peek_lock`](Self::peek_lock) to settle it.
        pub async fn peek_lock_message(&self, timeout: Option<Duration>) -> Result<String> {
            self.entity.peek_lock_message(timeout).await
        }

        #[doc = concat!("Lock the message at the head of the ", $source, " and keep its lock,")]
        /// so it can be completed, abandoned or renewed through the returned
        /// [`PeekLockResponse`]. `timeout` behaves as in
        /// [`peek_lock_message`](Self::peek_lock_message).
        pub async fn peek_lock(&self, timeout: Option<Duration>) -> Result<PeekLockResponse> {
            self.entity.peek_lock(timeout).await
        }
    };
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

    /// Send a message to the queue. The send is not retried; see the
    /// [delivery notes](ServiceBusClient#delivery).
    pub async fn send_message(&self, msg: &str, options: Option<SendMessageOptions>) -> Result<()> {
        self.entity.send_message(msg, options).await
    }

    receive_operations!("queue");
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
    entity: Entity,
    topic: String,
}

impl TopicClient {
    /// The topic name.
    pub fn name(&self) -> &str {
        &self.topic
    }

    /// A sender that publishes to this topic.
    pub fn topic_sender(&self) -> TopicSender {
        TopicSender {
            entity: self.entity.clone(),
        }
    }

    /// A receiver for one of this topic's subscriptions.
    pub fn subscription_receiver(&self, subscription: &str) -> Result<SubscriptionReceiver> {
        Ok(SubscriptionReceiver {
            entity: self.entity.subscription(subscription)?,
            subscription: subscription.to_string(),
        })
    }
}

impl std::fmt::Debug for TopicClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TopicClient")
            .field("topic", &self.topic)
            .field("url", &self.entity.root.as_str())
            .finish_non_exhaustive()
    }
}

/// Publishes messages to a topic.
#[derive(Clone)]
pub struct TopicSender {
    entity: Entity,
}

impl TopicSender {
    /// Send a message to the topic. The send is not retried; see the
    /// [delivery notes](ServiceBusClient#delivery).
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

    receive_operations!("subscription");
}

impl std::fmt::Debug for SubscriptionReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubscriptionReceiver")
            .field("url", &self.entity.root.as_str())
            .finish_non_exhaustive()
    }
}

/// A message locked by [`QueueClient::peek_lock`] or
/// [`SubscriptionReceiver::peek_lock`], with the operations that settle it.
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
    /// arrive as headers; values that are not valid UTF-8 are converted lossily.
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
#[non_exhaustive]
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

/// Options for sending a message, built with [`SendMessageOptions::new`] and its
/// setters.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct SendMessageOptions {
    /// `Content-Type` of the body.
    pub content_type: Option<String>,
    /// Broker properties to set on the message.
    pub broker_properties: Option<SettableBrokerProperties>,
    /// Custom message properties, sent as headers.
    pub custom_properties: Option<HashMap<String, String>>,
}

impl SendMessageOptions {
    /// Empty options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the `Content-Type` of the body.
    #[must_use]
    pub fn content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Set the broker properties of the message.
    #[must_use]
    pub fn broker_properties(mut self, properties: SettableBrokerProperties) -> Self {
        self.broker_properties = Some(properties);
        self
    }

    /// Add a custom message property, sent as a header.
    #[must_use]
    pub fn custom_property(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom_properties
            .get_or_insert_with(HashMap::new)
            .insert(name.into(), value.into());
        self
    }

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

/// Broker properties that can be set when sending a message, built with
/// [`SettableBrokerProperties::new`] and its setters.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "PascalCase")]
#[non_exhaustive]
pub struct SettableBrokerProperties {
    /// Correlation identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Session identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Message identifier, used by the entity's duplicate detection.
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

macro_rules! string_setters {
    ($($(#[$doc:meta])* $field:ident),* $(,)?) => {
        $(
            $(#[$doc])*
            #[must_use]
            pub fn $field(mut self, value: impl Into<String>) -> Self {
                self.$field = Some(value.into());
                self
            }
        )*
    };
}

impl SettableBrokerProperties {
    /// No properties set.
    pub fn new() -> Self {
        Self::default()
    }

    string_setters!(
        /// Set the correlation identifier.
        correlation_id,
        /// Set the session identifier.
        session_id,
        /// Set the message identifier.
        message_id,
        /// Set the application label.
        label,
        /// Set the reply-to address.
        reply_to,
        /// Set the destination address.
        to,
        /// Set the session to reply to.
        reply_to_session_id,
        /// Set the partition key.
        partition_key,
    );

    /// Set the time to live.
    #[must_use]
    pub fn time_to_live(mut self, ttl: Duration) -> Self {
        self.time_to_live = Some(ttl);
        self
    }

    /// Enqueue the message at `when` instead of immediately.
    #[must_use]
    pub fn scheduled_enqueue_time_utc(mut self, when: SystemTime) -> Self {
        self.scheduled_enqueue_time_utc = Some(when);
        self
    }
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
    const POLICY: &str = "RootManageSharedAccessKey";

    fn client_for(server: &MockServer) -> ServiceBusClient {
        ServiceBusClient::new("mybus", POLICY, KEY)
            .with_endpoint(server.uri())
            .expect("loopback endpoint")
    }

    fn query_value<'a>(token: &'a str, name: &str) -> &'a str {
        token
            .trim_start_matches("SharedAccessSignature ")
            .split('&')
            .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("{name} missing from {token}"))
    }

    #[test]
    fn from_connection_string_parses_namespace_policy_key() {
        let conn = "Endpoint=sb://mybus.servicebus.windows.net/;\
                    SharedAccessKeyName=RootManageSharedAccessKey;\
                    SharedAccessKey=abc123def456==";
        let client = ServiceBusClient::from_connection_string(conn).expect("parse");
        assert_eq!(client.namespace(), "mybus");
        assert_eq!(client.policy_name, POLICY);
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
        let topic = client.topic("events").expect("topic");
        let receiver = topic.subscription_receiver("audit").expect("receiver");
        assert_eq!(
            receiver.entity.scope(),
            "https://mybus.servicebus.windows.net/events/subscriptions/audit"
        );
        assert_eq!(
            topic.topic_sender().entity.scope(),
            "https://mybus.servicebus.windows.net/events"
        );
        let nested = client.queue("team/orders").expect("nested");
        assert_eq!(
            nested.entity.scope(),
            "https://mybus.servicebus.windows.net/team/orders"
        );
        assert!(client.queue("").is_err());
        assert!(client.queue("a//b").is_err());
        assert!(topic.subscription_receiver("").is_err());
    }

    #[test]
    fn with_endpoint_trims_and_restricts_schemes() {
        let client = ServiceBusClient::new("mybus", "policy", KEY);
        let local = client
            .clone()
            .with_endpoint("http://localhost:1234/")
            .expect("loopback http");
        assert_eq!(
            local.queue("orders").unwrap().entity.scope(),
            "http://localhost:1234/orders"
        );
        assert!(
            client
                .clone()
                .with_endpoint("http://127.0.0.1:5300")
                .is_ok()
        );
        assert!(client.clone().with_endpoint("http://[::1]:5300").is_ok());
        assert!(
            client
                .clone()
                .with_endpoint("https://emulator.example.com")
                .is_ok()
        );
        assert!(matches!(
            client
                .clone()
                .with_endpoint("http://mybus.servicebus.windows.net"),
            Err(AzureError::Config(_))
        ));
        assert!(client.clone().with_endpoint("ftp://localhost").is_err());
        assert!(
            client
                .clone()
                .with_endpoint("https://host.example/?x=1")
                .is_err()
        );
        assert!(client.with_endpoint("not a url").is_err());
    }

    #[test]
    fn sas_token_matches_known_answer_vector() {
        // Computed independently with Python's hmac/hashlib/urllib.parse.quote_plus.
        assert_eq!(
            sas_token(
                "https://mybus.servicebus.windows.net/orders",
                POLICY,
                KEY,
                1_700_000_000
            ),
            "SharedAccessSignature sr=https%3A%2F%2Fmybus.servicebus.windows.net%2Forders\
             &sig=RUSx912cq8wMduAfrBRdtS1YrrjoU4xlvqLzhyX3Ss8%3D&se=1700000000\
             &skn=RootManageSharedAccessKey"
        );
    }

    #[test]
    fn debug_output_redacts_the_key() {
        let client = ServiceBusClient::new("mybus", "policy", "super-secret-key");
        assert!(!format!("{client:?}").contains("super-secret-key"));
    }

    #[test]
    fn send_options_reject_invalid_headers() {
        let bad_name = SendMessageOptions::new().custom_property("bad name", "v");
        assert!(matches!(bad_name.to_headers(), Err(AzureError::Config(_))));
        let bad_value = SendMessageOptions::new().content_type("text/plain\r\nX-Evil: 1");
        assert!(matches!(bad_value.to_headers(), Err(AzureError::Config(_))));
        let bad_custom_value = SendMessageOptions::new().custom_property("ok", "a\nb");
        assert!(matches!(
            bad_custom_value.to_headers(),
            Err(AzureError::Config(_))
        ));
    }

    #[test]
    fn broker_properties_dates_are_optional_but_validated() {
        let props: BrokerProperties =
            serde_json::from_str(r#"{"DeliveryCount":1,"MessageId":"m"}"#).expect("minimal");
        assert_eq!(props.delivery_count, 1);
        assert!(props.enqueued_time_utc.is_none());
        assert!(props.locked_until_utc.is_none());
        assert!(
            serde_json::from_str::<BrokerProperties>(r#"{"EnqueuedTimeUtc":"not-a-date"}"#)
                .is_err()
        );
    }

    #[test]
    fn truncation_respects_utf8_boundaries() {
        let mut text = format!("{}€tail", "a".repeat(ERROR_BODY_LIMIT - 1));
        truncate_at_char_boundary(&mut text, ERROR_BODY_LIMIT);
        assert_eq!(text, "a".repeat(ERROR_BODY_LIMIT - 1));
    }

    #[tokio::test]
    async fn send_message_posts_body_with_a_valid_sas_and_broker_properties() {
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

        let options = SendMessageOptions::new()
            .content_type("application/json")
            .broker_properties(
                SettableBrokerProperties::new()
                    .message_id("m-1")
                    .label("created"),
            )
            .custom_property("priority", "high");
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

        // Verify the signature the server received against the key, the way the
        // service does, rather than only its shape.
        let auth = requests[0]
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap();
        let sr = query_value(auth, "sr");
        let se = query_value(auth, "se");
        let expected_scope = format!("{}/orders", server.uri());
        let expected_sr: String =
            url::form_urlencoded::byte_serialize(expected_scope.as_bytes()).collect();
        assert_eq!(sr, expected_sr);
        assert_eq!(query_value(auth, "skn"), POLICY);
        let expiry: u64 = se.parse().expect("numeric expiry");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(expiry > now && expiry <= now + SAS_TTL.as_secs() + 5);
        let mut mac = Hmac::<Sha256>::new_from_slice(b"c2VjcmV0LWtleQ==").unwrap();
        mac.update(format!("{sr}\n{se}").as_bytes());
        let expected_sig = base64::engine::general_purpose::STANDARD
            .encode(mac.finalize().into_bytes())
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D");
        assert_eq!(query_value(auth, "sig"), expected_sig);
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
    async fn peek_lock_message_returns_the_body_for_queue_and_subscription() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/orders/messages/head"))
            .and(query_param("timeout", "1"))
            .respond_with(ResponseTemplate::new(201).set_body_string("queued"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/events/subscriptions/audit/messages/head"))
            .respond_with(ResponseTemplate::new(201).set_body_string("published"))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_for(&server);
        // A sub-second wait is rounded up, not sent as `timeout=0`.
        let queued = client
            .queue("orders")
            .unwrap()
            .peek_lock_message(Some(Duration::from_millis(200)))
            .await
            .expect("queue peek-lock");
        assert_eq!(queued, "queued");
        let published = client
            .topic("events")
            .unwrap()
            .subscription_receiver("audit")
            .unwrap()
            .peek_lock_message(None)
            .await
            .expect("subscription peek-lock");
        assert_eq!(published, "published");
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
            .peek_lock(Some(Duration::from_secs(5)))
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
    async fn subscription_peek_lock_settles_under_the_subscription() {
        let server = MockServer::start().await;
        let lock_path = "/events/subscriptions/audit/messages/1/abc";
        Mock::given(method("POST"))
            .and(path("/events/subscriptions/audit/messages/head"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_string("evt")
                    .insert_header("Location", format!("{}{lock_path}", server.uri()).as_str()),
            )
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(lock_path))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let locked = client_for(&server)
            .topic("events")
            .unwrap()
            .subscription_receiver("audit")
            .unwrap()
            .peek_lock(None)
            .await
            .expect("peek-lock");
        assert_eq!(locked.body(), "evt");
        locked.delete_message().await.expect("complete");
    }

    #[tokio::test]
    async fn peek_lock_rejects_lock_locations_outside_the_entity() {
        let server = MockServer::start().await;
        let foreign = [
            "https://attacker.example/orders/messages/1/abc".to_string(),
            format!("{}/other-queue/messages/1/abc", server.uri()),
            "http://127.0.0.1:1/orders/messages/1/abc".to_string(),
        ];
        for location in &foreign {
            server.reset().await;
            Mock::given(method("POST"))
                .and(path("/orders/messages/head"))
                .respond_with(
                    ResponseTemplate::new(201)
                        .set_body_string("x")
                        .insert_header("Location", location.as_str()),
                )
                .mount(&server)
                .await;

            let err = client_for(&server)
                .queue("orders")
                .unwrap()
                .peek_lock(None)
                .await
                .expect_err("foreign lock location must be refused");
            assert!(matches!(err, AzureError::Service(_)), "{location}: {err}");
        }
    }

    #[tokio::test]
    async fn invalid_broker_properties_header_is_a_serialization_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/orders/messages/head"))
            .respond_with(
                ResponseTemplate::new(201)
                    .insert_header("BrokerProperties", r#"{"LockedUntilUtc":"yesterday"}"#),
            )
            .mount(&server)
            .await;

        let err = client_for(&server)
            .queue("orders")
            .unwrap()
            .peek_lock(None)
            .await
            .expect_err("invalid date");
        assert!(matches!(err, AzureError::Serialization(_)), "{err}");
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
            .peek_lock(None)
            .await
            .expect("peek-lock");
        assert_eq!(locked.status(), 204);
        assert!(!locked.has_message());
        assert!(locked.delete_message().await.is_err());
    }

    #[tokio::test]
    async fn auth_errors_carry_status_but_not_credentials() {
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

    #[tokio::test]
    async fn http_errors_expose_status_and_retryability() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/missing/messages/head"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let long_body = format!("{}€{}", "e".repeat(ERROR_BODY_LIMIT - 1), "z".repeat(600));
        Mock::given(method("DELETE"))
            .and(path("/busy/messages/head"))
            .respond_with(ResponseTemplate::new(503).set_body_string(long_body))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let missing = client
            .queue("missing")
            .unwrap()
            .receive_and_delete_message()
            .await
            .expect_err("404");
        assert_eq!(missing.status(), Some(404));
        assert!(!missing.is_retryable());

        let busy = client
            .queue("busy")
            .unwrap()
            .receive_and_delete_message()
            .await
            .expect_err("503");
        assert_eq!(busy.status(), Some(503));
        assert!(busy.is_retryable());
        let text = busy.to_string();
        // Cut before the multi-byte character, so nothing after it survives.
        assert!(!text.contains('€') && !text.contains("zz"), "{text}");
    }

    #[tokio::test]
    async fn transport_failures_are_network_errors() {
        // Port 1 on loopback is not listening, so the connection is refused.
        let err = ServiceBusClient::new("mybus", POLICY, KEY)
            .with_endpoint("http://127.0.0.1:1")
            .unwrap()
            .queue("orders")
            .unwrap()
            .send_message("x", None)
            .await
            .expect_err("connection refused");
        assert!(matches!(err, AzureError::Network(_)), "{err}");
        assert!(err.is_retryable());
    }
}
