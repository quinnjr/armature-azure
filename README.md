# armature-azure

Microsoft Azure services integration for the Armature framework.

## Features

- **Blob Storage** - Object storage
- **Queue Storage** - Storage queues
- **Cosmos DB** - Global database
- **Service Bus** - Message queues and topics
- **Key Vault** - Secrets management

Each service is behind a Cargo feature (`blob`, `queue`, `cosmos`, `servicebus`,
`keyvault`, or the `all` group) and is only compiled and initialized when enabled.

## Installation

```toml
[dependencies]
armature-azure = { version = "0.1", features = ["blob", "cosmos"] }
```

## Quick Start

Services are configured with `AzureConfig::builder()` and constructed through
`AzureServices::new`, which hands back the raw Azure SDK clients.

```rust,no_run
use armature_azure::{AzureConfig, AzureServices};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AzureConfig::builder()
        .storage_account("mystorageaccount")
        .cosmos_endpoint("https://myaccount.documents.azure.com:443/")
        .cosmos_database("mydb")
        .servicebus_connection_string(
            "Endpoint=sb://mybus.servicebus.windows.net/;\
             SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=<key>",
        )
        .enable_blob()
        .enable_cosmos()
        .enable_servicebus()
        .build();

    let services = AzureServices::new(config).await?;

    // Blob Storage: raw azure_storage_blob::BlobServiceClient
    let blob = services.blob_service()?;
    let _containers = blob.list_containers(None)?;

    // Cosmos DB: raw azure_data_cosmos clients
    let db = services.cosmos_database()?;
    let _container = db.container_client("items");

    // Service Bus: per-entity clients over the REST API
    let queue = services.servicebus()?.queue("orders")?;
    queue.send_message("hello", None).await?;

    Ok(())
}
```

## Authentication

Storage, Cosmos DB and Key Vault use Microsoft Entra ID (AAD) token
credentials via `CredentialsSource` (the Azure SDK 1.0 line dropped
connection-string and shared-key auth for these services):

- Default / developer-tools chain (Azure CLI, Azure Developer CLI)
- Managed Identity
- Service Principal (client secret)
- Azure CLI credential

Service Bus authenticates with a Shared Access Signature (SAS), supplied as a
`servicebus_connection_string` or a `service_config("servicebus")` block with
`policy_name` + `shared_access_key`. It is implemented directly over the Service
Bus REST API (`QueueClient`, `TopicClient` / `TopicSender` /
`SubscriptionReceiver`, peek-lock with complete / abandon / renew), not the legacy
`azure_messaging_servicebus` SDK, whose `azure_core` 0.21 logs live authorization
headers at debug/trace level (RUSTSEC-2026-0275). Point
`ServiceBusClient::with_endpoint` at the Service Bus emulator for local testing.

## License

MIT OR Apache-2.0
