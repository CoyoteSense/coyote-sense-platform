# Redis Data Storage Design

## 1. Introduction

This document outlines the design for utilizing Redis as a data storage solution within the CoyoteSense platform, complementing its primary role as a low-latency event broker. The goal is to provide a structured, scalable, and manageable approach to storing and accessing operational data required by various platform units.

This design addresses key aspects such as data organization, lifecycle management, scalability, and atomicity to ensure data integrity and performance.

## 2. Core Principles

The Redis data storage strategy is built upon the following core principles:

*   **Data Tiering:** Data is categorized based on its importance, access frequency, and persistence requirements to optimize memory usage and performance.
*   **TTL (Time-To-Live) Management:** TTLs are applied strategically to manage the lifecycle of non-critical or transient data, ensuring automatic cleanup and efficient memory utilization.
*   **Archival Strategy:** A defined process for moving important historical data from Redis to a long-term persistent store (e.g., PostgreSQL, MongoDB) before TTL expiration or as part of regular maintenance.
*   **Atomicity:** Operations involving multiple Redis keys or data structures (e.g., updating data and its secondary indexes) must be performed atomically using Redis Transactions (`MULTI`/`EXEC`) or Lua scripting to maintain data consistency.
*   **Consistent Key Naming:** A standardized key naming convention is enforced for clarity, discoverability, and easier management of data within Redis.

## 3. Key Naming Schema

A consistent key naming schema is crucial for organizing data in Redis.

*   **Separator:** The colon (`:`) character is used as a separator for different parts of a key.
*   **Case:** Keys are generally lowercase to maintain consistency.
*   **Structure:** Keys are structured hierarchically to reflect the data they represent.

    `<entity_type>:<tier_or_purpose>:<identifier>[:<sub_identifier_or_attribute>]`

*   **Entity Type Prefixes:**
    *   `order`: For order-related data.
    *   `position`: For position data.
    *   `account`: For account balance and details.
    *   `user`: For user session or profile data.
    *   `marketdata`: For market data snapshots or reference data.
    *   `cache`: For general-purpose caching.
    *   *(More to be added as new entities are defined)*

*   **Tier/Purpose Prefixes:**
    *   `live`: For critical, real-time state data.
    *   `events`: For logs or historical event streams related to an entity.
    *   `index`: For secondary indexes.
    *   `config`: For configuration data stored in Redis.
    *   `session`: For user session data.

### Example Key Structures:

*   **Primary Entity Data (Redis Hash):**
    *   `order:live:<orderID>`
    *   `account:live:<accountID>`
    *   `user:session:<sessionID>`
*   **Entity Event Logs (Redis List/Stream):**
    *   `order:events:<orderID>`
*   **Secondary Indexes (Redis Set):**
    *   `index:user_orders:live:<userID>` (Set of live orderIDs for a user)
    *   `index:exchange_instrument_orders:live:<exchange>:<instrumentSymbol>` (Set of live orderIDs for an instrument on an exchange)
    *   `index:order_status:live:<status>` (Set of live orderIDs with a specific status)

## 4. Data Structures

The choice of Redis data structure depends on the nature of the data being stored:

*   **Hashes:** Used for storing structured objects representing entities (e.g., an order, user profile). Each field in the hash represents an attribute of the entity.
    *   Example: `order:live:<orderID>` -> `{ "status": "FILLED", "price": 150.25, ... }`
*   **Sets:** Used for storing collections of unique elements, primarily for secondary indexes.
    *   Example: `index:user_orders:live:<userID>` -> `{ "<orderID1>", "<orderID2>" }`
*   **Lists:** Used for storing ordered sequences of elements, suitable for logs or event streams where order is important and access is often at the ends. Can be used as capped collections with `LPUSH` and `LTRIM`.
    *   Example: `order:events:<orderID>` -> `[ "{event1_json}", "{event2_json}" ]`
*   **Streams:** A more advanced data structure for append-only logs, offering consumer groups and more robust message handling than Lists for complex event sourcing patterns.
*   **Strings:** Used for simple key-value pairs, counters, or serialized objects (though Hashes are preferred for structured data).

## 5. Data Tiering & Lifecycle Management

Data in Redis is managed across different tiers based on its access patterns and persistence needs:

*   **Tier 1: Critical/Live Data:**
    *   **Description:** Real-time state information essential for immediate operations (e.g., current order status, active positions, live account balances).
    *   **Redis Keys:** Typically prefixed with `<entity_type>:live:...`
    *   **TTL:** Long or indefinite. Data is actively managed and updated.
    *   **Persistence:** This data is the "source of truth" within Redis for its active lifetime.
*   **Tier 2: Important/Archivable Data (Events/Logs):**
    *   **Description:** Historical data, event logs, or detailed records that are valuable but not required for immediate, sub-millisecond access after a certain period (e.g., detailed history of an order's state changes).
    *   **Redis Keys:** Typically prefixed with `<entity_type>:events:...`
    *   **TTL:** Moderate (e.g., 1 to 7 days, configurable per data type).
    *   **Persistence:** This data is subject to archival to a long-term persistent store (e.g., `db` unit like PostgreSQL) before TTL expiration.
*   **Tier 3: Transient/Cache Data:**
    *   **Description:** Temporary data, cached results of computations, or frequently changing data with a short lifespan.
    *   **Redis Keys:** Typically prefixed with `cache:...`
    *   **TTL:** Short (seconds to minutes).
    *   **Persistence:** Not typically archived; regenerated as needed.

### Archival Process:

An "Archiver Unit" (to be developed as part of the platform) will be responsible for:
1.  Periodically scanning Redis for keys matching archivable patterns (e.g., `*:events:*`) that are approaching their TTL.
2.  Reading the data from these keys.
3.  Writing the data to the designated long-term persistent storage system.
4.  Deleting the keys from Redis after successful archival (or allowing TTL to handle removal).

### Redis Eviction Policy:

The Redis instance will be configured with a `maxmemory` limit and an appropriate `maxmemory-policy` (e.g., `volatile-lru` or `volatile-ttl`) as a safeguard. This policy will primarily target keys with TTLs set, aligning with the data tiering strategy. However, proactive TTL management and archival are the primary mechanisms for memory control.

## 6. Specific Entity Example: Order Data

This section details how order-related data is structured and managed.

*   **Live Order State (Hash):**
    *   **Key:** `order:live:<orderID>`
    *   **Fields:** `status`, `userID`, `exchange`, `symbol`, `instrumentID`, `price`, `quantity`, `filledQuantity`, `orderType`, `timeInForce`, `sourceUnitID`, `creationTimestamp`, `lastUpdateTimestamp`, etc.
    *   **TTL:** Long or indefinite while the order is active (e.g., PENDING, PARTIALLY_FILLED). May be shortened after terminal states (FILLED, CANCELLED, REJECTED) before archival of the final state.
*   **Order Events Log (List or Stream):**
    *   **Key:** `order:events:<orderID>`
    *   **Content:** A time-ordered sequence of events related to the order (e.g., status changes, modifications, partial fills). Each event is a JSON string or a structured entry if using Streams.
    *   **TTL:** Moderate (e.g., 7 days), then archived.
*   **Secondary Indexes (Sets):**
    *   `index:user_orders:live:<userID>` -> Set of `<orderID>`
    *   `index:instrument_orders:live:<instrumentID>` -> Set of `<orderID>`
    *   `index:exchange_orders:live:<exchangeName>` -> Set of `<orderID>`
    *   `index:order_status:live:<statusValue>` -> Set of `<orderID>` (e.g., `index:order_status:live:PENDING`)

**Atomicity for Order Updates:**
When an order's status changes:
1.  Update the relevant fields in the `order:live:<orderID>` Hash.
2.  Add a new event to the `order:events:<orderID>` List/Stream.
3.  If the status changed, remove the `<orderID>` from the old status Set (e.g., `index:order_status:live:PENDING`) and add it to the new status Set (e.g., `index:order_status:live:FILLED`).
These operations must be performed within a Redis `MULTI`/`EXEC` transaction.

## 7. Unit Responsibilities

*   **Data Producing Units** (e.g., Rithmic Connector Unit, NinjaTrader Connector Unit, Order Management Unit):
    *   Responsible for writing and updating data in Redis according to the defined schema and data structures.
    *   Must ensure atomicity for complex updates.
    *   Must set appropriate TTLs for archivable or transient data they produce.
*   **Data Consuming Units** (e.g., Monitoring Unit, AI Agent Unit, Reporting Unit):
    *   Responsible for reading data from Redis using the defined key patterns.
    *   Should not modify data unless they are designated owners or part of a defined workflow.
*   **Archiver Unit:**
    *   Responsible for implementing the archival process as described in Section 5.
*   **Configuration Unit:**
    *   May store parts of its configuration or lookup tables in Redis (e.g., `config:instrument_details:<symbol>`).

## 8. MCP Server and AI Agent Data Utilization

This section describes how the Management/Control Plane (MCP) Server and AI Agent units leverage data stored in Redis, encompassing trading, payment, and finance operations.

### 8.1. Management/Control Plane (MCP) Server

The MCP Server acts as the central orchestrator and monitor for the CoyoteSense platform. It relies on Redis for:

*   **Platform State Monitoring:**
    *   **Unit Health & Registration:** Consumes data from `units-registration` channel (though this is a channel, MCP might persist a summary or list of active units in Redis keys like `mcp:active_units` (Set) or `mcp:unit_heartbeat:<unitID>` (String with last heartbeat timestamp)).
    *   **System-Wide Metrics:** Aggregates metrics from various units. For example, total open orders (`mcp:stats:total_open_orders` - Counter), transaction volumes (`mcp:stats:payment_volume_hourly:<hour_timestamp>` - Counter).
    *   **Alert Aggregation:** Monitors `alerts` or `{unitId}-alerts` channels and may persist critical unresolved alerts in a list like `mcp:active_alerts` (List).

*   **Orchestration & Control:**
    *   **Workflow State:** Stores and retrieves the state of complex, multi-unit workflows. Example: `mcp:workflow_state:<workflowInstanceID>` (Hash).
    *   **Configuration Distribution:** While units might fetch primary config from a Configuration Unit, MCP might push dynamic overrides or mode changes via Redis. Example: `mcp:config_override:<unit_pattern>` (Hash) or signal via a pub/sub and store confirmation `mcp:config_applied:<unitID>` (String).
    *   **Resource Management:** Tracks resource utilization if units report it. Example: `mcp:unit_resource_usage:<unitID>` (Hash with CPU, memory).

*   **Payment & Finance Oversight (if applicable):**
    *   **Settlement Process Monitoring:** Tracks stages of payment settlement processes. Example: `mcp:settlement_batch_status:<batchID>` (Hash).
    *   **System-Wide Financial Health:** Aggregates key financial indicators. Example: `mcp:platform_total_balance:<currency>` (String/Counter).

### 8.2. AI Agent Units

AI Agents utilize Redis for accessing real-time and historical data for model training, inference, and action execution.

*   **Feature Engineering & Model Input:**
    *   **Live Trading Data:** Consumes `order:live:<orderID>`, `marketdata:live:<instrumentSymbol>`, `position:live:<accountID>:<instrumentID>`.
    *   **Historical Trading Data:** Accesses `order:events:<orderID>` or data from the Archiver Unit's persistent store (though direct Redis access is for recent history).
    *   **Live Payment/Finance Data:** For fraud detection or financial forecasting, consumes `payment:live:<transactionID>`, `payment:events:<transactionID>`, `account:live:<userID>:currency:<currencyCode>`.
    *   **Aggregated Data Views:** May read pre-aggregated features stored by other units or MCP. Example: `cache:market_sentiment_features:<instrumentSymbol>` (Hash).

*   **Real-time Inference & Decision Making:**
    *   **Input:** Fetches the latest required data points (as above) for on-the-fly predictions.
    *   **Output/Signal Generation:**
        *   **Trading Signals:** `ai_agent:signal:trade:<agentID>:<signalID>` (Hash: `{instrument, direction, confidence, targetPrice, timestamp}`). These signals can then be picked up by execution units.
        *   **Fraud Alerts (Payment):** `ai_agent:signal:fraud_alert:<agentID>:<transactionID>` (Hash: `{riskScore, reasons, timestamp}`).
        *   **Payment Risk Assessment:** `ai_agent:assessment:payment_risk:<transactionID>` (Hash: `{riskScore, recommendedAction}`).

*   **Model Output & Feedback Loop:**
    *   **Storing Predictions:** Persists model outputs or intermediate calculations. Example: `cache:ai_agent:prediction_output:<modelID>:<inputHash>` (String/Hash).
    *   **Action Confirmation/Results:** Subscribes to channels or reads keys to get feedback on actions taken based on its signals (e.g., order fill confirmations from `order:live:<orderID>`, payment success/failure from `payment:live:<transactionID>`).

*   **Specific Use Case Examples:**
    *   **Market Making (Trading):** AI agent reads `marketdata:live:*` for current bids/asks, `order:live:*` for its own working orders, and `position:live:*` to manage inventory. It then places new orders, updating Redis accordingly (via an execution unit).
    *   **Payment Fraud Detection (Finance):** AI agent reads `payment:live:<transactionID>` and related customer historical data (potentially `user:profile:<userID>`). It outputs a risk score to `ai_agent:assessment:payment_risk:<transactionID>`.
    *   **Financial Forecasting (Finance):** AI agent reads historical `account:events:*` or `transaction:events:*` (from archive or recent in Redis) and external market data to predict cash flows, storing results in `ai_agent:forecast:cashflow:<period>` (Hash).

## 9. Future Considerations

*   **Redis Clustering:** As data volume grows beyond the capacity of a single Redis instance, Redis Cluster will be evaluated for horizontal scaling. The key naming schema should be compatible with clustering requirements (e.g., use of hash tags if specific keys need to reside on the same shard).
*   **Lua Scripting:** For highly complex atomic operations or business logic that needs to be executed server-side for performance, Lua scripting will be considered.
*   **Security:** Access to Redis will be managed according to the platform's overall security design (see `security.md`).

This design document will be reviewed and updated as the CoyoteSense platform evolves and new data storage requirements emerge.
