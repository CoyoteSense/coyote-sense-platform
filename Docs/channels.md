# Channels Overview

This document describes the messaging channels used in the CoyoteSense platform. Channels are used for communication between units, system components, and external systems.

## Channel List

| Channel Name                  | Scope      | Type       | Purpose                                                        |
|-------------------------------|------------|------------|----------------------------------------------------------------|
| units-registration            | Common     | JSON       | Register/unregister events for all units                       |
| broadcast-command             | Common     | Protobuf   | Broadcast commands to all units                                |
| system-broadcast              | Common     | JSON       | System-wide announcements or configuration changes             |
| units-heartbeat               | Common     | JSON       | Health/heartbeat signals from units                            |
| logs                          | Common     | JSON       | Aggregated logs from all units                                 |
| alerts                        | Common     | JSON       | Critical system-wide errors or alerts                          |
| {unitId}-command              | Per-Unit   | Protobuf   | Commands sent to a specific unit (request/reply RPC)          |
| {unitId}-response             | Per-Unit   | Protobuf   | Responses from a specific unit to commands                     |
| {unitId}-notification         | Per-Unit   | JSON       | General status updates or events from a specific unit          |
| {unitId}-logs                 | Per-Unit   | JSON       | Unit-specific log entries                                      |
| {unitId}-alerts               | Per-Unit   | JSON       | Critical errors or alerts from a specific unit                 |
| {unitId}-order-notification   | Per-Unit   | Protobuf   | Order-related events (fills, rejects) from a specific unit     |
| {unitId}-market-notification  | Per-Unit   | Protobuf   | Market-data or signal events produced by a specific unit       |
| external-notifications        | Common     | JSON       | Notifications to/from external systems (trading venues, payment gateways) |
| config-update                 | Common/Per | JSON       | On-the-fly configuration changes pushed to units               |
| metrics                       | Common     | JSON       | Telemetry and performance metrics                              |
| simulation-control            | Common     | JSON       | Start/stop/pause simulation commands                           |
| recording-control             | Common     | JSON       | Start/stop recording sessions for later replay                 |

> **Mixed formats:**  
> - **Protobuf** on high-throughput, low-latency channels (commands, responses, market/order events)  
> - **JSON** on human-readable or infrequent channels (logs, alerts, heartbeats, config, metrics)

---

## Channel Descriptions

- **units-registration** (JSON)  
  Units announce startup (`register`) and shutdown (`unregister`); the orchestrator tracks active units.

- **broadcast-command** (Protobuf)  
  A single message fan-out to all units, typically for urgent actions like `reload-config`.

- **system-broadcast** (JSON)  
  General announcements—e.g., “new workflow deployed” or global parameter changes.

- **units-heartbeat** (JSON)  
  Periodic “I’m alive” pings from each unit; missing heartbeats trigger alerts or restarts.

- **logs / {unitId}-logs** (JSON)  
  Streaming log entries; use a common channel for central aggregation or per-unit for isolation.

- **alerts / {unitId}-alerts** (JSON)  
  Critical errors or exceptional conditions requiring operator attention.

- **{unitId}-command** (Protobuf)  
  RPC-style commands to a unit; payload includes `correlation_id` and `reply_to`.

- **{unitId}-response** (Protobuf)  
  The unit’s response to commands; must include matching `correlation_id`.

- **{unitId}-notification** (JSON)  
  Informational events from a unit (e.g., “snapshot complete”, “mode changed”).

- **{unitId}-order-notification** (Protobuf)  
  Order lifecycle events (e.g. placed, filled, canceled) emitted by trading units.

- **{unitId}-market-notification** (Protobuf)  
  Tick or signal data produced by market-facing units for strategy consumption.

- **external-notifications** (JSON)  
  Inbound/outbound integrations, e.g. FIX or webhook adapters translating into CoyoteSense events.

- **config-update** (JSON)  
  Dynamic configuration pushes (e.g. tuning parameters) without full redeployment.

- **metrics** (JSON)  
  Telemetry streams (latency histograms, error rates) for monitoring/alerting systems.

- **simulation-control** (JSON)  
  Commands to start, pause, resume, or adjust the speed of simulation mode.

- **recording-control** (JSON)  
  Control messages to begin or end recording of live events for later playback.

---

### Comments

- Protobuf consumers reject JSON; JSON consumers reject Protobuf.  
- Include a `version` field in message payloads to manage schema evolution.  

