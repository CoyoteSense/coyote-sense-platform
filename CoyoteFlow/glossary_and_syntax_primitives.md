# Core Concepts — CoyoteFlow Configuration Language

This document describes the main building blocks of the **CoyoteFlow** configuration language for the CoyoteSense automation platform. Each concept is a first-class entity in the platform and configuration syntax.

---

## Glossary & Syntax Primitives

### `project`

**Top-level metadata about the automation solution.**
Defines the project name, description, and versioning.

---

### `module`

**A containerized deployable block.**
Modules can be Docker containers, VMs, or other isolation units. They encapsulate one or more units.

*Examples:*

* Rithmic API server
* UI dashboard module
* Custom Python strategy service

---

### `unit`

**An executable service or logic block within a module.**
Represents a single component responsible for data processing, integration, UI, or automation logic.

*Examples:*

* Stripe API integration
* Paypal API integration
* Rithmic data feed unit
* Binance API client unit
* NinjaTrader API client unit
* Custom webhook handler unit

---

### `broker`

**A special type of unit that implements messaging (pub/sub) functionality.**
Acts as the backbone for event distribution and communication between units.

*Examples:*

* Redis broker

---

### `channel`

**A named logical message bus (topic/queue) managed by a broker.**
Channels enable decoupling of publishers and subscribers for flexible event-driven automation.

*Examples:*

* `orders`
* `trade_signals`
* `alerts`

---

### `publisher` / `subscriber`

**Roles assigned to units that send (publish) or receive (subscribe) messages via a channel.**
Defines the data flow between different units.

---

### `keyVault`

**A secure storage unit for credentials and secrets.**
Can be embedded or external (integrated with cloud key vaults or local secrets management).

*Examples:*

* Embedded secrets manager
* AWS Secrets Manager integration

---

### `aiAgent`

**A unit encapsulating AI or ML-driven automation, intelligence, or prediction logic.**
Examples: Signal generation, trade optimization, anomaly detection.

---

### `mcpServer`

**A management/control plane unit for platform orchestration.**
Handles platform-level state, data saving, or advanced control logic.

---

### `db`

**A persistent storage unit (database or data lake).**
Used for storing operational data, logs, trades, or any other persistent information.

*Examples:*

* PostgreSQL database
* MongoDB cluster

---

### `configuration`

**A dedicated unit or section for holding all settings and platform configuration.**
May be embedded or external, and enables dynamic reloading or versioning.

---

### `runner`

**A supervisor or orchestrator unit for managing the lifecycle of other units.**
Can start, stop, or monitor units, and may allow dynamic (scripted) orchestration.

---

### `workflow`

**A (optional) sequence or graph of steps connecting multiple units and actions.**
Defines how data and events flow across units in response to triggers.

---

### `trigger`

**An event or condition that starts a workflow or action.**
Examples: Timer, webhook, data arrival, manual initiation.

---

### `env`

**Global environment variables or configuration values.**
Used to pass system-wide parameters, credentials, and secrets.

---

### `secret`

**Reference to a value securely managed in a key vault or secrets store.**
Syntax:

```yaml
apiKey: !secret myApiKey
```

---

### `artifact`

**Reference to external files or resources required by modules or units.**
Examples: Custom strategy scripts, config files, certificates.

---

## Additional Concepts for Extensibility

* **Resource Constraints:** (CPU/memory limits for modules/units)
* **Monitoring & Logging:** (Special units or configuration for observability)
* **RBAC/Security:** (Fine-grained access control over modules/units)
* **Plugins/Extensions:** (Mechanism for user-defined types or logic)

---

## Example Snippet

```yaml
modules:
  - id: binance-api
    type: unit
    image: binance/api:stable
    config:
      apiKey: !secret binanceApiKey
    publisher:
      channel: orders

  - id: broker-redis
    type: broker
    image: redis:7.2
    channels: [ orders, signals ]
```

---

**This glossary is the foundation for defining and composing any automation project on the CoyoteSense platform using the CoyoteFlow configuration language.**

---
