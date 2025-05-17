# Core Concepts — CoyoteFlow Configuration Language

This document describes the main building blocks of the **CoyoteFlow** configuration language for the CoyoteSense automation platform. Each concept is a first-class entity in the platform and configuration syntax.

---

## Glossary & Syntax Primitives

### project

**Top-level metadata about the automation solution.**
Defines the project name, description, and versioning.

---

### module

**A containerized deployable block.**
Modules can be Docker containers, VMs, or other isolation units. They encapsulate one or more units.

*Examples:*

* Rithmic API server
* UI dashboard module
* Custom Python strategy service
* **AI agent module (MCP, automation, analytics)**
* **Finance/payment module (payment gateway, transaction processor)**

---

### unit

**An executable service or logic block within a module.**
Represents a single component responsible for data processing, integration, UI, automation logic, or financial/payment operations.

*Examples:*

* Stripe API integration
* Paypal API integration
* QuickFix client unit
* Rithmic data feed unit
* Binance API client unit
* NinjaTrader API client unit
* Custom webhook handler unit
* **AI agent unit (signal generation, prediction, optimization)**
* **Finance/payment unit (transaction, settlement, fraud detection)**

---

### broker

**A special type of unit that implements messaging (pub/sub) functionality.**
Acts as the backbone for event distribution and communication between units.

*Examples:*

* Redis broker

---

### channel

**A named logical message bus (topic/queue) managed by a broker.**
Channels enable decoupling of publishers and subscribers for flexible event-driven automation.

*Examples:*

* orders
* trade_signals
* alerts
* **payments**
* **finance_events**

---

### publisher / subscriber

**Roles assigned to units that send (publish) or receive (subscribe) messages via a channel.**
Defines the data flow between different units.

---

### keyVault

**A secure storage unit for credentials and secrets.**
Can be embedded or external (integrated with cloud key vaults or local secrets management).

*Examples:*

* Embedded secrets manager
* AWS Secrets Manager integration

---

### aiAgent

**A unit encapsulating AI or ML-driven automation, intelligence, or prediction logic.**
Examples: Signal generation, trade optimization, anomaly detection, **payment fraud detection, financial forecasting**.

---

### mcpServer

**A management/control plane unit for platform orchestration.**
Handles platform-level state, data saving, or advanced control logic. **Can coordinate AI and finance/payment units.**

---

### financeUnit

**A unit dedicated to finance/payment operations, such as payment gateway integration, transaction processing, settlement, and financial data aggregation.**
Examples: Stripe payment processor, bank API integration, payment fraud detection.

---

### db

**A persistent storage unit (database or data lake).**
Used for storing operational data, logs, trades, payments, or any other persistent information.

*Examples:*

* PostgreSQL database
* MongoDB cluster

---

### configuration

**A dedicated unit or section for holding all settings and platform configuration.**
May be embedded or external, and enables dynamic reloading or versioning.

---

### runner

**A supervisor or orchestrator unit for managing the lifecycle of other units.**
Can start, stop, or monitor units, and may allow dynamic (scripted) orchestration.

---

### workflow

**A (optional) sequence or graph of steps connecting multiple units and actions.**
Defines how data and events flow across units in response to triggers.

---

### trigger

**An event or condition that starts a workflow or action.**
Examples: Timer, webhook, data arrival, manual initiation.

---

### env

**Global environment variables or configuration values.**
Used to pass system-wide parameters, credentials, and secrets.

---

### secret

**Reference to a value securely managed in a key vault or secrets store.**
Syntax:

yaml
apiKey: !secret myApiKey

---

### artifact

**Reference to external files or resources required by modules or units.**
Examples: Custom strategy scripts, config files, certificates.

---

## Additional Concepts for Extensibility

* **Resource Constraints:** (CPU/memory limits for modules/units)
* **Monitoring & Logging:** (Special units or configuration for observability)
* **RBAC/Security:** (Fine-grained access control over modules/units)
* **Plugins/Extensions:** (Mechanism for user-defined types or logic)

---

**This glossary is the foundation for defining and composing any automation project on the CoyoteSense platform using the CoyoteFlow configuration language.**

## CoyoteFlow Example

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
    channels: [ orders, signals, payments ]

  - id: ai-agent
    type: aiAgent
    image: myorg/ai-agent:latest
    config:
      modelPath: /models/ai-model.bin
    publisher:
      channel: trade_signals

  - id: payment-processor
    type: financeUnit
    image: myorg/payment-processor:latest
    config:
      provider: Stripe
      apiKey: !secret stripeApiKey
    publisher:
      channel: payments
```

## Additional Infrastructure Units

### `infraUnit`

**Infrastructure-critical component mandatory for operation.**

Examples:

- Redis (mandatory event broker)
- Message brokers (e.g., RabbitMQ, Kafka as optional additional infrastructure)

---

## Additional Runtime Modes

### `runtimeMode`

Defines operational modes for the CoyoteSense platform:

- `production`: Live trading, real data, finance/payment enabled.
- `simulation`: Virtual trading and payment environment.
- `recording`: Captures real event data for replay or analysis.
- `playback`: Replays previously recorded sessions.
- `debug`: Development and debugging mode with verbose logging.

Example snippet:

```yaml
runtimeMode: simulation
```
