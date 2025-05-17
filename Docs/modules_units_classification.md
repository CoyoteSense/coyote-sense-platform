# Modules & Units Classification

## Module

- Containerized deployable block (Docker, Kubernetes Pod).
- Can host multiple units.

Examples:

- Trading engine module (C++, actor-based)
- AI analytics module (Python, actor-based)
- **AI agent module (MCP, Python or C#, actor-based, optional)**
- **Finance/payment module (integrates payment gateways, financial APIs, optional)**

## Unit

- Single executable logic component within a module.
- Implemented as actors in an actor framework.

Types of Units:

- **Mandatory Units**:
  - Redis broker (infraUnit)
  - Configurator (managementUnit)
  - Trading engine unit (core trading logic)

- **Optional Units**:
  - Rithmic data feed handler
  - Binance integration unit
  - AI analytics unit
  - **AI agent unit (MCP, automation, prediction, optimization, optional)**
  - **Finance/payment unit (transaction processing, payment gateway integration, optional)**
  - Visualization/dashboard unit

---

## Infra Units

Critical infrastructural components:

- Redis (mandatory for event distribution)
- Optional databases (PostgreSQL, MongoDB)
- Optional messaging layers (RabbitMQ, Kafka)

---

## Management Units

Control plane units:

- `configurator`: manages system modes (`simulation`, `recording`, `playback`, etc.).
- `runner`: manages unit lifecycles.
- **MCP (Management/Control Plane) unit: orchestrates, monitors, and optimizes all platform operations, including optional AI and finance/payment workflows.**

---

## Finance/Payment Units (Optional)
- **Finance/payment units**: Integrate with payment gateways, process transactions, and interact with financial APIs. Can be extended to support new providers and instruments. Work in conjunction with AI agents for fraud detection, risk analysis, and payment optimization.

---

## AI Agent Units

- **AI agent units**: Provide automation, analytics, prediction, anomaly detection, and optimization for trading and finance/payment workflows. Can be implemented in Python, C#, or other languages supported by the platform.

