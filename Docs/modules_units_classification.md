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

### Unit Structure
```
Platform/units/<category>/<unit-name>/
├── Dockerfile              # Container configuration
├── unit.spec.json          # Unit specification and metadata
├── worker/                 # Main unit implementation
└── tests/                  # Unit tests and test specifications
```

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
  - **Finance/payment unit (transaction processing, payment gateway integration, optional)**  - Visualization/dashboard unit

---

## Infrastructure Components

Infrastructure components provide foundational services and follow a consistent structure with standardized language folders:

### Component Structure
```
Platform/infra/<component>/
├── factory/                 # Factory implementations
│   ├── cpp/                # C++ implementations
│   ├── dotnet/             # .NET/C# implementations
│   ├── python/             # Python implementations
│   └── ts/                 # TypeScript implementations
├── interfaces/              # Interface definitions and types
│   ├── cpp/
│   ├── dotnet/
│   ├── python/
│   └── ts/
├── modes/                   # Runtime mode implementations
│   ├── debug/
│   ├── mock/
│   ├── real/
│   ├── record/
│   ├── replay/
│   └── simulation/
├── examples/                # Usage examples (where applicable)
├── tests/                   # Component tests
└── clients/                 # Client implementations (where applicable)
```

### Available Infrastructure Components
- **`broker/redis/`** - Redis message broker integration
- **`cfg/`** - Configuration management 
- **`http/`** - HTTP client/server functionality
- **`log/`** - Logging infrastructure
- **`msg/`** - Messaging infrastructure
- **`security/`** - Authentication and security (OAuth2, JWT, mTLS)
- **`ws/`** - WebSocket communication

> **Note**: All infrastructure components now use standardized language folder naming: `cpp/`, `dotnet/`, `python/`, `ts/` (previously inconsistent with `js/` and `py/`).

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

---

## Unit Categories and Organization

Units are organized by functional domain under `Platform/units/`:

### **AI Units** (`units/ai/`)
- **`placeholder-ai/`** - AI processing and analytics

### **Analytics Units** (`units/analytics/`)
- **`tech-indicators/`** - Technical analysis and indicators

### **API Units** (`units/api/`)
- **`auth/`** - Authentication services
- **`https/`** - HTTPS API endpoints
- **`users/`** - User management
- **`websocket/`** - WebSocket API services

### **Core Units** (`units/core/`)
- **`debug-proxy/`** - Debugging and monitoring proxy
- **`keyvault/`** - Secret and key management
- **`metrics/`** - System metrics collection
- **`mongo-adapter/`** - MongoDB integration
- **`recorder/`** - Event recording and storage
- **`redis-broker/`** - Redis broker management (mandatory)
- **`replay-player/`** - Event replay functionality
- **`simulation-controller/`** - Simulation orchestration

### **External Integration Units** (`units/ext/`)
- **`n8n/`** - N8N workflow automation integration
- **`zapper/`** - Zapper DeFi integration

### **Service Units** (`units/services/`)
- **`configurator/`** - System configuration management (mandatory)
- **`dashboard/`** - Web-based dashboard
- **`mcp/`** - Model Context Protocol (MCP) services
- **`report/`** - Reporting and analytics

### **Trading Units** (`units/trading/`)
- **`datafeed/`** - Market data processing
  - **`binance/`** - Binance exchange integration
  - **`iex/`** - IEX Cloud data integration
- **`fix/`** - FIX protocol implementation
  - **`quickfix/`** - QuickFIX integration
- **`ninja/`** - NinjaTrader integration
- **`rithmic/`** - Rithmic trading platform integration

> **See Also**: For complete folder structure documentation, refer to [`PLATFORM_FOLDER_STRUCTURE.md`](./PLATFORM_FOLDER_STRUCTURE.md)

