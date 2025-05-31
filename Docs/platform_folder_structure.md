# CoyoteSense Platform - Folder Structure and Organization

## Overview

The CoyoteSense platform follows a modular, event-driven architecture with clear separation between **Infrastructure Components** and **Business Units**. This document describes the complete folder structure, naming conventions, and organizational principles.

## Top-Level Structure

```
CoyoteSense/
├── CoyoteCompiler/          # Compiles CoyoteFlow YAML to deployment configs
├── CoyoteFlow/              # Business configuration and orchestration
├── Docs/                    # Documentation and specifications
├── Examples/                # Example implementations and tutorials
├── Models/                  # Protocol buffer definitions and generated code
├── Platform/                # Core platform implementation
│   ├── infra/              # Infrastructure components
│   └── units/              # Business logic units
└── Tools/                  # Development and deployment tools
```

## Language Folder Standardization

All infrastructure components and some units follow consistent language folder naming:

- **`cpp/`** - C++ implementations
- **`dotnet/`** - .NET/C# implementations  
- **`python/`** - Python implementations
- **`ts/`** - TypeScript implementations

> **Note**: Previously inconsistent naming (`js/` containing `.ts` files, `py/` instead of `python/`) has been standardized across all components.

## Infrastructure Components (`Platform/infra/`)

Infrastructure components provide foundational services and follow a consistent structure:

```
Platform/infra/<component>/
├── factory/                 # Factory implementations for creating instances
│   ├── cpp/
│   ├── dotnet/
│   ├── python/
│   └── ts/
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

### Infrastructure Components List

1. **`broker/redis/`** - Redis message broker integration
2. **`cfg/`** - Configuration management 
3. **`http/`** - HTTP client/server functionality
4. **`log/`** - Logging infrastructure
5. **`msg/`** - Messaging infrastructure
6. **`security/`** - Authentication and security (OAuth2, JWT, mTLS)
7. **`ws/`** - WebSocket communication

### Infrastructure Component Characteristics

- **Language Support**: All components support `cpp`, `dotnet`, `python`, `ts`
- **Mode Support**: Components support multiple runtime modes for testing and deployment
- **Interface Driven**: Clear separation between interfaces and implementations
- **Factory Pattern**: Consistent factory pattern for object creation
- **Cross-Language**: Implementations can interoperate across language boundaries

## Business Units (`Platform/units/`)

Business units implement specific business logic and are organized by functional domain:

```
Platform/units/<category>/<unit-name>/
├── Dockerfile              # Container configuration
├── unit.spec.json          # Unit specification and metadata
├── worker/                 # Main unit implementation
├── tests/                  # Unit tests and test specifications
└── [additional folders]    # Unit-specific resources
```

### Unit Categories

#### **AI Units** (`units/ai/`)
- **`placeholder-ai/`** - AI processing and analytics

#### **Analytics Units** (`units/analytics/`)
- **`tech-indicators/`** - Technical analysis and indicators

#### **API Units** (`units/api/`)
- **`auth/`** - Authentication services
- **`https/`** - HTTPS API endpoints
- **`users/`** - User management
- **`websocket/`** - WebSocket API services

#### **Core Units** (`units/core/`)
- **`debug-proxy/`** - Debugging and monitoring proxy
- **`keyvault/`** - Secret and key management
- **`metrics/`** - System metrics collection
- **`mongo-adapter/`** - MongoDB integration
- **`recorder/`** - Event recording and storage
- **`redis-broker/`** - Redis broker management (mandatory)
- **`replay-player/`** - Event replay functionality
- **`simulation-controller/`** - Simulation orchestration

#### **External Integration Units** (`units/ext/`)
- **`n8n/`** - N8N workflow automation integration
- **`zapper/`** - Zapper DeFi integration

#### **Service Units** (`units/services/`)
- **`configurator/`** - System configuration management (mandatory)
- **`dashboard/`** - Web-based dashboard
- **`mcp/`** - Model Context Protocol (MCP) services
- **`report/`** - Reporting and analytics

#### **Trading Units** (`units/trading/`)
- **`datafeed/`** - Market data processing
  - **`binance/`** - Binance exchange integration
  - **`iex/`** - IEX Cloud data integration
- **`fix/`** - FIX protocol implementation
  - **`quickfix/`** - QuickFIX integration
- **`ninja/`** - NinjaTrader integration
- **`rithmic/`** - Rithmic trading platform integration

### Unit Structure Details

#### Core Files (All Units)

- **`Dockerfile`** - Container configuration and runtime environment
- **`unit.spec.json`** - Unit metadata, dependencies, configuration schema
- **`worker/`** - Main implementation directory containing business logic
- **`tests/`** - Unit tests, integration tests, and test specifications

#### Unit Specification (`unit.spec.json`)

Contains:
- Unit metadata (name, version, description)
- Dependencies on infrastructure components
- Configuration schema and defaults
- Resource requirements
- Communication channels and protocols

#### Worker Implementation (`worker/`)

The main implementation can be in any supported language:
- **C++** - High-performance trading engines, low-latency components
- **C#/.NET** - Business logic, APIs, integration services
- **Python** - AI/ML, analytics, data processing
- **TypeScript** - Web services, APIs, dashboards
- **Other** - Units can use other languages as needed

## Models and Generated Code (`Models/`)

```
Models/
├── proto/                   # Protocol buffer definitions
│   ├── account.proto
│   ├── order.proto
│   ├── trade.proto
│   └── ...
└── generated/               # Generated code from proto definitions
    ├── cpp/
    ├── csharp/
    ├── js/                  # JavaScript for browser compatibility
    └── python/
```

## Configuration and Orchestration

### CoyoteFlow (`CoyoteFlow/`)
- **Business configuration** in YAML format
- **Declarative unit composition** and wiring
- **Runtime mode specifications**
- **Deployment configurations**

### CoyoteCompiler (`CoyoteCompiler/`)
- **Compiles CoyoteFlow YAML** to deployment artifacts
- **Generates Docker Compose** for development/testing
- **Generates Kubernetes manifests** for production

## Runtime Modes

Both infrastructure components and units support multiple runtime modes:

- **`debug/`** - Enhanced logging and debugging
- **`mock/`** - Mock implementations for testing
- **`real/`** - Production implementations
- **`record/`** - Record events and interactions
- **`replay/`** - Replay recorded events
- **`simulation/`** - Simulated environments

## Development Workflow

### For Infrastructure Components
1. Define interfaces in `/interfaces/<language>/`
2. Implement factories in `/factory/<language>/`
3. Create mode-specific implementations in `/modes/`
4. Add examples in `/examples/`
5. Write tests in `/tests/`

### For Business Units
1. Create unit directory in appropriate category
2. Define `unit.spec.json` with metadata and dependencies
3. Implement business logic in `/worker/`
4. Create `Dockerfile` for containerization
5. Add tests in `/tests/`

## Key Design Principles

### Modularity
- **Clear separation** between infrastructure and business logic
- **Pluggable components** with well-defined interfaces
- **Language agnostic** - choose the right tool for each component

### Consistency
- **Standardized folder structure** across all components
- **Consistent naming conventions** for language folders
- **Uniform interface patterns** across languages

### Scalability
- **Event-driven architecture** with Redis as message backbone
- **Actor-based concurrency** model
- **Container-ready** with Docker and Kubernetes support

### Testability
- **Multiple runtime modes** for testing scenarios
- **Mock implementations** for isolated testing
- **Comprehensive test coverage** requirements

## Migration Notes

### Recent Standardization (Completed)
- ✅ **Infrastructure language folders** standardized to `cpp/`, `dotnet/`, `python/`, `ts/`
- ✅ **Security component** renamed from OAuth2 to Auth for multi-standard support
- ✅ **Removed duplicate files** and inconsistent naming

### Language Folder Evolution
- **Before**: Mixed `js/`, `py/`, inconsistent naming
- **After**: Standardized `cpp/`, `dotnet/`, `python/`, `ts/`
- **Impact**: Clearer organization, better tooling support, consistent developer experience

This structure provides a scalable, maintainable foundation for the CoyoteSense trading platform while supporting diverse implementation languages and deployment scenarios.
