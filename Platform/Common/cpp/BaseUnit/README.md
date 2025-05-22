# CoyoteSense BaseUnit Architecture

This directory contains the core BaseUnit implementation and shared infrastructure components for the CoyoteSense trading platform.

## Overview

The BaseUnit serves as the foundation for all units in the CoyoteSense platform, providing:

- **Redis pub/sub integration** for low-latency inter-unit communication
- **Secure credential management** via KeyVault integration
- **Configuration management** with JSON-based configuration files
- **Logging and monitoring** with centralized log aggregation
- **Heartbeat and health monitoring** for system supervision
- **Protocol buffer support** for high-performance message serialization

## Architecture Components

### Infrastructure Layer (`Infra/`)

#### RedisClient
- High-performance Redis client for pub/sub and data operations
- Separate connections for commands and subscriptions
- Support for all Redis data structures (strings, hashes, sets, lists)
- Automatic reconnection and error handling

#### SecureStore (KeyVault)
- TLS-encrypted communication with KeyVault service
- Token-based authentication with automatic refresh
- Support for mutual TLS (mTLS) authentication
- In-memory secret handling with automatic cleanup

#### ConfigReader
- JSON-based configuration management
- Hierarchical configuration structure
- Type-safe configuration access
- Runtime configuration updates

### BaseUnit Core

The `BaseUnit` class provides:

```cpp
class BaseUnit {
public:
    // Lifecycle management
    virtual bool initialize();
    virtual bool start();
    virtual void stop();
    virtual void run();

    // Communication
    bool publishMessage(const std::string& channel, const std::string& message);
    void subscribeToChannel(const std::string& channel, callback);

    // Security
    std::string getSecret(const std::string& path);

    // Monitoring
    void logInfo/Warning/Error(const std::string& message);
    void sendHeartbeat();
    void updateMetrics(const std::string& metric, double value);

protected:
    // Override in derived classes
    virtual bool onInitialize() = 0;
    virtual bool onStart() = 0;
    virtual void onStop() = 0;
    virtual void onMessage(const std::string& channel, const std::string& message);
};
```

### Component Handlers

#### DataFeedHandler
- Produces market data to Redis channels
- Generates sample trading data for testing
- Publishes order updates and trade notifications
- Configurable data generation rates

#### CommandHandler
- Receives and processes unit commands
- Handles system-wide broadcast commands
- Supports unit-specific command routing
- Provides status reporting and configuration updates

## Channel Architecture

The BaseUnit implements the standardized channel architecture defined in the platform documentation:

### System Channels
- `units-registration` - Unit lifecycle events
- `broadcast-command` - System-wide commands
- `units-heartbeat` - Health monitoring
- `logs` - Centralized logging
- `alerts` - Critical error notifications
- `metrics` - Performance telemetry

### Unit-Specific Channels
- `{unitId}-command` - Direct unit commands
- `{unitId}-response` - Command responses
- `{unitId}-notification` - Status updates
- `{unitId}-order-notification` - Order events (Protobuf)
- `{unitId}-market-notification` - Market data (Protobuf)

## Configuration

Example configuration file (`config.json`):

```json
{
  "redis": {
    "host": "localhost",
    "port": 6379,
    "connectionTimeout": 5000
  },
  "unit": {
    "id": "trading-unit-001",
    "type": "TradingUnit",
    "logLevel": "INFO",
    "heartbeatInterval": 30000
  },
  "keyvault": {
    "url": "https://vault:8201",
    "unitRole": "trading-unit",
    "enableMutualTLS": false
  }
}
```

## Building

### Prerequisites
- CMake 3.8+
- C++17 compatible compiler
- Redis client library (hiredis)
- libcurl for HTTPS requests
- nlohmann/json for JSON processing

### Windows (Visual Studio)
```powershell
mkdir build
cd build
cmake .. -G "Visual Studio 16 2019"
cmake --build . --config Release
```

### Linux
```bash
mkdir build
cd build
cmake ..
make -j$(nproc)
```

### Dependencies Installation

#### Ubuntu/Debian
```bash
sudo apt-get install libhiredis-dev libcurl4-openssl-dev nlohmann-json3-dev
```

#### Windows (vcpkg)
```powershell
vcpkg install hiredis curl nlohmann-json
```

## Usage Example

```cpp
#include "BaseUnit.h"

class MyTradingUnit : public BaseUnit {
public:
    MyTradingUnit(const std::string& configPath) : BaseUnit(configPath) {}

protected:
    bool onInitialize() override {
        // Subscribe to market data
        subscribeToChannel("market-data", [this](const std::string& channel, const std::string& message) {
            processMarketData(message);
        });
        return true;
    }

    bool onStart() override {
        logInfo("Trading unit started");
        return true;
    }

    void onStop() override {
        logInfo("Trading unit stopped");
    }

private:
    void processMarketData(const std::string& data) {
        // Trading logic implementation
    }
};

int main() {
    MyTradingUnit unit("config.json");
    unit.run();
    return 0;
}
```

## Security Features

- **No persistent secrets**: All credentials are fetched on-demand from KeyVault
- **TLS encryption**: All vault communication uses HTTPS
- **Token-based auth**: Short-lived tokens with automatic refresh
- **Memory protection**: Sensitive data is cleared from memory after use
- **Audit logging**: All security operations are logged

## Monitoring and Observability

- **Structured logging**: JSON-formatted logs with timestamps and context
- **Health checks**: Automatic heartbeat with configurable intervals
- **Performance metrics**: Built-in metrics collection and reporting
- **Error tracking**: Centralized error aggregation and alerting

## Protocol Buffer Integration

The BaseUnit is designed to work with the platform's Protocol Buffer definitions in `Models/proto/`:

- High-performance binary serialization
- Language-agnostic message formats
- Versioned schema evolution
- Generated code for C++, C#, Python, and JavaScript

To generate Protocol Buffer code:
```bash
protoc --cpp_out=Models/generated/cpp/ Models/proto/*.proto
```

## Testing

The included `ExampleTradingUnit.cpp` demonstrates:
- Complete BaseUnit implementation
- Market data processing
- Order management
- Command handling
- Configuration usage

Run the example:
```bash
./BaseUnit config.json
```

## Integration with CoyoteSense Platform

This BaseUnit implementation follows the CoyoteSense platform architecture:

1. **Event-driven**: Uses Redis for low-latency pub/sub messaging
2. **Actor-based**: Each unit is an isolated, supervised actor
3. **Secure**: Integrated with KeyVault for credential management
4. **Observable**: Built-in logging, metrics, and health monitoring
5. **Configurable**: JSON-based configuration with runtime updates

Units built on this foundation can be deployed using Docker Compose or Kubernetes as defined by the CoyoteCompiler workflow.
