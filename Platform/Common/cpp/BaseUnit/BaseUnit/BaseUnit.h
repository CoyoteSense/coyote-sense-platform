#pragma once

#include <iostream>
#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <chrono>
#include <functional>
#include <nlohmann/json.hpp>

// Infrastructure includes
#include "../../Infra/RedisClient.h"
#include "../../Infra/SecureStore.h"
#include "../../Infra/ConfigReader.h"

// Forward declarations
namespace trading {
    class Order;
    class Trade;
    class Position;
}

namespace coyote {
namespace baseunit {

enum class UnitState {
    INITIALIZING,
    STARTING,
    RUNNING,
    STOPPING,
    STOPPED,
    ERROR
};

class IDataFeedHandler {
public:
    virtual ~IDataFeedHandler() = default;
    virtual void start() = 0;
    virtual void stop() = 0;
    virtual bool isRunning() const = 0;
};

class ICommandHandler {
public:
    virtual ~ICommandHandler() = default;
    virtual void handleCommand(const std::string& command, const nlohmann::json& payload) = 0;
    virtual void start() = 0;
    virtual void stop() = 0;
};

class BaseUnit {
public:
    explicit BaseUnit(const std::string& configPath);
    virtual ~BaseUnit();

    // Lifecycle methods
    virtual bool initialize();
    virtual bool start();
    virtual void stop();
    virtual void run();

    // Core functionality
    bool publishMessage(const std::string& channel, const std::string& message);
    bool publishProtobuf(const std::string& channel, const std::string& serializedData);
    
    void subscribeToChannel(const std::string& channel, 
                           std::function<void(const std::string&, const std::string&)> callback);
    void unsubscribeFromChannel(const std::string& channel);

    // Configuration and credentials
    const infra::CoyoteConfig& getConfig() const { return *m_config; }
    std::string getSecret(const std::string& path);
    
    // Logging and monitoring
    void logInfo(const std::string& message);
    void logWarning(const std::string& message);
    void logError(const std::string& message);
    void sendHeartbeat();
    void updateMetrics(const std::string& metricName, double value);

    // State management
    UnitState getState() const { return m_state; }
    const std::string& getUnitId() const { return m_unitId; }
    const std::string& getUnitType() const { return m_unitType; }

protected:
    // Virtual methods for derived classes to implement
    virtual bool onInitialize() = 0;
    virtual bool onStart() = 0;
    virtual void onStop() = 0;
    virtual void onHeartbeat() {}
    virtual void onMessage(const std::string& channel, const std::string& message) {}

    // Helper methods for derived classes
    void setState(UnitState state);
    void registerForSystemChannels();
    void handleSystemCommand(const std::string& command, const nlohmann::json& payload);

    // Component access for derived classes
    std::shared_ptr<infra::RedisClient> getRedisClient() { return m_redisClient; }
    std::shared_ptr<infra::ISecureStore> getSecureStore() { return m_secureStore; }

private:
    // Configuration
    std::unique_ptr<infra::CoyoteConfig> m_config;
    std::string m_unitId;
    std::string m_unitType;
    
    // Core components
    std::shared_ptr<infra::RedisClient> m_redisClient;
    std::shared_ptr<infra::ISecureStore> m_secureStore;
    
    // State management
    std::atomic<UnitState> m_state;
    std::atomic<bool> m_running;
    
    // Background threads
    std::thread m_heartbeatThread;
    std::thread m_metricsThread;
    
    // Internal methods
    bool connectToRedis();
    bool authenticateWithVault();
    void heartbeatLoop();
    void metricsLoop();
    void registerUnit();
    void unregisterUnit();
    
    // Channel handling
    void onBroadcastCommand(const std::string& channel, const std::string& message);
    void onUnitCommand(const std::string& channel, const std::string& message);
    
    // Standard channels
    static const std::string UNITS_REGISTRATION_CHANNEL;
    static const std::string BROADCAST_COMMAND_CHANNEL;
    static const std::string UNITS_HEARTBEAT_CHANNEL;
    static const std::string LOGS_CHANNEL;
    static const std::string ALERTS_CHANNEL;
    static const std::string METRICS_CHANNEL;
};

// Stub implementations for specific handlers
class DataFeedHandler : public IDataFeedHandler {
public:
    explicit DataFeedHandler(BaseUnit* unit);
    ~DataFeedHandler() override = default;

    void start() override;
    void stop() override;
    bool isRunning() const override;

    // Data production methods
    void publishMarketData(const std::string& symbol, double price, double volume);
    void publishOrderUpdate(const std::string& orderId, const std::string& status);
    void publishTradeData(const std::string& tradeId, const std::string& symbol, 
                         double price, double quantity);

private:
    BaseUnit* m_unit;
    std::atomic<bool> m_running;
    std::thread m_dataThread;
    
    void dataFeedLoop();
    void generateSampleData();
};

class CommandHandler : public ICommandHandler {
public:
    explicit CommandHandler(BaseUnit* unit);
    ~CommandHandler() override = default;

    void handleCommand(const std::string& command, const nlohmann::json& payload) override;
    void start() override;
    void stop() override;

private:
    BaseUnit* m_unit;
    
    void handleStartCommand(const nlohmann::json& payload);
    void handleStopCommand(const nlohmann::json& payload);
    void handleConfigUpdateCommand(const nlohmann::json& payload);
    void handleStatusRequest(const nlohmann::json& payload);
};

} // namespace baseunit
} // namespace coyote
