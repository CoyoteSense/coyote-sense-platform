#include "BaseUnit.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <random>

using namespace std;
using json = nlohmann::json;

namespace coyote {
namespace baseunit {

// Static channel names
const std::string BaseUnit::UNITS_REGISTRATION_CHANNEL = "units-registration";
const std::string BaseUnit::BROADCAST_COMMAND_CHANNEL = "broadcast-command";
const std::string BaseUnit::UNITS_HEARTBEAT_CHANNEL = "units-heartbeat";
const std::string BaseUnit::LOGS_CHANNEL = "logs";
const std::string BaseUnit::ALERTS_CHANNEL = "alerts";
const std::string BaseUnit::METRICS_CHANNEL = "metrics";

BaseUnit::BaseUnit(const std::string& configPath) 
    : m_config(std::make_unique<infra::CoyoteConfig>(configPath)),
      m_state(UnitState::INITIALIZING),
      m_running(false) {
    
    const auto& unitConfig = m_config->getUnitConfig();
    m_unitId = unitConfig.unitId;
    m_unitType = unitConfig.unitType;
    
    if (m_unitId.empty()) {
        // Generate a unique unit ID if not provided
        m_unitId = m_unitType + "-" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    }
    
    logInfo("BaseUnit created: " + m_unitId + " (type: " + m_unitType + ")");
}

BaseUnit::~BaseUnit() {
    stop();
}

bool BaseUnit::initialize() {
    setState(UnitState::INITIALIZING);
    
    logInfo("Initializing unit: " + m_unitId);
    
    // Connect to Redis
    if (!connectToRedis()) {
        logError("Failed to connect to Redis");
        setState(UnitState::ERROR);
        return false;
    }
    
    // Authenticate with KeyVault
    if (!authenticateWithVault()) {
        logError("Failed to authenticate with KeyVault");
        setState(UnitState::ERROR);
        return false;
    }
    
    // Register for system channels
    registerForSystemChannels();
    
    // Call derived class initialization
    if (!onInitialize()) {
        logError("Derived class initialization failed");
        setState(UnitState::ERROR);
        return false;
    }
    
    logInfo("Unit initialized successfully: " + m_unitId);
    return true;
}

bool BaseUnit::start() {
    if (m_state != UnitState::INITIALIZING) {
        logError("Unit must be initialized before starting");
        return false;
    }
    
    setState(UnitState::STARTING);
    logInfo("Starting unit: " + m_unitId);
    
    // Register unit with the system
    registerUnit();
    
    // Start background threads
    m_running = true;
    m_heartbeatThread = std::thread(&BaseUnit::heartbeatLoop, this);
    m_metricsThread = std::thread(&BaseUnit::metricsLoop, this);
    
    // Call derived class start
    if (!onStart()) {
        logError("Derived class start failed");
        stop();
        setState(UnitState::ERROR);
        return false;
    }
    
    setState(UnitState::RUNNING);
    logInfo("Unit started successfully: " + m_unitId);
    return true;
}

void BaseUnit::stop() {
    if (m_state == UnitState::STOPPED || m_state == UnitState::STOPPING) {
        return;
    }
    
    setState(UnitState::STOPPING);
    logInfo("Stopping unit: " + m_unitId);
    
    // Stop background threads
    m_running = false;
    
    if (m_heartbeatThread.joinable()) {
        m_heartbeatThread.join();
    }
    
    if (m_metricsThread.joinable()) {
        m_metricsThread.join();
    }
    
    // Unregister unit
    unregisterUnit();
    
    // Call derived class stop
    onStop();
    
    // Disconnect from services
    if (m_redisClient) {
        m_redisClient->disconnect();
    }
    
    if (m_secureStore) {
        m_secureStore->disconnect();
    }
    
    setState(UnitState::STOPPED);
    logInfo("Unit stopped: " + m_unitId);
}

void BaseUnit::run() {
    if (!initialize()) {
        logError("Failed to initialize unit");
        return;
    }
    
    if (!start()) {
        logError("Failed to start unit");
        return;
    }
    
    logInfo("Unit running. Press Ctrl+C to stop...");
    
    // Main event loop
    while (m_running && m_state == UnitState::RUNNING) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    stop();
}

bool BaseUnit::publishMessage(const std::string& channel, const std::string& message) {
    if (!m_redisClient || !m_redisClient->isConnected()) {
        logError("Redis client not connected");
        return false;
    }
    
    return m_redisClient->publish(channel, message);
}

bool BaseUnit::publishProtobuf(const std::string& channel, const std::string& serializedData) {
    return publishMessage(channel, serializedData);
}

void BaseUnit::subscribeToChannel(const std::string& channel, 
                                 std::function<void(const std::string&, const std::string&)> callback) {
    if (!m_redisClient || !m_redisClient->isConnected()) {
        logError("Redis client not connected");
        return;
    }
    
    m_redisClient->subscribe(channel, callback);
}

void BaseUnit::unsubscribeFromChannel(const std::string& channel) {
    if (m_redisClient && m_redisClient->isConnected()) {
        m_redisClient->unsubscribe(channel);
    }
}

std::string BaseUnit::getSecret(const std::string& path) {
    if (!m_secureStore || !m_secureStore->isConnected()) {
        logWarning("Secure store not available for secret: " + path);
        return "";
    }
    
    return m_secureStore->getSecret(path);
}

void BaseUnit::logInfo(const std::string& message) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    
    std::string logMessage = "[" + ss.str() + "] [INFO] [" + m_unitId + "] " + message;
    std::cout << logMessage << std::endl;
    
    // Also send to centralized logging
    if (m_redisClient && m_redisClient->isConnected()) {
        json logEntry;
        logEntry["timestamp"] = ss.str();
        logEntry["level"] = "INFO";
        logEntry["unitId"] = m_unitId;
        logEntry["message"] = message;
        
        m_redisClient->publish(LOGS_CHANNEL, logEntry.dump());
    }
}

void BaseUnit::logWarning(const std::string& message) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    
    std::string logMessage = "[" + ss.str() + "] [WARN] [" + m_unitId + "] " + message;
    std::cout << logMessage << std::endl;
    
    if (m_redisClient && m_redisClient->isConnected()) {
        json logEntry;
        logEntry["timestamp"] = ss.str();
        logEntry["level"] = "WARN";
        logEntry["unitId"] = m_unitId;
        logEntry["message"] = message;
        
        m_redisClient->publish(LOGS_CHANNEL, logEntry.dump());
    }
}

void BaseUnit::logError(const std::string& message) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    
    std::string logMessage = "[" + ss.str() + "] [ERROR] [" + m_unitId + "] " + message;
    std::cerr << logMessage << std::endl;
    
    if (m_redisClient && m_redisClient->isConnected()) {
        json logEntry;
        logEntry["timestamp"] = ss.str();
        logEntry["level"] = "ERROR";
        logEntry["unitId"] = m_unitId;
        logEntry["message"] = message;
        
        m_redisClient->publish(LOGS_CHANNEL, logEntry.dump());
        m_redisClient->publish(ALERTS_CHANNEL, logEntry.dump());
    }
}

void BaseUnit::sendHeartbeat() {
    if (!m_redisClient || !m_redisClient->isConnected()) {
        return;
    }
    
    json heartbeat;
    heartbeat["unitId"] = m_unitId;
    heartbeat["unitType"] = m_unitType;
    heartbeat["state"] = static_cast<int>(m_state);
    heartbeat["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    m_redisClient->publish(UNITS_HEARTBEAT_CHANNEL, heartbeat.dump());
    
    // Call derived class heartbeat
    onHeartbeat();
}

void BaseUnit::updateMetrics(const std::string& metricName, double value) {
    if (!m_redisClient || !m_redisClient->isConnected()) {
        return;
    }
    
    json metric;
    metric["unitId"] = m_unitId;
    metric["metric"] = metricName;
    metric["value"] = value;
    metric["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    m_redisClient->publish(METRICS_CHANNEL, metric.dump());
}

void BaseUnit::setState(UnitState state) {
    m_state = state;
}

bool BaseUnit::connectToRedis() {
    const auto& redisConfig = m_config->getRedisConfig();
    
    m_redisClient = std::make_shared<infra::RedisClient>(redisConfig.host, redisConfig.port);
    
    if (!m_redisClient->connect()) {
        logError("Failed to connect to Redis at " + redisConfig.host + ":" + std::to_string(redisConfig.port));
        return false;
    }
    
    logInfo("Connected to Redis successfully");
    return true;
}

bool BaseUnit::authenticateWithVault() {
    const auto& vaultConfig = m_config->getKeyVaultConfig();
    
    if (vaultConfig.url.empty() || vaultConfig.unitRole.empty()) {
        logWarning("KeyVault configuration incomplete, skipping authentication");
        return true; // Not a failure if KeyVault is not configured
    }
    
    m_secureStore = std::make_shared<infra::KeyVaultClient>(vaultConfig.url, vaultConfig.unitRole);
    
    // For demo purposes, use a default secret. In production, this would come from environment or file
    std::string credentials = "default-secret-id";
    
    if (!m_secureStore->authenticate(vaultConfig.unitRole, credentials)) {
        logError("Failed to authenticate with KeyVault");
        return false;
    }
    
    logInfo("Authenticated with KeyVault successfully");
    return true;
}

void BaseUnit::registerForSystemChannels() {
    // Subscribe to broadcast commands
    subscribeToChannel(BROADCAST_COMMAND_CHANNEL, 
        [this](const std::string& channel, const std::string& message) {
            onBroadcastCommand(channel, message);
        });
    
    // Subscribe to unit-specific commands
    std::string unitCommandChannel = m_unitId + "-command";
    subscribeToChannel(unitCommandChannel,
        [this](const std::string& channel, const std::string& message) {
            onUnitCommand(channel, message);
        });
}

void BaseUnit::registerUnit() {
    json registration;
    registration["action"] = "register";
    registration["unitId"] = m_unitId;
    registration["unitType"] = m_unitType;
    registration["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    publishMessage(UNITS_REGISTRATION_CHANNEL, registration.dump());
    logInfo("Unit registered with system");
}

void BaseUnit::unregisterUnit() {
    json registration;
    registration["action"] = "unregister";
    registration["unitId"] = m_unitId;
    registration["unitType"] = m_unitType;
    registration["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    publishMessage(UNITS_REGISTRATION_CHANNEL, registration.dump());
    logInfo("Unit unregistered from system");
}

void BaseUnit::heartbeatLoop() {
    const auto& unitConfig = m_config->getUnitConfig();
    auto interval = std::chrono::milliseconds(unitConfig.heartbeatInterval);
    
    while (m_running) {
        sendHeartbeat();
        std::this_thread::sleep_for(interval);
    }
}

void BaseUnit::metricsLoop() {
    while (m_running) {
        // Send basic metrics
        updateMetrics("uptime_seconds", 
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
        
        updateMetrics("state", static_cast<double>(m_state));
        
        std::this_thread::sleep_for(std::chrono::seconds(60)); // Send metrics every minute
    }
}

void BaseUnit::onBroadcastCommand(const std::string& channel, const std::string& message) {
    try {
        auto commandJson = json::parse(message);
        std::string command = commandJson.value("command", "");
        
        logInfo("Received broadcast command: " + command);
        handleSystemCommand(command, commandJson);
        
    } catch (const std::exception& e) {
        logError("Error parsing broadcast command: " + std::string(e.what()));
    }
}

void BaseUnit::onUnitCommand(const std::string& channel, const std::string& message) {
    try {
        auto commandJson = json::parse(message);
        std::string command = commandJson.value("command", "");
        
        logInfo("Received unit command: " + command);
        handleSystemCommand(command, commandJson);
        
    } catch (const std::exception& e) {
        logError("Error parsing unit command: " + std::string(e.what()));
    }
}

void BaseUnit::handleSystemCommand(const std::string& command, const nlohmann::json& payload) {
    if (command == "reload-config") {
        logInfo("Reloading configuration");
        // Reload configuration logic here
    } else if (command == "get-status") {
        json response;
        response["unitId"] = m_unitId;
        response["unitType"] = m_unitType;
        response["state"] = static_cast<int>(m_state);
        response["uptime"] = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        
        std::string responseChannel = m_unitId + "-response";
        publishMessage(responseChannel, response.dump());
    } else if (command == "shutdown") {
        logInfo("Received shutdown command");
        m_running = false;
    }
    
    // Call derived class message handler
    onMessage("command", payload.dump());
}

// DataFeedHandler implementation
DataFeedHandler::DataFeedHandler(BaseUnit* unit) : m_unit(unit), m_running(false) {
}

void DataFeedHandler::start() {
    if (m_running) {
        return;
    }
    
    m_running = true;
    m_dataThread = std::thread(&DataFeedHandler::dataFeedLoop, this);
    m_unit->logInfo("DataFeedHandler started");
}

void DataFeedHandler::stop() {
    if (!m_running) {
        return;
    }
    
    m_running = false;
    if (m_dataThread.joinable()) {
        m_dataThread.join();
    }
    
    m_unit->logInfo("DataFeedHandler stopped");
}

bool DataFeedHandler::isRunning() const {
    return m_running;
}

void DataFeedHandler::dataFeedLoop() {
    while (m_running) {
        generateSampleData();
        std::this_thread::sleep_for(std::chrono::milliseconds(1000)); // Generate data every second
    }
}

void DataFeedHandler::generateSampleData() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_real_distribution<> priceDist(100.0, 200.0);
    static std::uniform_real_distribution<> volumeDist(1000.0, 10000.0);
    
    // Generate sample market data
    publishMarketData("BTCUSD", priceDist(gen), volumeDist(gen));
    publishMarketData("ETHUSD", priceDist(gen) * 0.1, volumeDist(gen));
}

void DataFeedHandler::publishMarketData(const std::string& symbol, double price, double volume) {
    json marketData;
    marketData["type"] = "market_data";
    marketData["symbol"] = symbol;
    marketData["price"] = price;
    marketData["volume"] = volume;
    marketData["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    std::string channel = m_unit->getUnitId() + "-market-notification";
    m_unit->publishMessage(channel, marketData.dump());
}

void DataFeedHandler::publishOrderUpdate(const std::string& orderId, const std::string& status) {
    json orderUpdate;
    orderUpdate["type"] = "order_update";
    orderUpdate["orderId"] = orderId;
    orderUpdate["status"] = status;
    orderUpdate["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    std::string channel = m_unit->getUnitId() + "-order-notification";
    m_unit->publishMessage(channel, orderUpdate.dump());
}

void DataFeedHandler::publishTradeData(const std::string& tradeId, const std::string& symbol, 
                                      double price, double quantity) {
    json tradeData;
    tradeData["type"] = "trade";
    tradeData["tradeId"] = tradeId;
    tradeData["symbol"] = symbol;
    tradeData["price"] = price;
    tradeData["quantity"] = quantity;
    tradeData["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    std::string channel = m_unit->getUnitId() + "-market-notification";
    m_unit->publishMessage(channel, tradeData.dump());
}

// CommandHandler implementation
CommandHandler::CommandHandler(BaseUnit* unit) : m_unit(unit) {
}

void CommandHandler::handleCommand(const std::string& command, const nlohmann::json& payload) {
    m_unit->logInfo("Handling command: " + command);
    
    if (command == "start") {
        handleStartCommand(payload);
    } else if (command == "stop") {
        handleStopCommand(payload);
    } else if (command == "config-update") {
        handleConfigUpdateCommand(payload);
    } else if (command == "status") {
        handleStatusRequest(payload);
    } else {
        m_unit->logWarning("Unknown command: " + command);
    }
}

void CommandHandler::start() {
    m_unit->logInfo("CommandHandler started");
}

void CommandHandler::stop() {
    m_unit->logInfo("CommandHandler stopped");
}

void CommandHandler::handleStartCommand(const nlohmann::json& payload) {
    m_unit->logInfo("Processing start command");
    // Implementation for start command
}

void CommandHandler::handleStopCommand(const nlohmann::json& payload) {
    m_unit->logInfo("Processing stop command");
    // Implementation for stop command
}

void CommandHandler::handleConfigUpdateCommand(const nlohmann::json& payload) {
    m_unit->logInfo("Processing config update command");
    // Implementation for config update
}

void CommandHandler::handleStatusRequest(const nlohmann::json& payload) {
    m_unit->logInfo("Processing status request");
    
    json response;
    response["unitId"] = m_unit->getUnitId();
    response["unitType"] = m_unit->getUnitType();
    response["state"] = static_cast<int>(m_unit->getState());
    response["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    std::string responseChannel = m_unit->getUnitId() + "-response";
    m_unit->publishMessage(responseChannel, response.dump());
}

} // namespace baseunit
} // namespace coyote
