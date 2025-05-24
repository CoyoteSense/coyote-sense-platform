#pragma once

#include "IConfigReader.h"
#include <unordered_map>
#include <vector>
#include <functional>
#include <mutex>

namespace coyote {
namespace infra {
namespace mocks {

// Mock ConfigReader implementation
class MockConfigReader : public IConfigReader {
private:
    mutable std::mutex config_mutex_;
    std::unordered_map<std::string, ConfigValue> config_data_;
    std::vector<std::function<void()>> change_callbacks_;
    bool simulate_failures_ = false;
    std::string config_path_;

public:
    MockConfigReader(const std::string& configPath = "mock://config") 
        : config_path_(configPath) {
        // Pre-populate with common configuration values
        config_data_["redis.host"] = std::string("localhost");
        config_data_["redis.port"] = 6379;
        config_data_["redis.password"] = std::string("");
        config_data_["redis.connectionTimeout"] = 5000;
        config_data_["redis.commandTimeout"] = 3000;
        config_data_["redis.enableSSL"] = false;
        
        config_data_["unit.id"] = std::string("test-unit-001");
        config_data_["unit.type"] = std::string("TradingUnit");
        config_data_["unit.logLevel"] = std::string("INFO");
        config_data_["unit.heartbeatInterval"] = 30000;
        config_data_["unit.enableMetrics"] = true;
        config_data_["unit.workingDirectory"] = std::string("/tmp/coyote");
        
        std::vector<std::string> channels = {"market-data", "orders", "positions"};
        config_data_["unit.channels"] = channels;
        
        std::unordered_map<std::string, std::string> customProps = {
            {"strategy", "momentum"},
            {"riskLevel", "medium"}
        };
        config_data_["unit.customProperties"] = customProps;
        
        config_data_["keyvault.url"] = std::string("https://test-vault.vault.azure.net");
        config_data_["keyvault.unitRole"] = std::string("trading-unit");
        config_data_["keyvault.enableMutualTLS"] = false;
        config_data_["keyvault.tokenRefreshInterval"] = 300000;
    }

    // Basic value retrieval
    bool hasKey(const std::string& key) const override {
        std::lock_guard<std::mutex> lock(config_mutex_);
        return config_data_.find(key) != config_data_.end();
    }

    std::string getString(const std::string& key, const std::string& defaultValue) const override {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        if (simulate_failures_) {
            return defaultValue;
        }
        
        auto it = config_data_.find(key);
        if (it != config_data_.end()) {
            if (std::holds_alternative<std::string>(it->second)) {
                return std::get<std::string>(it->second);
            }
        }
        return defaultValue;
    }

    int getInt(const std::string& key, int defaultValue) const override {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        if (simulate_failures_) {
            return defaultValue;
        }
        
        auto it = config_data_.find(key);
        if (it != config_data_.end()) {
            if (std::holds_alternative<int>(it->second)) {
                return std::get<int>(it->second);
            } else if (std::holds_alternative<double>(it->second)) {
                return static_cast<int>(std::get<double>(it->second));
            }
        }
        return defaultValue;
    }

    double getDouble(const std::string& key, double defaultValue) const override {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        if (simulate_failures_) {
            return defaultValue;
        }
        
        auto it = config_data_.find(key);
        if (it != config_data_.end()) {
            if (std::holds_alternative<double>(it->second)) {
                return std::get<double>(it->second);
            } else if (std::holds_alternative<int>(it->second)) {
                return static_cast<double>(std::get<int>(it->second));
            }
        }
        return defaultValue;
    }

    bool getBool(const std::string& key, bool defaultValue) const override {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        if (simulate_failures_) {
            return defaultValue;
        }
        
        auto it = config_data_.find(key);
        if (it != config_data_.end()) {
            if (std::holds_alternative<bool>(it->second)) {
                return std::get<bool>(it->second);
            }
        }
        return defaultValue;
    }

    // Array operations
    std::vector<std::string> getArray(const std::string& key) const override {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        if (simulate_failures_) {
            return {};
        }
        
        auto it = config_data_.find(key);
        if (it != config_data_.end()) {
            if (std::holds_alternative<std::vector<std::string>>(it->second)) {
                return std::get<std::vector<std::string>>(it->second);
            }
        }
        return {};
    }

    size_t getArraySize(const std::string& key) const override {
        return getArray(key).size();
    }

    std::string getArrayElement(const std::string& key, size_t index, const std::string& defaultValue) const override {
        auto array = getArray(key);
        return (index < array.size()) ? array[index] : defaultValue;
    }

    // Object operations
    std::unordered_map<std::string, std::string> getObject(const std::string& key) const override {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        if (simulate_failures_) {
            return {};
        }
        
        auto it = config_data_.find(key);
        if (it != config_data_.end()) {
            if (std::holds_alternative<std::unordered_map<std::string, std::string>>(it->second)) {
                return std::get<std::unordered_map<std::string, std::string>>(it->second);
            }
        }
        return {};
    }

    std::string getObjectProperty(const std::string& key, const std::string& property, const std::string& defaultValue) const override {
        auto obj = getObject(key);
        auto it = obj.find(property);
        return (it != obj.end()) ? it->second : defaultValue;
    }

    // Value setting
    bool setString(const std::string& key, const std::string& value) override {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        if (simulate_failures_) {
            return false;
        }
        
        config_data_[key] = value;
        return true;
    }

    bool setInt(const std::string& key, int value) override {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        if (simulate_failures_) {
            return false;
        }
        
        config_data_[key] = value;
        return true;
    }

    bool setDouble(const std::string& key, double value) override {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        if (simulate_failures_) {
            return false;
        }
        
        config_data_[key] = value;
        return true;
    }

    bool setBool(const std::string& key, bool value) override {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        if (simulate_failures_) {
            return false;
        }
        
        config_data_[key] = value;
        return true;
    }

    bool setArray(const std::string& key, const std::vector<std::string>& value) override {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        if (simulate_failures_) {
            return false;
        }
        
        config_data_[key] = value;
        return true;
    }

    bool setObject(const std::string& key, const std::unordered_map<std::string, std::string>& value) override {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        if (simulate_failures_) {
            return false;
        }
        
        config_data_[key] = value;
        return true;
    }

    // File operations
    bool loadConfig(const std::string& configPath) override {
        if (simulate_failures_) {
            return false;
        }
        
        config_path_ = configPath;
        // Mock implementation - just return success
        return true;
    }

    bool saveConfig(const std::string& configPath) override {
        if (simulate_failures_) {
            return false;
        }
        
        // Mock implementation - just return success
        return true;
    }

    bool reloadConfig() override {
        if (simulate_failures_) {
            return false;
        }
        
        // Trigger change callbacks
        for (auto& callback : change_callbacks_) {
            try {
                callback();
            } catch (const std::exception& e) {
                // Ignore callback errors in mock
            }
        }
        
        return true;
    }

    // Hot-reload support
    void startFileWatcher() override {
        // Mock implementation - no actual file watching
    }

    void stopFileWatcher() override {
        // Mock implementation - no actual file watching
    }

    void addChangeCallback(std::function<void()> callback) override {
        std::lock_guard<std::mutex> lock(config_mutex_);
        change_callbacks_.push_back(std::move(callback));
    }

    // Mock-specific methods for testing
    
    void setSimulateFailures(bool simulate) {
        simulate_failures_ = simulate;
    }
    
    void clearConfig() {
        std::lock_guard<std::mutex> lock(config_mutex_);
        config_data_.clear();
    }
    
    void addConfigValue(const std::string& key, const ConfigValue& value) {
        std::lock_guard<std::mutex> lock(config_mutex_);
        config_data_[key] = value;
    }
    
    void removeConfigValue(const std::string& key) {
        std::lock_guard<std::mutex> lock(config_mutex_);
        config_data_.erase(key);
    }
    
    void triggerChange() {
        for (auto& callback : change_callbacks_) {
            try {
                callback();
            } catch (const std::exception& e) {
                // Ignore callback errors in mock
            }
        }
    }
    
    size_t getConfigSize() const {
        std::lock_guard<std::mutex> lock(config_mutex_);
        return config_data_.size();
    }
    
    std::vector<std::string> getAllKeys() const {
        std::lock_guard<std::mutex> lock(config_mutex_);
        std::vector<std::string> keys;
        for (const auto& [key, value] : config_data_) {
            keys.push_back(key);
        }
        return keys;
    }
    
    const std::string& getConfigPath() const {
        return config_path_;
    }
    
    bool isSimulatingFailures() const {
        return simulate_failures_;
    }
};

// Mock CoyoteConfig implementation
class MockCoyoteConfig : public ICoyoteConfig {
private:
    std::unique_ptr<MockConfigReader> reader_;
    RedisConfig redis_config_;
    UnitConfig unit_config_;
    KeyVaultConfig keyvault_config_;

public:
    MockCoyoteConfig() : reader_(std::make_unique<MockConfigReader>()) {
        loadStructuredConfig();
    }

    explicit MockCoyoteConfig(std::unique_ptr<IConfigReader> reader) {
        auto mockReader = dynamic_cast<MockConfigReader*>(reader.release());
        if (mockReader) {
            reader_.reset(mockReader);
        } else {
            reader_ = std::make_unique<MockConfigReader>();
        }
        loadStructuredConfig();
    }

    IConfigReader* getConfigReader() override {
        return reader_.get();
    }

    const RedisConfig& getRedisConfig() const override {
        return redis_config_;
    }

    const UnitConfig& getUnitConfig() const override {
        return unit_config_;
    }

    const KeyVaultConfig& getKeyVaultConfig() const override {
        return keyvault_config_;
    }

    bool reloadConfig() override {
        loadStructuredConfig();
        return reader_->reloadConfig();
    }

    void addChangeCallback(std::function<void()> callback) override {
        reader_->addChangeCallback(std::move(callback));
    }

private:
    void loadStructuredConfig() {
        // Load Redis configuration
        redis_config_.host = reader_->getString("redis.host", "localhost");
        redis_config_.port = reader_->getInt("redis.port", 6379);
        redis_config_.password = reader_->getString("redis.password", "");
        redis_config_.connectionTimeout = reader_->getInt("redis.connectionTimeout", 5000);
        redis_config_.commandTimeout = reader_->getInt("redis.commandTimeout", 3000);
        redis_config_.enableSSL = reader_->getBool("redis.enableSSL", false);

        // Load Unit configuration
        unit_config_.unitId = reader_->getString("unit.id", "default-unit");
        unit_config_.unitType = reader_->getString("unit.type", "BaseUnit");
        unit_config_.logLevel = reader_->getString("unit.logLevel", "INFO");
        unit_config_.heartbeatInterval = reader_->getInt("unit.heartbeatInterval", 30000);
        unit_config_.enableMetrics = reader_->getBool("unit.enableMetrics", true);
        unit_config_.workingDirectory = reader_->getString("unit.workingDirectory", "/tmp/coyote");
        unit_config_.channels = reader_->getArray("unit.channels");
        unit_config_.customProperties = reader_->getObject("unit.customProperties");

        // Load KeyVault configuration
        keyvault_config_.url = reader_->getString("keyvault.url", "");
        keyvault_config_.unitRole = reader_->getString("keyvault.unitRole", "");
        keyvault_config_.caPath = reader_->getString("keyvault.caPath", "");
        keyvault_config_.clientCertPath = reader_->getString("keyvault.clientCertPath", "");
        keyvault_config_.clientKeyPath = reader_->getString("keyvault.clientKeyPath", "");
        keyvault_config_.enableMutualTLS = reader_->getBool("keyvault.enableMutualTLS", false);
        keyvault_config_.tokenRefreshInterval = reader_->getInt("keyvault.tokenRefreshInterval", 300000);
    }

public:
    // Mock-specific methods
    MockConfigReader* getMockReader() {
        return reader_.get();
    }
    
    void updateRedisConfig(const RedisConfig& config) {
        redis_config_ = config;
        // Update the underlying reader
        reader_->setString("redis.host", config.host);
        reader_->setInt("redis.port", config.port);
        reader_->setString("redis.password", config.password);
        reader_->setInt("redis.connectionTimeout", config.connectionTimeout);
        reader_->setInt("redis.commandTimeout", config.commandTimeout);
        reader_->setBool("redis.enableSSL", config.enableSSL);
    }
    
    void updateUnitConfig(const UnitConfig& config) {
        unit_config_ = config;
        // Update the underlying reader
        reader_->setString("unit.id", config.unitId);
        reader_->setString("unit.type", config.unitType);
        reader_->setString("unit.logLevel", config.logLevel);
        reader_->setInt("unit.heartbeatInterval", config.heartbeatInterval);
        reader_->setBool("unit.enableMetrics", config.enableMetrics);
        reader_->setString("unit.workingDirectory", config.workingDirectory);
        reader_->setArray("unit.channels", config.channels);
        reader_->setObject("unit.customProperties", config.customProperties);
    }
    
    void updateKeyVaultConfig(const KeyVaultConfig& config) {
        keyvault_config_ = config;
        // Update the underlying reader
        reader_->setString("keyvault.url", config.url);
        reader_->setString("keyvault.unitRole", config.unitRole);
        reader_->setString("keyvault.caPath", config.caPath);
        reader_->setString("keyvault.clientCertPath", config.clientCertPath);
        reader_->setString("keyvault.clientKeyPath", config.clientKeyPath);
        reader_->setBool("keyvault.enableMutualTLS", config.enableMutualTLS);
        reader_->setInt("keyvault.tokenRefreshInterval", config.tokenRefreshInterval);
    }
};

// Mock ConfigReader Factory
class MockConfigReaderFactory : public IConfigReaderFactory {
public:
    std::unique_ptr<IConfigReader> create(const std::string& configPath, ConfigFormat format) override {
        return std::make_unique<MockConfigReader>(configPath);
    }

    std::unique_ptr<IConfigReader> createJsonReader(const std::string& configPath) override {
        return std::make_unique<MockConfigReader>(configPath);
    }

    std::unique_ptr<IConfigReader> createYamlReader(const std::string& configPath) override {
        return std::make_unique<MockConfigReader>(configPath);
    }

    std::unique_ptr<ICoyoteConfig> createCoyoteConfig(std::unique_ptr<IConfigReader> reader) override {
        return std::make_unique<MockCoyoteConfig>(std::move(reader));
    }
};

} // namespace mocks
} // namespace infra
} // namespace coyote
