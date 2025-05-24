#pragma once

#include "IConfigReader.h"
#include <string>
#include <unordered_map>
#include <memory>
#include <variant>
#include <vector>
#include <filesystem>
#include <thread>
#include <atomic>
#include <functional>

namespace coyote {
namespace infra {

// Remove duplicate declarations since they're in IConfigReader.h now

class JsonConfigReader : public IConfigReader {
public:
    JsonConfigReader() = default;
    explicit JsonConfigReader(const std::string& configPath);
    ~JsonConfigReader() override = default;

    // IConfigReader implementation
    bool loadConfig(const std::string& configPath) override;
    bool hasKey(const std::string& key) const override;
    
    std::string getString(const std::string& key, const std::string& defaultValue = "") const override;
    int getInt(const std::string& key, int defaultValue = 0) const override;
    double getDouble(const std::string& key, double defaultValue = 0.0) const override;
    bool getBool(const std::string& key, bool defaultValue = false) const override;
    std::vector<std::string> getArray(const std::string& key, const std::vector<std::string>& defaultValue = {}) const override;
    std::unordered_map<std::string, std::string> getObject(const std::string& key, const std::unordered_map<std::string, std::string>& defaultValue = {}) const override;
    
    void setString(const std::string& key, const std::string& value) override;
    void setInt(const std::string& key, int value) override;
    void setDouble(const std::string& key, double value) override;
    void setBool(const std::string& key, bool value) override;
    void setArray(const std::string& key, const std::vector<std::string>& value) override;
    void setObject(const std::string& key, const std::unordered_map<std::string, std::string>& value) override;
      bool saveConfig(const std::string& configPath = "") override;

    // IConfigReader hot-reload implementation
    void setConfigWatcher(std::function<void()> callback) override;
    void enableHotReload(bool enable) override;
    bool isHotReloadEnabled() const override;

    // Additional utility methods
    void merge(const JsonConfigReader& other);
    std::string toJsonString() const;    bool fromJsonString(const std::string& jsonStr);

private:
    std::unordered_map<std::string, ConfigValue> m_config;
    std::string m_configPath;
    
    // Hot-reload support
    std::atomic<bool> m_hotReloadEnabled{false};
    std::thread m_watcherThread;
    std::function<void()> m_changeCallback;
    std::filesystem::file_time_type m_lastWriteTime;
    
    std::vector<std::string> splitKey(const std::string& key) const;
    ConfigValue getValue(const std::string& key) const;
    void setValue(const std::string& key, const ConfigValue& value);
    void startFileWatcher();
    void stopFileWatcher();
    void watcherLoop();
};

// New YAML Config Reader
class YamlConfigReader : public IConfigReader {
public:
    YamlConfigReader() = default;
    explicit YamlConfigReader(const std::string& configPath);
    ~YamlConfigReader() override = default;

    // IConfigReader implementation
    bool loadConfig(const std::string& configPath) override;
    bool hasKey(const std::string& key) const override;
    
    std::string getString(const std::string& key, const std::string& defaultValue = "") const override;
    int getInt(const std::string& key, int defaultValue = 0) const override;
    double getDouble(const std::string& key, double defaultValue = 0.0) const override;
    bool getBool(const std::string& key, bool defaultValue = false) const override;
    std::vector<std::string> getArray(const std::string& key, const std::vector<std::string>& defaultValue = {}) const override;
    std::unordered_map<std::string, std::string> getObject(const std::string& key, const std::unordered_map<std::string, std::string>& defaultValue = {}) const override;
    
    void setString(const std::string& key, const std::string& value) override;
    void setInt(const std::string& key, int value) override;
    void setDouble(const std::string& key, double value) override;
    void setBool(const std::string& key, bool value) override;
    void setArray(const std::string& key, const std::vector<std::string>& value) override;
    void setObject(const std::string& key, const std::unordered_map<std::string, std::string>& value) override;
      bool saveConfig(const std::string& configPath = "") override;

    // IConfigReader hot-reload implementation
    void setConfigWatcher(std::function<void()> callback) override;
    void enableHotReload(bool enable) override;
    bool isHotReloadEnabled() const override;

    // Additional utility methods
    void merge(const YamlConfigReader& other);
    std::string toYamlString() const;
    bool fromYamlString(const std::string& yamlStr);

private:
    std::unordered_map<std::string, ConfigValue> m_config;
    std::string m_configPath;
    
    // Hot-reload support  
    std::atomic<bool> m_hotReloadEnabled{false};
    std::thread m_watcherThread;
    std::function<void()> m_changeCallback;
    std::filesystem::file_time_type m_lastWriteTime;
    
    std::vector<std::string> splitKey(const std::string& key) const;
    ConfigValue getValue(const std::string& key) const;
    void setValue(const std::string& key, const ConfigValue& value);
    void parseYamlNode(const void* node, const std::string& prefix = "");
    void startFileWatcher();
    void stopFileWatcher();
    void watcherLoop();
};

// Configuration sections for CoyoteSense units
struct RedisConfig {
    std::string host = "localhost";
    int port = 6379;
    std::string password = "";
    int connectionTimeout = 5000;
    int commandTimeout = 1000;
    bool enableSSL = false;
};

struct UnitConfig {
    std::string unitId;
    std::string unitType;
    std::string logLevel = "INFO";
    int heartbeatInterval = 30000; // milliseconds
    bool enableMetrics = true;
    std::string workingDirectory = ".";
    std::vector<std::string> channels; // Additional channels to subscribe
    std::unordered_map<std::string, std::string> customProperties; // Custom unit properties
};

struct KeyVaultConfig {
    std::string url = "https://vault:8201";
    std::string unitRole;
    std::string caPath = "";
    std::string clientCertPath = "";
    std::string clientKeyPath = "";
    bool enableMutualTLS = false;
    int tokenRefreshInterval = 300000; // 5 minutes in milliseconds
};

// Enhanced CoyoteConfig with file watching and hot reload
class CoyoteConfig : public ICoyoteConfig {
public:    CoyoteConfig() = default;
    explicit CoyoteConfig(const std::string& configPath);
    ~CoyoteConfig() override = default;
    
    // ICoyoteConfig implementation
    bool loadFromFile(const std::string& configPath) override;
    bool loadFromJson(const std::string& jsonStr) override;
    bool saveToFile(const std::string& configPath = "") const override;
      // Configuration getters
    const RedisConfig& getRedisConfig() const override { return m_redisConfig; }
    const UnitConfig& getUnitConfig() const override { return m_unitConfig; }
    const KeyVaultConfig& getKeyVaultConfig() const override { return m_keyVaultConfig; }
    
    // Configuration setters
    void setRedisConfig(const RedisConfig& config) override { m_redisConfig = config; }
    void setUnitConfig(const UnitConfig& config) override { m_unitConfig = config; }
    void setKeyVaultConfig(const KeyVaultConfig& config) override { m_keyVaultConfig = config; }
    
    // Generic configuration access
    std::string getString(const std::string& key, const std::string& defaultValue = "") const override;
    int getInt(const std::string& key, int defaultValue = 0) const override;
    double getDouble(const std::string& key, double defaultValue = 0.0) const override;
    bool getBool(const std::string& key, bool defaultValue = false) const override;
    std::vector<std::string> getArray(const std::string& key, const std::vector<std::string>& defaultValue = {}) const override;
    std::unordered_map<std::string, std::string> getObject(const std::string& key, const std::unordered_map<std::string, std::string>& defaultValue = {}) const override;
    
    // Hot reload functionality
    void enableConfigWatcher(bool enable) override;
    void setConfigChangeCallback(std::function<void()> callback) override;
    
    // File format detection
    enum class ConfigFormat { JSON, YAML, AUTO };
    static ConfigFormat detectFormat(const std::string& configPath);

private:
    std::unique_ptr<IConfigReader> m_reader;
    std::string m_configPath;
    ConfigFormat m_format = ConfigFormat::AUTO;
    
    RedisConfig m_redisConfig;
    UnitConfig m_unitConfig;
    KeyVaultConfig m_keyVaultConfig;
    
    // Hot reload support
    bool m_hotReloadEnabled = false;
    std::thread m_watcherThread;
    std::atomic<bool> m_watcherRunning{false};
    std::function<void()> m_onConfigChanged;
    std::chrono::file_time_type m_lastModified;
    
    void loadStructuredConfig();
    void saveStructuredConfig();
    void watchConfigFile();    void createReaderForFormat(ConfigFormat format);
};

// Factory implementations
class ConfigReaderFactory : public IConfigReaderFactory {
public:
    std::unique_ptr<IConfigReader> createReader(const std::string& filePath, ConfigFormat format = ConfigFormat::AUTO) override;
    std::unique_ptr<ICoyoteConfig> createCoyoteConfig(const std::string& filePath = "") override;
    ConfigFormat detectFormat(const std::string& filePath) override;
};

} // namespace infra
} // namespace coyote
