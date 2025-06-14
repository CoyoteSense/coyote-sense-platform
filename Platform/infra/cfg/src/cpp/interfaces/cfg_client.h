#pragma once

#include <string>
#include <unordered_map>
#include <memory>
#include <variant>
#include <vector>
#include <functional>

namespace coyote {
namespace infra {

// Enhanced ConfigValue to support arrays and objects
using ConfigValue = std::variant<std::string, int, double, bool, std::vector<std::string>, std::unordered_map<std::string, std::string>>;

// Configuration format detection
enum class ConfigFormat {
    JSON,
    YAML,
    AUTO
};

// Configuration reader interface
class ConfigReader {
public:
    virtual ~IConfigReader() = default;
    
    // Core configuration operations
    virtual bool loadConfig(const std::string& configPath) = 0;
    virtual bool hasKey(const std::string& key) const = 0;
    
    // Getter methods
    virtual std::string getString(const std::string& key, const std::string& defaultValue = "") const = 0;
    virtual int getInt(const std::string& key, int defaultValue = 0) const = 0;
    virtual double getDouble(const std::string& key, double defaultValue = 0.0) const = 0;
    virtual bool getBool(const std::string& key, bool defaultValue = false) const = 0;
    virtual std::vector<std::string> getArray(const std::string& key, const std::vector<std::string>& defaultValue = {}) const = 0;
    virtual std::unordered_map<std::string, std::string> getObject(const std::string& key, const std::unordered_map<std::string, std::string>& defaultValue = {}) const = 0;
    
    // Setter methods
    virtual void setString(const std::string& key, const std::string& value) = 0;
    virtual void setInt(const std::string& key, int value) = 0;
    virtual void setDouble(const std::string& key, double value) = 0;
    virtual void setBool(const std::string& key, bool value) = 0;
    virtual void setArray(const std::string& key, const std::vector<std::string>& value) = 0;
    virtual void setObject(const std::string& key, const std::unordered_map<std::string, std::string>& value) = 0;
    
    // Persistence
    virtual bool saveConfig(const std::string& configPath = "") = 0;
    
    // Configuration watching and hot-reload
    virtual void setConfigWatcher(std::function<void()> callback) = 0;
    virtual void enableHotReload(bool enable) = 0;
    virtual bool isHotReloadEnabled() const = 0;
};

// Configuration structures
struct RedisConfig {
    std::string host = "localhost";
    int port = 6379;
    std::string password;
    int connectionTimeout = 5000;
    int commandTimeout = 1000;
    bool enableSSL = false;
};

struct KeyVaultConfig {
    std::string url = "https://vault:8201";
    std::string unitRole;
    std::string caPath;
    std::string clientCertPath;
    std::string clientKeyPath;
    bool enableMutualTLS = false;
    int tokenRefreshInterval = 300000;
};

struct UnitConfig {
    std::string unitId;
    std::string unitType;
    std::string logLevel = "INFO";
    int heartbeatInterval = 30000;
    bool enableMetrics = true;
    std::string workingDirectory = ".";
    std::vector<std::string> channels;
    std::unordered_map<std::string, std::string> customProperties;
};

// High-level configuration interface
class CoyoteConfig {
public:
    virtual ~ICoyoteConfig() = default;
    
    // File operations
    virtual bool loadFromFile(const std::string& configPath) = 0;
    virtual bool loadFromJson(const std::string& jsonStr) = 0;
    virtual bool saveToFile(const std::string& configPath = "") const = 0;
    
    // Direct key access (for custom configurations)
    virtual std::string getString(const std::string& key, const std::string& defaultValue = "") const = 0;
    virtual int getInt(const std::string& key, int defaultValue = 0) const = 0;
    virtual double getDouble(const std::string& key, double defaultValue = 0.0) const = 0;
    virtual bool getBool(const std::string& key, bool defaultValue = false) const = 0;
    virtual std::vector<std::string> getArray(const std::string& key, const std::vector<std::string>& defaultValue = {}) const = 0;
    virtual std::unordered_map<std::string, std::string> getObject(const std::string& key, const std::unordered_map<std::string, std::string>& defaultValue = {}) const = 0;
    
    // Structured configuration access
    virtual const RedisConfig& getRedisConfig() const = 0;
    virtual const KeyVaultConfig& getKeyVaultConfig() const = 0;
    virtual const UnitConfig& getUnitConfig() const = 0;
    
    virtual void setRedisConfig(const RedisConfig& config) = 0;
    virtual void setKeyVaultConfig(const KeyVaultConfig& config) = 0;
    virtual void setUnitConfig(const UnitConfig& config) = 0;
    
    // Hot-reload support
    virtual void enableConfigWatcher(bool enable) = 0;
    virtual void setConfigChangeCallback(std::function<void()> callback) = 0;
};

} // namespace infra
} // namespace coyote
