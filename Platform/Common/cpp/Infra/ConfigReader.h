#pragma once

#include <string>
#include <unordered_map>
#include <memory>
#include <variant>

namespace coyote {
namespace infra {

using ConfigValue = std::variant<std::string, int, double, bool>;

class IConfigReader {
public:
    virtual ~IConfigReader() = default;
    
    virtual bool loadConfig(const std::string& configPath) = 0;
    virtual bool hasKey(const std::string& key) const = 0;
    
    virtual std::string getString(const std::string& key, const std::string& defaultValue = "") const = 0;
    virtual int getInt(const std::string& key, int defaultValue = 0) const = 0;
    virtual double getDouble(const std::string& key, double defaultValue = 0.0) const = 0;
    virtual bool getBool(const std::string& key, bool defaultValue = false) const = 0;
    
    virtual void setString(const std::string& key, const std::string& value) = 0;
    virtual void setInt(const std::string& key, int value) = 0;
    virtual void setDouble(const std::string& key, double value) = 0;
    virtual void setBool(const std::string& key, bool value) = 0;
    
    virtual bool saveConfig(const std::string& configPath = "") = 0;
};

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
    
    void setString(const std::string& key, const std::string& value) override;
    void setInt(const std::string& key, int value) override;
    void setDouble(const std::string& key, double value) override;
    void setBool(const std::string& key, bool value) override;
    
    bool saveConfig(const std::string& configPath = "") override;

    // Additional utility methods
    void merge(const JsonConfigReader& other);
    std::string toJsonString() const;
    bool fromJsonString(const std::string& jsonStr);

private:
    std::unordered_map<std::string, ConfigValue> m_config;
    std::string m_configPath;
    
    std::vector<std::string> splitKey(const std::string& key) const;
    ConfigValue getValue(const std::string& key) const;
    void setValue(const std::string& key, const ConfigValue& value);
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

class CoyoteConfig {
public:
    CoyoteConfig() = default;
    explicit CoyoteConfig(const std::string& configPath);
    
    bool loadFromFile(const std::string& configPath);
    bool loadFromJson(const std::string& jsonStr);
    bool saveToFile(const std::string& configPath = "") const;
    
    // Configuration getters
    const RedisConfig& getRedisConfig() const { return m_redisConfig; }
    const UnitConfig& getUnitConfig() const { return m_unitConfig; }
    const KeyVaultConfig& getKeyVaultConfig() const { return m_keyVaultConfig; }
    
    // Configuration setters
    void setRedisConfig(const RedisConfig& config) { m_redisConfig = config; }
    void setUnitConfig(const UnitConfig& config) { m_unitConfig = config; }
    void setKeyVaultConfig(const KeyVaultConfig& config) { m_keyVaultConfig = config; }
    
    // Generic configuration access
    std::string getString(const std::string& key, const std::string& defaultValue = "") const;
    int getInt(const std::string& key, int defaultValue = 0) const;
    double getDouble(const std::string& key, double defaultValue = 0.0) const;
    bool getBool(const std::string& key, bool defaultValue = false) const;

private:
    std::unique_ptr<IConfigReader> m_reader;
    std::string m_configPath;
    
    RedisConfig m_redisConfig;
    UnitConfig m_unitConfig;
    KeyVaultConfig m_keyVaultConfig;
    
    void loadStructuredConfig();
    void saveStructuredConfig();
};

} // namespace infra
} // namespace coyote
