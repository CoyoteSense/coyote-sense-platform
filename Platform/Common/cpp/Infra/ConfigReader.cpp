#include "ConfigReader.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <sstream>

namespace coyote {
namespace infra {

JsonConfigReader::JsonConfigReader(const std::string& configPath) : m_configPath(configPath) {
    loadConfig(configPath);
}

bool JsonConfigReader::loadConfig(const std::string& configPath) {
    try {
        std::ifstream file(configPath);
        if (!file.is_open()) {
            std::cerr << "Failed to open config file: " << configPath << std::endl;
            return false;
        }

        nlohmann::json jsonData;
        file >> jsonData;
        file.close();

        m_configPath = configPath;
        m_config.clear();

        // Flatten JSON structure for easier key access
        std::function<void(const nlohmann::json&, const std::string&)> flattenJson;
        flattenJson = [&](const nlohmann::json& obj, const std::string& prefix) {
            for (auto it = obj.begin(); it != obj.end(); ++it) {
                std::string key = prefix.empty() ? it.key() : prefix + "." + it.key();
                
                if (it.value().is_object()) {
                    flattenJson(it.value(), key);
                } else if (it.value().is_string()) {
                    m_config[key] = it.value().get<std::string>();
                } else if (it.value().is_number_integer()) {
                    m_config[key] = it.value().get<int>();
                } else if (it.value().is_number_float()) {
                    m_config[key] = it.value().get<double>();
                } else if (it.value().is_boolean()) {
                    m_config[key] = it.value().get<bool>();
                }
            }
        };

        flattenJson(jsonData, "");
        std::cout << "Loaded configuration from: " << configPath << std::endl;
        return true;

    } catch (const std::exception& e) {
        std::cerr << "Error loading config: " << e.what() << std::endl;
        return false;
    }
}

bool JsonConfigReader::hasKey(const std::string& key) const {
    return m_config.find(key) != m_config.end();
}

std::string JsonConfigReader::getString(const std::string& key, const std::string& defaultValue) const {
    auto value = getValue(key);
    if (std::holds_alternative<std::string>(value)) {
        return std::get<std::string>(value);
    }
    return defaultValue;
}

int JsonConfigReader::getInt(const std::string& key, int defaultValue) const {
    auto value = getValue(key);
    if (std::holds_alternative<int>(value)) {
        return std::get<int>(value);
    } else if (std::holds_alternative<double>(value)) {
        return static_cast<int>(std::get<double>(value));
    }
    return defaultValue;
}

double JsonConfigReader::getDouble(const std::string& key, double defaultValue) const {
    auto value = getValue(key);
    if (std::holds_alternative<double>(value)) {
        return std::get<double>(value);
    } else if (std::holds_alternative<int>(value)) {
        return static_cast<double>(std::get<int>(value));
    }
    return defaultValue;
}

bool JsonConfigReader::getBool(const std::string& key, bool defaultValue) const {
    auto value = getValue(key);
    if (std::holds_alternative<bool>(value)) {
        return std::get<bool>(value);
    }
    return defaultValue;
}

void JsonConfigReader::setString(const std::string& key, const std::string& value) {
    setValue(key, value);
}

void JsonConfigReader::setInt(const std::string& key, int value) {
    setValue(key, value);
}

void JsonConfigReader::setDouble(const std::string& key, double value) {
    setValue(key, value);
}

void JsonConfigReader::setBool(const std::string& key, bool value) {
    setValue(key, value);
}

bool JsonConfigReader::saveConfig(const std::string& configPath) {
    std::string path = configPath.empty() ? m_configPath : configPath;
    if (path.empty()) {
        std::cerr << "No config path specified for saving" << std::endl;
        return false;
    }

    try {
        nlohmann::json jsonData;

        // Rebuild nested JSON structure from flattened config
        for (const auto& [key, value] : m_config) {
            auto keys = splitKey(key);
            nlohmann::json* current = &jsonData;

            for (size_t i = 0; i < keys.size() - 1; ++i) {
                current = &(*current)[keys[i]];
            }

            const std::string& lastKey = keys.back();
            std::visit([&](const auto& val) {
                (*current)[lastKey] = val;
            }, value);
        }

        std::ofstream file(path);
        if (!file.is_open()) {
            std::cerr << "Failed to open config file for writing: " << path << std::endl;
            return false;
        }

        file << jsonData.dump(4) << std::endl;
        file.close();

        std::cout << "Saved configuration to: " << path << std::endl;
        return true;

    } catch (const std::exception& e) {
        std::cerr << "Error saving config: " << e.what() << std::endl;
        return false;
    }
}

ConfigValue JsonConfigReader::getValue(const std::string& key) const {
    auto it = m_config.find(key);
    if (it != m_config.end()) {
        return it->second;
    }
    return std::string{}; // Return empty string as default
}

void JsonConfigReader::setValue(const std::string& key, const ConfigValue& value) {
    m_config[key] = value;
}

std::vector<std::string> JsonConfigReader::splitKey(const std::string& key) const {
    std::vector<std::string> result;
    std::stringstream ss(key);
    std::string item;

    while (std::getline(ss, item, '.')) {
        result.push_back(item);
    }

    return result;
}

// CoyoteConfig implementation
CoyoteConfig::CoyoteConfig(const std::string& configPath) : m_configPath(configPath) {
    m_reader = std::make_unique<JsonConfigReader>();
    loadFromFile(configPath);
}

bool CoyoteConfig::loadFromFile(const std::string& configPath) {
    if (!m_reader) {
        m_reader = std::make_unique<JsonConfigReader>();
    }

    if (!m_reader->loadConfig(configPath)) {
        return false;
    }

    m_configPath = configPath;
    loadStructuredConfig();
    return true;
}

bool CoyoteConfig::loadFromJson(const std::string& jsonStr) {
    if (!m_reader) {
        m_reader = std::make_unique<JsonConfigReader>();
    }

    auto jsonReader = dynamic_cast<JsonConfigReader*>(m_reader.get());
    if (!jsonReader || !jsonReader->fromJsonString(jsonStr)) {
        return false;
    }

    loadStructuredConfig();
    return true;
}

bool CoyoteConfig::saveToFile(const std::string& configPath) const {
    if (!m_reader) {
        return false;
    }

    std::string path = configPath.empty() ? m_configPath : configPath;
    return m_reader->saveConfig(path);
}

std::string CoyoteConfig::getString(const std::string& key, const std::string& defaultValue) const {
    return m_reader ? m_reader->getString(key, defaultValue) : defaultValue;
}

int CoyoteConfig::getInt(const std::string& key, int defaultValue) const {
    return m_reader ? m_reader->getInt(key, defaultValue) : defaultValue;
}

double CoyoteConfig::getDouble(const std::string& key, double defaultValue) const {
    return m_reader ? m_reader->getDouble(key, defaultValue) : defaultValue;
}

bool CoyoteConfig::getBool(const std::string& key, bool defaultValue) const {
    return m_reader ? m_reader->getBool(key, defaultValue) : defaultValue;
}

void CoyoteConfig::loadStructuredConfig() {
    if (!m_reader) return;

    // Load Redis configuration
    m_redisConfig.host = m_reader->getString("redis.host", "localhost");
    m_redisConfig.port = m_reader->getInt("redis.port", 6379);
    m_redisConfig.password = m_reader->getString("redis.password", "");
    m_redisConfig.connectionTimeout = m_reader->getInt("redis.connectionTimeout", 5000);
    m_redisConfig.commandTimeout = m_reader->getInt("redis.commandTimeout", 1000);
    m_redisConfig.enableSSL = m_reader->getBool("redis.enableSSL", false);

    // Load Unit configuration
    m_unitConfig.unitId = m_reader->getString("unit.id", "");
    m_unitConfig.unitType = m_reader->getString("unit.type", "");
    m_unitConfig.logLevel = m_reader->getString("unit.logLevel", "INFO");
    m_unitConfig.heartbeatInterval = m_reader->getInt("unit.heartbeatInterval", 30000);
    m_unitConfig.enableMetrics = m_reader->getBool("unit.enableMetrics", true);
    m_unitConfig.workingDirectory = m_reader->getString("unit.workingDirectory", ".");

    // Load KeyVault configuration
    m_keyVaultConfig.url = m_reader->getString("keyvault.url", "https://vault:8201");
    m_keyVaultConfig.unitRole = m_reader->getString("keyvault.unitRole", "");
    m_keyVaultConfig.caPath = m_reader->getString("keyvault.caPath", "");
    m_keyVaultConfig.clientCertPath = m_reader->getString("keyvault.clientCertPath", "");
    m_keyVaultConfig.clientKeyPath = m_reader->getString("keyvault.clientKeyPath", "");
    m_keyVaultConfig.enableMutualTLS = m_reader->getBool("keyvault.enableMutualTLS", false);
    m_keyVaultConfig.tokenRefreshInterval = m_reader->getInt("keyvault.tokenRefreshInterval", 300000);
}

void CoyoteConfig::saveStructuredConfig() {
    if (!m_reader) return;

    // Save Redis configuration
    m_reader->setString("redis.host", m_redisConfig.host);
    m_reader->setInt("redis.port", m_redisConfig.port);
    m_reader->setString("redis.password", m_redisConfig.password);
    m_reader->setInt("redis.connectionTimeout", m_redisConfig.connectionTimeout);
    m_reader->setInt("redis.commandTimeout", m_redisConfig.commandTimeout);
    m_reader->setBool("redis.enableSSL", m_redisConfig.enableSSL);

    // Save Unit configuration
    m_reader->setString("unit.id", m_unitConfig.unitId);
    m_reader->setString("unit.type", m_unitConfig.unitType);
    m_reader->setString("unit.logLevel", m_unitConfig.logLevel);
    m_reader->setInt("unit.heartbeatInterval", m_unitConfig.heartbeatInterval);
    m_reader->setBool("unit.enableMetrics", m_unitConfig.enableMetrics);
    m_reader->setString("unit.workingDirectory", m_unitConfig.workingDirectory);

    // Save KeyVault configuration
    m_reader->setString("keyvault.url", m_keyVaultConfig.url);
    m_reader->setString("keyvault.unitRole", m_keyVaultConfig.unitRole);
    m_reader->setString("keyvault.caPath", m_keyVaultConfig.caPath);
    m_reader->setString("keyvault.clientCertPath", m_keyVaultConfig.clientCertPath);
    m_reader->setString("keyvault.clientKeyPath", m_keyVaultConfig.clientKeyPath);
    m_reader->setBool("keyvault.enableMutualTLS", m_keyVaultConfig.enableMutualTLS);
    m_reader->setInt("keyvault.tokenRefreshInterval", m_keyVaultConfig.tokenRefreshInterval);
}

} // namespace infra
} // namespace coyote
