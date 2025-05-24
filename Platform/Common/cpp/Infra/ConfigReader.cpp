#include "ConfigReader.h"
#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <thread>
#include <mutex>

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
        m_config.clear();        // Flatten JSON structure for easier key access
        std::function<void(const nlohmann::json&, const std::string&)> flattenJson;
        flattenJson = [&](const nlohmann::json& obj, const std::string& prefix) {
            for (auto it = obj.begin(); it != obj.end(); ++it) {
                std::string key = prefix.empty() ? it.key() : prefix + "." + it.key();
                
                if (it.value().is_object()) {
                    // Store object as ConfigValue
                    std::unordered_map<std::string, std::string> objMap;
                    for (auto& [k, v] : it.value().items()) {
                        if (v.is_string()) {
                            objMap[k] = v.get<std::string>();
                        } else {
                            objMap[k] = v.dump();
                        }
                    }
                    m_config[key] = objMap;
                    // Also flatten for nested access
                    flattenJson(it.value(), key);
                } else if (it.value().is_array()) {
                    // Store array as ConfigValue
                    std::vector<std::string> arr;
                    for (const auto& item : it.value()) {
                        if (item.is_string()) {
                            arr.push_back(item.get<std::string>());
                        } else {
                            arr.push_back(item.dump());
                        }
                    }
                    m_config[key] = arr;
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

std::vector<std::string> JsonConfigReader::getArray(const std::string& key, const std::vector<std::string>& defaultValue) const {
    auto value = getValue(key);
    if (std::holds_alternative<std::vector<std::string>>(value)) {
        return std::get<std::vector<std::string>>(value);
    }
    return defaultValue;
}

std::unordered_map<std::string, std::string> JsonConfigReader::getObject(const std::string& key, const std::unordered_map<std::string, std::string>& defaultValue) const {
    auto value = getValue(key);
    if (std::holds_alternative<std::unordered_map<std::string, std::string>>(value)) {
        return std::get<std::unordered_map<std::string, std::string>>(value);
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

void JsonConfigReader::setArray(const std::string& key, const std::vector<std::string>& value) {
    setValue(key, value);
}

void JsonConfigReader::setObject(const std::string& key, const std::unordered_map<std::string, std::string>& value) {
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
            }            const std::string& lastKey = keys.back();
            std::visit([&](const auto& val) {
                using T = std::decay_t<decltype(val)>;
                if constexpr (std::is_same_v<T, std::vector<std::string>>) {
                    nlohmann::json arr = nlohmann::json::array();
                    for (const auto& item : val) {
                        arr.push_back(item);
                    }
                    (*current)[lastKey] = arr;
                } else if constexpr (std::is_same_v<T, std::unordered_map<std::string, std::string>>) {
                    nlohmann::json obj = nlohmann::json::object();
                    for (const auto& [k, v] : val) {
                        obj[k] = v;
                    }
                    (*current)[lastKey] = obj;
                } else {
                    (*current)[lastKey] = val;
                }
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

bool JsonConfigReader::fromJsonString(const std::string& jsonStr) {
    try {
        nlohmann::json jsonData = nlohmann::json::parse(jsonStr);
        m_config.clear();

        // Flatten JSON structure for easier key access
        std::function<void(const nlohmann::json&, const std::string&)> flattenJson;
        flattenJson = [&](const nlohmann::json& obj, const std::string& prefix) {
            for (auto it = obj.begin(); it != obj.end(); ++it) {
                std::string key = prefix.empty() ? it.key() : prefix + "." + it.key();
                
                if (it.value().is_object()) {
                    // Store object as ConfigValue
                    std::unordered_map<std::string, std::string> objMap;
                    for (auto& [k, v] : it.value().items()) {
                        if (v.is_string()) {
                            objMap[k] = v.get<std::string>();
                        } else {
                            objMap[k] = v.dump();
                        }
                    }
                    m_config[key] = objMap;
                    // Also flatten for nested access
                    flattenJson(it.value(), key);
                } else if (it.value().is_array()) {
                    // Store array as ConfigValue
                    std::vector<std::string> arr;
                    for (const auto& item : it.value()) {
                        if (item.is_string()) {
                            arr.push_back(item.get<std::string>());
                        } else {
                            arr.push_back(item.dump());
                        }
                    }
                    m_config[key] = arr;
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
        return true;

    } catch (const std::exception& e) {
        std::cerr << "Error parsing JSON string: " << e.what() << std::endl;
        return false;
    }
}

std::vector<std::string> JsonConfigReader::splitKey(const std::string& key) const {
    std::vector<std::string> result;
    std::stringstream ss(key);
    std::string item;

    while (std::getline(ss, item, '.')) {
        result.push_back(item);
    }    return result;
}

// YamlConfigReader implementation
YamlConfigReader::YamlConfigReader(const std::string& configPath) : m_configPath(configPath) {
    loadConfig(configPath);
}

bool YamlConfigReader::loadConfig(const std::string& configPath) {
    try {
        YAML::Node yamlData = YAML::LoadFile(configPath);
        m_configPath = configPath;
        m_config.clear();

        // Flatten YAML structure for easier key access
        std::function<void(const YAML::Node&, const std::string&)> flattenYaml;
        flattenYaml = [&](const YAML::Node& node, const std::string& prefix) {
            if (node.IsMap()) {
                for (const auto& item : node) {
                    std::string key = prefix.empty() ? item.first.as<std::string>() : prefix + "." + item.first.as<std::string>();
                    const YAML::Node& value = item.second;
                    
                    if (value.IsMap()) {
                        // Store object as ConfigValue
                        std::unordered_map<std::string, std::string> objMap;
                        for (const auto& mapItem : value) {
                            objMap[mapItem.first.as<std::string>()] = mapItem.second.as<std::string>();
                        }
                        m_config[key] = objMap;
                        // Also flatten for nested access
                        flattenYaml(value, key);
                    } else if (value.IsSequence()) {
                        // Store array as ConfigValue
                        std::vector<std::string> arr;
                        for (const auto& seqItem : value) {
                            arr.push_back(seqItem.as<std::string>());
                        }
                        m_config[key] = arr;
                    } else if (value.IsScalar()) {
                        std::string strValue = value.as<std::string>();
                        
                        // Try to determine the actual type
                        if (strValue == "true" || strValue == "false") {
                            m_config[key] = value.as<bool>();
                        } else if (strValue.find('.') != std::string::npos) {
                            try {
                                m_config[key] = value.as<double>();
                            } catch (...) {
                                m_config[key] = strValue;
                            }
                        } else {
                            try {
                                m_config[key] = value.as<int>();
                            } catch (...) {
                                m_config[key] = strValue;
                            }
                        }
                    }
                }
            }
        };

        flattenYaml(yamlData, "");
        std::cout << "Loaded YAML configuration from: " << configPath << std::endl;
        return true;

    } catch (const std::exception& e) {
        std::cerr << "Error loading YAML config: " << e.what() << std::endl;
        return false;
    }
}

bool YamlConfigReader::hasKey(const std::string& key) const {
    return m_config.find(key) != m_config.end();
}

std::string YamlConfigReader::getString(const std::string& key, const std::string& defaultValue) const {
    auto value = getValue(key);
    if (std::holds_alternative<std::string>(value)) {
        return std::get<std::string>(value);
    }
    return defaultValue;
}

int YamlConfigReader::getInt(const std::string& key, int defaultValue) const {
    auto value = getValue(key);
    if (std::holds_alternative<int>(value)) {
        return std::get<int>(value);
    } else if (std::holds_alternative<double>(value)) {
        return static_cast<int>(std::get<double>(value));
    }
    return defaultValue;
}

double YamlConfigReader::getDouble(const std::string& key, double defaultValue) const {
    auto value = getValue(key);
    if (std::holds_alternative<double>(value)) {
        return std::get<double>(value);
    } else if (std::holds_alternative<int>(value)) {
        return static_cast<double>(std::get<int>(value));
    }
    return defaultValue;
}

bool YamlConfigReader::getBool(const std::string& key, bool defaultValue) const {
    auto value = getValue(key);
    if (std::holds_alternative<bool>(value)) {
        return std::get<bool>(value);
    }
    return defaultValue;
}

std::vector<std::string> YamlConfigReader::getArray(const std::string& key, const std::vector<std::string>& defaultValue) const {
    auto value = getValue(key);
    if (std::holds_alternative<std::vector<std::string>>(value)) {
        return std::get<std::vector<std::string>>(value);
    }
    return defaultValue;
}

std::unordered_map<std::string, std::string> YamlConfigReader::getObject(const std::string& key, const std::unordered_map<std::string, std::string>& defaultValue) const {
    auto value = getValue(key);
    if (std::holds_alternative<std::unordered_map<std::string, std::string>>(value)) {
        return std::get<std::unordered_map<std::string, std::string>>(value);
    }
    return defaultValue;
}

void YamlConfigReader::setString(const std::string& key, const std::string& value) {
    setValue(key, value);
}

void YamlConfigReader::setInt(const std::string& key, int value) {
    setValue(key, value);
}

void YamlConfigReader::setDouble(const std::string& key, double value) {
    setValue(key, value);
}

void YamlConfigReader::setBool(const std::string& key, bool value) {
    setValue(key, value);
}

void YamlConfigReader::setArray(const std::string& key, const std::vector<std::string>& value) {
    setValue(key, value);
}

void YamlConfigReader::setObject(const std::string& key, const std::unordered_map<std::string, std::string>& value) {
    setValue(key, value);
}

bool YamlConfigReader::saveConfig(const std::string& configPath) {
    std::string path = configPath.empty() ? m_configPath : configPath;
    if (path.empty()) {
        std::cerr << "No config path specified for saving" << std::endl;
        return false;
    }

    try {
        YAML::Node yamlData;

        // Rebuild nested YAML structure from flattened config
        for (const auto& [key, value] : m_config) {
            auto keys = splitKey(key);
            YAML::Node current = yamlData;

            for (size_t i = 0; i < keys.size() - 1; ++i) {
                if (!current[keys[i]]) {
                    current[keys[i]] = YAML::Node(YAML::NodeType::Map);
                }
                current = current[keys[i]];
            }

            const std::string& lastKey = keys.back();
            std::visit([&](const auto& val) {
                using T = std::decay_t<decltype(val)>;
                if constexpr (std::is_same_v<T, std::vector<std::string>>) {
                    YAML::Node arr(YAML::NodeType::Sequence);
                    for (const auto& item : val) {
                        arr.push_back(item);
                    }
                    current[lastKey] = arr;
                } else if constexpr (std::is_same_v<T, std::unordered_map<std::string, std::string>>) {
                    YAML::Node obj(YAML::NodeType::Map);
                    for (const auto& [k, v] : val) {
                        obj[k] = v;
                    }
                    current[lastKey] = obj;
                } else {
                    current[lastKey] = val;
                }
            }, value);
        }

        std::ofstream file(path);
        if (!file.is_open()) {
            std::cerr << "Failed to open YAML config file for writing: " << path << std::endl;
            return false;
        }

        file << yamlData << std::endl;
        file.close();

        std::cout << "Saved YAML configuration to: " << path << std::endl;
        return true;

    } catch (const std::exception& e) {
        std::cerr << "Error saving YAML config: " << e.what() << std::endl;
        return false;
    }
}

ConfigValue YamlConfigReader::getValue(const std::string& key) const {
    auto it = m_config.find(key);
    if (it != m_config.end()) {
        return it->second;
    }
    return std::string{}; // Return empty string as default
}

void YamlConfigReader::setValue(const std::string& key, const ConfigValue& value) {
    m_config[key] = value;
}

std::vector<std::string> YamlConfigReader::splitKey(const std::string& key) const {
    std::vector<std::string> result;
    std::stringstream ss(key);
    std::string item;

    while (std::getline(ss, item, '.')) {
        result.push_back(item);
    }

    return result;
}

// ConfigReaderFactory implementation
std::unique_ptr<IConfigReader> ConfigReaderFactory::create(const std::string& configPath, ConfigFormat format) {
    ConfigFormat actualFormat = format;
    
    if (format == ConfigFormat::AUTO) {
        actualFormat = detectFormat(configPath);
    }
    
    switch (actualFormat) {
        case ConfigFormat::JSON:
            return std::make_unique<JsonConfigReader>(configPath);
        case ConfigFormat::YAML:
            return std::make_unique<YamlConfigReader>(configPath);
        default:
            throw std::invalid_argument("Unsupported config format");
    }
}

std::unique_ptr<IConfigReader> ConfigReaderFactory::createJsonReader(const std::string& configPath) {
    return std::make_unique<JsonConfigReader>(configPath);
}

std::unique_ptr<IConfigReader> ConfigReaderFactory::createYamlReader(const std::string& configPath) {
    return std::make_unique<YamlConfigReader>(configPath);
}

std::unique_ptr<ICoyoteConfig> ConfigReaderFactory::createCoyoteConfig(std::unique_ptr<IConfigReader> reader) {
    return std::make_unique<CoyoteConfig>(std::move(reader));
}

ConfigFormat ConfigReaderFactory::detectFormat(const std::string& configPath) {
    std::string extension = configPath.substr(configPath.find_last_of('.') + 1);
    std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
    
    if (extension == "json") {
        return ConfigFormat::JSON;
    } else if (extension == "yaml" || extension == "yml") {
        return ConfigFormat::YAML;
    }
    
    // Default to JSON if extension is unknown
    return ConfigFormat::JSON;
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

std::vector<std::string> CoyoteConfig::getArray(const std::string& key, const std::vector<std::string>& defaultValue) const {
    return m_reader ? m_reader->getArray(key, defaultValue) : defaultValue;
}

std::unordered_map<std::string, std::string> CoyoteConfig::getObject(const std::string& key, const std::unordered_map<std::string, std::string>& defaultValue) const {
    return m_reader ? m_reader->getObject(key, defaultValue) : defaultValue;
}

void CoyoteConfig::loadStructuredConfig() {
    if (!m_reader) return;

    // Load Redis configuration
    m_redisConfig.host = m_reader->getString("redis.host", "localhost");
    m_redisConfig.port = m_reader->getInt("redis.port", 6379);
    m_redisConfig.password = m_reader->getString("redis.password", "");
    m_redisConfig.connectionTimeout = m_reader->getInt("redis.connectionTimeout", 5000);
    m_redisConfig.commandTimeout = m_reader->getInt("redis.commandTimeout", 1000);
    m_redisConfig.enableSSL = m_reader->getBool("redis.enableSSL", false);    // Load Unit configuration
    m_unitConfig.unitId = m_reader->getString("unit.id", "");
    m_unitConfig.unitType = m_reader->getString("unit.type", "");
    m_unitConfig.logLevel = m_reader->getString("unit.logLevel", "INFO");
    m_unitConfig.heartbeatInterval = m_reader->getInt("unit.heartbeatInterval", 30000);
    m_unitConfig.enableMetrics = m_reader->getBool("unit.enableMetrics", true);
    m_unitConfig.workingDirectory = m_reader->getString("unit.workingDirectory", ".");
    m_unitConfig.channels = m_reader->getArray("unit.channels", {});
    m_unitConfig.customProperties = m_reader->getObject("unit.customProperties", {});

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
    m_reader->setBool("redis.enableSSL", m_redisConfig.enableSSL);    // Save Unit configuration
    m_reader->setString("unit.id", m_unitConfig.unitId);
    m_reader->setString("unit.type", m_unitConfig.unitType);
    m_reader->setString("unit.logLevel", m_unitConfig.logLevel);
    m_reader->setInt("unit.heartbeatInterval", m_unitConfig.heartbeatInterval);
    m_reader->setBool("unit.enableMetrics", m_unitConfig.enableMetrics);
    m_reader->setString("unit.workingDirectory", m_unitConfig.workingDirectory);
    m_reader->setArray("unit.channels", m_unitConfig.channels);
    m_reader->setObject("unit.customProperties", m_unitConfig.customProperties);

    // Save KeyVault configuration
    m_reader->setString("keyvault.url", m_keyVaultConfig.url);
    m_reader->setString("keyvault.unitRole", m_keyVaultConfig.unitRole);
    m_reader->setString("keyvault.caPath", m_keyVaultConfig.caPath);
    m_reader->setString("keyvault.clientCertPath", m_keyVaultConfig.clientCertPath);
    m_reader->setString("keyvault.clientKeyPath", m_keyVaultConfig.clientKeyPath);
    m_reader->setBool("keyvault.enableMutualTLS", m_keyVaultConfig.enableMutualTLS);
    m_reader->setInt("keyvault.tokenRefreshInterval", m_keyVaultConfig.tokenRefreshInterval);
}

// Hot-reload implementation for JsonConfigReader
void JsonConfigReader::startFileWatcher() {
    if (file_watcher_running_) {
        return; // Already running
    }
    
    file_watcher_running_ = true;
    last_write_time_ = std::filesystem::last_write_time(m_configPath);
    
    watcher_thread_ = std::thread([this]() {
        while (file_watcher_running_) {
            try {
                auto current_time = std::filesystem::last_write_time(m_configPath);
                if (current_time != last_write_time_) {
                    last_write_time_ = current_time;
                    
                    // Wait a bit to ensure file write is complete
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    
                    std::lock_guard<std::mutex> lock(config_mutex_);
                    if (loadConfig(m_configPath)) {
                        // Notify callbacks
                        for (auto& callback : change_callbacks_) {
                            try {
                                callback();
                            } catch (const std::exception& e) {
                                std::cerr << "Error in config change callback: " << e.what() << std::endl;
                            }
                        }
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "File watcher error: " << e.what() << std::endl;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    });
}

void JsonConfigReader::stopFileWatcher() {
    file_watcher_running_ = false;
    if (watcher_thread_.joinable()) {
        watcher_thread_.join();
    }
}

void JsonConfigReader::addChangeCallback(std::function<void()> callback) {
    change_callbacks_.push_back(std::move(callback));
}

// Hot-reload implementation for YamlConfigReader
void YamlConfigReader::startFileWatcher() {
    if (file_watcher_running_) {
        return; // Already running
    }
    
    file_watcher_running_ = true;
    last_write_time_ = std::filesystem::last_write_time(m_configPath);
    
    watcher_thread_ = std::thread([this]() {
        while (file_watcher_running_) {
            try {
                auto current_time = std::filesystem::last_write_time(m_configPath);
                if (current_time != last_write_time_) {
                    last_write_time_ = current_time;
                    
                    // Wait a bit to ensure file write is complete
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    
                    std::lock_guard<std::mutex> lock(config_mutex_);
                    if (loadConfig(m_configPath)) {
                        // Notify callbacks
                        for (auto& callback : change_callbacks_) {
                            try {
                                callback();
                            } catch (const std::exception& e) {
                                std::cerr << "Error in config change callback: " << e.what() << std::endl;
                            }
                        }
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "File watcher error: " << e.what() << std::endl;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    });
}

void YamlConfigReader::stopFileWatcher() {
    file_watcher_running_ = false;
    if (watcher_thread_.joinable()) {
        watcher_thread_.join();
    }
}

void YamlConfigReader::addChangeCallback(std::function<void()> callback) {
    change_callbacks_.push_back(std::move(callback));
}

} // namespace infra
} // namespace coyote
