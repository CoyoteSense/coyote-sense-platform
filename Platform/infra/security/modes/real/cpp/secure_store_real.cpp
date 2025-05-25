#include "SecureStore.h"
#include "HttpClient.h"
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <iomanip>
#include <sstream>

namespace coyote {
namespace infra {

// KeyVaultSecureStore implementation
KeyVaultSecureStore::KeyVaultSecureStore(const SecureStoreConfig& config, 
                                        std::unique_ptr<IHttpClient> httpClient)
    : config_(config)
    , http_client_(std::move(httpClient))
    , metrics_(std::make_unique<SecureStoreMetrics>())
    , cache_ttl_(config.cache_ttl_minutes)
{
    if (!http_client_) {
        throw std::invalid_argument("HTTP client cannot be null");
    }
    
    if (config_.key_vault_url.empty()) {
        throw std::invalid_argument("Key Vault URL cannot be empty");
    }

    // Set up HTTP client defaults
    std::unordered_map<std::string, std::string> defaultHeaders = {
        {"Content-Type", "application/json"},
        {"Accept", "application/json"}
    };
    http_client_->setDefaultHeaders(defaultHeaders);
    http_client_->setUserAgent("CoyoteSense-SecureStore/1.0");
}

bool KeyVaultSecureStore::getSecret(const std::string& secretName, std::string& value, const std::string& version) {
    auto start_time = std::chrono::steady_clock::now();
    metrics_->incrementTotalRequests();

    try {
        // Check cache first
        {
            std::lock_guard<std::mutex> lock(cache_mutex_);
            if (isCacheValid(secretName)) {
                value = secret_cache_[secretName];
                metrics_->incrementCacheHits();
                metrics_->incrementSuccessfulRequests();
                return true;
            }
            metrics_->incrementCacheMisses();
        }        
        std::string url = buildSecretUrl(secretName, version);
        
        auto request = std::make_unique<HttpRequest>();
        request->setUrl(url);
        request->setMethod(HttpMethod::GET);
        request->addHeader("Authorization", "Bearer " + access_token_);
        request->setTimeout(config_.request_timeout_seconds);
        
        auto response = http_client_->execute(*request);
        
        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        metrics_->updateResponseTime(duration.count());

        if (response->isSuccess() && response->getStatusCode() == 200) {
            // Parse JSON response
            nlohmann::json root;
            root = nlohmann::json::parse(response->getBody());
            if (root.contains("value")) {
                value = root["value"].get<std::string>();
                updateCache(secretName, value);
                metrics_->incrementSuccessfulRequests();
                metrics_->setConnected(true);
                return true;
            }
        }
        
        metrics_->incrementFailedRequests();
        metrics_->setConnected(false);
        return false;
        
    } catch (const std::exception& e) {
        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        metrics_->updateResponseTime(duration.count());
        metrics_->incrementFailedRequests();
        metrics_->setConnected(false);
        return false;
    }
}

bool KeyVaultSecureStore::setSecret(const std::string& secretName, const std::string& value) {
    auto start_time = std::chrono::steady_clock::now();
    metrics_->incrementTotalRequests();

    try {
        refreshTokenIfNeeded();
        
        std::string url = buildSecretUrl(secretName);
        
        nlohmann::json jsonBody;
        jsonBody["value"] = value;
        std::string body = jsonBody.dump();
        
        auto request = std::make_unique<HttpRequest>();
        request->setUrl(url);
        request->setMethod(HttpMethod::PUT);
        request->addHeader("Authorization", "Bearer " + access_token_);
        request->setBody(body);
        request->setTimeout(config_.request_timeout_seconds);
        
        auto response = http_client_->execute(*request);
        
        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        metrics_->updateResponseTime(duration.count());

        if (response->isSuccess() && (response->getStatusCode() == 200 || response->getStatusCode() == 201)) {
            updateCache(secretName, value);
            metrics_->incrementSuccessfulRequests();
            metrics_->setConnected(true);
            return true;
        }
        
        metrics_->incrementFailedRequests();
        metrics_->setConnected(false);
        return false;
        
    } catch (const std::exception& e) {
        
bool KeyVaultSecureStore::deleteSecret(const std::string& secretName) {
    auto start_time = std::chrono::steady_clock::now();
    metrics_->incrementTotalRequests();

    try {
        refreshTokenIfNeeded();
        
        std::string url = buildSecretUrl(secretName);
        
        auto request = std::make_unique<HttpRequest>();
        request->setUrl(url);
        request->setMethod(HttpMethod::DELETE);
        request->addHeader("Authorization", "Bearer " + access_token_);
        request->setTimeout(config_.request_timeout_seconds);
        
        auto response = http_client_->execute(*request);
        
        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        metrics_->updateResponseTime(duration.count());

        if (response->isSuccess() && response->getStatusCode() == 200) {
            // Remove from cache
            {
                std::lock_guard<std::mutex> lock(cache_mutex_);
                secret_cache_.erase(secretName);
                cache_timestamps_.erase(secretName);
            }
            metrics_->incrementSuccessfulRequests();
            metrics_->setConnected(true);
            return true;
        }
        
        metrics_->incrementFailedRequests();
        metrics_->setConnected(false);
        return false;
        
    } catch (const std::exception& e) {
        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        metrics_->updateResponseTime(duration.count());
        metrics_->incrementFailedRequests();
        metrics_->setConnected(false);
        return false;
    }
}

std::vector<std::string> KeyVaultSecureStore::listSecrets() {
    std::vector<std::string> secrets;
    auto start_time = std::chrono::steady_clock::now();
    metrics_->incrementTotalRequests();

    try {
        refreshTokenIfNeeded();
        
        std::string url = config_.key_vault_url + "/secrets?api-version=" + config_.api_version;
        
        auto request = std::make_unique<HttpRequest>();
        request->setUrl(url);
        request->setMethod(HttpMethod::GET);
        request->addHeader("Authorization", "Bearer " + access_token_);
        request->setTimeout(config_.request_timeout_seconds);
        
        auto response = http_client_->execute(*request);
        
        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        metrics_->updateResponseTime(duration.count());

        if (response->isSuccess() && response->getStatusCode() == 200) {
            nlohmann::json root = nlohmann::json::parse(response->getBody());
            if (root.contains("value") && root["value"].is_array()) {
                for (const auto& item : root["value"]) {
                    if (item.contains("id")) {
                        std::string id = item["id"].get<std::string>();
                        // Extract secret name from the full ID
                        size_t lastSlash = id.find_last_of('/');
                        if (lastSlash != std::string::npos) {
                            secrets.push_back(id.substr(lastSlash + 1));
                        }
                    }
                }
            }
            metrics_->incrementSuccessfulRequests();
            metrics_->setConnected(true);
        } else {
            metrics_->incrementFailedRequests();
            metrics_->setConnected(false);
        }
        
    bool KeyVaultSecureStore::hasSecret(const std::string& secretName) {
    // Check cache first
    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        if (isCacheValid(secretName)) {
            return true;
        }
    }
    
    // Try to get the secret
    std::string value;
    return getSecret(secretName, value);
}

bool KeyVaultSecureStore::isConnected() const {
    return metrics_->isConnected();
}

bool KeyVaultSecureStore::testConnection() {
    try {
        refreshTokenIfNeeded();
        
        // Try to list secrets as a connection test
        std::string url = config_.key_vault_url + "/secrets?api-version=" + config_.api_version + "&maxresults=1";
        
        auto request = std::make_unique<HttpRequest>();
        request->setUrl(url);
        request->setMethod(HttpMethod::GET);
        request->addHeader("Authorization", "Bearer " + access_token_);
        request->setTimeout(5); // Short timeout for connection test
        
        auto response = http_client_->execute(*request);
        
        bool connected = response->isSuccess() && response->getStatusCode() == 200;
        metrics_->setConnected(connected);
        return connected;
        
    } catch (const std::exception& e) {
        metrics_->setConnected(false);
        return false;
    }
}

void KeyVaultSecureStore::clearCache() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    secret_cache_.clear();
    cache_timestamps_.clear();
}

std::shared_ptr<ISecureStoreMetrics> KeyVaultSecureStore::getMetrics() {
    return metrics_;
}

// Private helper methods
std::string KeyVaultSecureStore::getAccessToken() {
    // Implementation depends on authentication method (managed identity, service principal, etc.)
    
    if (!config_.client_id.empty() && !config_.client_secret.empty()) {
        // Service principal authentication
        std::string url = "https://login.microsoftonline.com/" + config_.tenant_id + "/oauth2/v2.0/token";
        
        auto request = std::make_unique<HttpRequest>();
        request->setUrl(url);
        request->setMethod(HttpMethod::POST);
        request->addHeader("Content-Type", "application/x-www-form-urlencoded");
        
        std::stringstream body;
        body << "grant_type=client_credentials"
             << "&client_id=" << config_.client_id
             << "&client_secret=" << config_.client_secret
             << "&scope=https://vault.azure.net/.default";
        
        request->setBody(body.str());
        request->setTimeout(config_.request_timeout_seconds);
        
        auto response = http_client_->execute(*request);
        
        if (response->isSuccess() && response->getStatusCode() == 200) {
            nlohmann::json root = nlohmann::json::parse(response->getBody());
            if (root.contains("access_token")) {
                // Calculate expiry time
                int expiresIn = root.value("expires_in", 3600);
                token_expiry_ = std::chrono::steady_clock::now() + std::chrono::seconds(expiresIn - 300); // 5 min buffer
                
                return root["access_token"].get<std::string>();
            }
        }
    }
    
    throw std::runtime_error("Failed to obtain access token");
}

bool KeyVaultSecureStore::isTokenExpired() const {
    return std::chrono::steady_clock::now() >= token_expiry_;
}

void KeyVaultSecureStore::refreshTokenIfNeeded() {
    std::lock_guard<std::mutex> lock(token_mutex_);
    if (access_token_.empty() || isTokenExpired()) {
        access_token_ = getAccessToken();
    }
}

std::string KeyVaultSecureStore::buildSecretUrl(const std::string& secretName, const std::string& version) const {
    std::string url = config_.key_vault_url + "/secrets/" + secretName;
    if (!version.empty()) {
        url += "/" + version;
    }
    url += "?api-version=" + config_.api_version;
    return url;
}

bool KeyVaultSecureStore::isCacheValid(const std::string& key) const {
    auto it = cache_timestamps_.find(key);
    if (it == cache_timestamps_.end()) {
        return false;
    }
    
    auto age = std::chrono::steady_clock::now() - it->second;
    return age < cache_ttl_;
}

void KeyVaultSecureStore::updateCache(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    secret_cache_[key] = value;
    cache_timestamps_[key] = std::chrono::steady_clock::now();
}

// SecureStoreFactory implementation
std::unique_ptr<ISecureStore> SecureStoreFactory::create(const SecureStoreConfig& config) {
    auto httpClient = std::make_unique<CurlHttpClient>();
    return createKeyVault(config, std::move(httpClient));
}

std::unique_ptr<ISecureStore> SecureStoreFactory::createKeyVault(const SecureStoreConfig& config, 
                                                               std::unique_ptr<IHttpClient> httpClient) {
    return std::make_unique<KeyVaultSecureStore>(config, std::move(httpClient));
}

} // namespace infra
} // namespace coyote
