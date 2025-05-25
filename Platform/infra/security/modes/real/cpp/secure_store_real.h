#pragma once

#include "ISecureStore.h"
#include "IHttpClient.h"
#include <memory>
#include <string>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <chrono>
#include <thread>

namespace coyote {
namespace infra {

// Concrete implementation of SecureStore metrics
class SecureStoreMetrics : public ISecureStoreMetrics {
private:
    std::atomic<size_t> total_requests_{0};
    std::atomic<size_t> successful_requests_{0};
    std::atomic<size_t> failed_requests_{0};
    std::atomic<double> avg_response_time_ms_{0.0};
    std::atomic<size_t> cache_hits_{0};
    std::atomic<size_t> cache_misses_{0};
    std::atomic<bool> is_connected_{false};
    mutable std::mutex metrics_mutex_;
    std::chrono::steady_clock::time_point start_time_;

public:
    SecureStoreMetrics() : start_time_(std::chrono::steady_clock::now()) {}

    size_t getTotalRequests() const override { return total_requests_.load(); }
    size_t getSuccessfulRequests() const override { return successful_requests_.load(); }
    size_t getFailedRequests() const override { return failed_requests_.load(); }
    double getAverageResponseTime() const override { return avg_response_time_ms_.load(); }
    size_t getCacheHits() const override { return cache_hits_.load(); }
    size_t getCacheMisses() const override { return cache_misses_.load(); }
    bool isConnected() const override { return is_connected_.load(); }
    
    std::chrono::steady_clock::time_point getStartTime() const override {
        return start_time_;
    }

    void incrementTotalRequests() { total_requests_++; }
    void incrementSuccessfulRequests() { successful_requests_++; }
    void incrementFailedRequests() { failed_requests_++; }
    void updateResponseTime(double time_ms) {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        auto current_avg = avg_response_time_ms_.load();
        auto total = total_requests_.load();
        if (total > 0) {
            avg_response_time_ms_ = (current_avg * (total - 1) + time_ms) / total;
        } else {
            avg_response_time_ms_ = time_ms;
        }
    }
    void incrementCacheHits() { cache_hits_++; }
    void incrementCacheMisses() { cache_misses_++; }
    void setConnected(bool connected) { is_connected_ = connected; }
};

// Azure Key Vault implementation of ISecureStore
class KeyVaultSecureStore : public ISecureStore {
private:
    std::unique_ptr<IHttpClient> http_client_;
    SecureStoreConfig config_;
    std::unique_ptr<SecureStoreMetrics> metrics_;
    mutable std::mutex cache_mutex_;
    std::unordered_map<std::string, std::string> secret_cache_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> cache_timestamps_;
    std::chrono::minutes cache_ttl_;
    std::string access_token_;
    std::chrono::steady_clock::time_point token_expiry_;
    mutable std::mutex token_mutex_;

    // Private methods
    std::string getAccessToken();
    bool isTokenExpired() const;
    void refreshTokenIfNeeded();
    std::string buildSecretUrl(const std::string& secretName, const std::string& version = "") const;
    bool isCacheValid(const std::string& key) const;
    void updateCache(const std::string& key, const std::string& value);

public:
    explicit KeyVaultSecureStore(const SecureStoreConfig& config, 
                                std::unique_ptr<IHttpClient> httpClient);
    ~KeyVaultSecureStore() override = default;    bool getSecret(const std::string& secretName, std::string& value, const std::string& version = "") override;
    bool setSecret(const std::string& secretName, const std::string& value) override;
    bool deleteSecret(const std::string& secretName) override;
    std::vector<std::string> listSecrets() override;
    bool hasSecret(const std::string& secretName) override;
    
    bool isConnected() const override;
    bool testConnection() override;
    void clearCache() override;
    std::shared_ptr<ISecureStoreMetrics> getMetrics() override;
};

// SecureStore Factory implementation
class SecureStoreFactory : public ISecureStoreFactory {
public:
    std::unique_ptr<ISecureStore> create(const SecureStoreConfig& config) override;
    std::unique_ptr<ISecureStore> createKeyVault(const SecureStoreConfig& config, 
                                                std::unique_ptr<IHttpClient> httpClient) override;
};

} // namespace infra
} // namespace coyote
