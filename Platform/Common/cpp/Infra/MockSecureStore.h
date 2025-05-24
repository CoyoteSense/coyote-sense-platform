#pragma once

#include "ISecureStore.h"
#include <unordered_map>
#include <vector>
#include <mutex>
#include <atomic>
#include <chrono>

namespace coyote {
namespace infra {
namespace mocks {

// Mock SecureStore Metrics implementation
class MockSecureStoreMetrics : public ISecureStoreMetrics {
private:
    std::atomic<size_t> total_requests_{0};
    std::atomic<size_t> successful_requests_{0};
    std::atomic<size_t> failed_requests_{0};
    std::atomic<double> avg_response_time_ms_{5.0};
    std::atomic<size_t> cache_hits_{0};
    std::atomic<size_t> cache_misses_{0};
    std::atomic<bool> is_connected_{true};
    std::chrono::steady_clock::time_point start_time_;

public:
    MockSecureStoreMetrics() : start_time_(std::chrono::steady_clock::now()) {}

    size_t getTotalRequests() const override { return total_requests_.load(); }
    size_t getSuccessfulRequests() const override { return successful_requests_.load(); }
    size_t getFailedRequests() const override { return failed_requests_.load(); }
    double getAverageResponseTime() const override { return avg_response_time_ms_.load(); }
    size_t getCacheHits() const override { return cache_hits_.load(); }
    size_t getCacheMisses() const override { return cache_misses_.load(); }
    bool isConnected() const override { return is_connected_.load(); }
    std::chrono::steady_clock::time_point getStartTime() const override { return start_time_; }

    void incrementTotalRequests() { total_requests_++; }
    void incrementSuccessfulRequests() { successful_requests_++; }
    void incrementFailedRequests() { failed_requests_++; }
    void incrementCacheHits() { cache_hits_++; }
    void incrementCacheMisses() { cache_misses_++; }
    void setConnected(bool connected) { is_connected_ = connected; }
    void setResponseTime(double time_ms) { avg_response_time_ms_ = time_ms; }
};

// Mock SecureStore implementation
class MockSecureStore : public ISecureStore {
private:
    mutable std::mutex secrets_mutex_;
    std::unordered_map<std::string, std::string> secrets_;
    std::unique_ptr<MockSecureStoreMetrics> metrics_;
    bool connected_ = true;
    bool simulate_failures_ = false;
    std::string failure_error_message_ = "Mock SecureStore failure";
    
    // Simulate operation delays
    std::chrono::milliseconds operation_delay_{0};

public:
    MockSecureStore() : metrics_(std::make_unique<MockSecureStoreMetrics>()) {
        // Pre-populate with some test secrets
        secrets_["test-secret"] = "test-value";
        secrets_["database-password"] = "super-secret-password";
        secrets_["api-key"] = "mock-api-key-12345";
    }

    bool getSecret(const std::string& secretName, std::string& value, const std::string& version = "") override {
        std::lock_guard<std::mutex> lock(secrets_mutex_);
        metrics_->incrementTotalRequests();
        
        // Simulate delay if configured
        if (operation_delay_.count() > 0) {
            std::this_thread::sleep_for(operation_delay_);
        }
        
        if (!connected_ || simulate_failures_) {
            metrics_->incrementFailedRequests();
            return false;
        }
        
        auto it = secrets_.find(secretName);
        if (it != secrets_.end()) {
            value = it->second;
            metrics_->incrementSuccessfulRequests();
            metrics_->incrementCacheHits(); // Mock treats all as cache hits
            return true;
        }
        
        metrics_->incrementFailedRequests();
        metrics_->incrementCacheMisses();
        return false;
    }

    bool setSecret(const std::string& secretName, const std::string& value) override {
        std::lock_guard<std::mutex> lock(secrets_mutex_);
        metrics_->incrementTotalRequests();
        
        // Simulate delay if configured
        if (operation_delay_.count() > 0) {
            std::this_thread::sleep_for(operation_delay_);
        }
        
        if (!connected_ || simulate_failures_) {
            metrics_->incrementFailedRequests();
            return false;
        }
        
        secrets_[secretName] = value;
        metrics_->incrementSuccessfulRequests();
        return true;
    }

    bool deleteSecret(const std::string& secretName) override {
        std::lock_guard<std::mutex> lock(secrets_mutex_);
        metrics_->incrementTotalRequests();
        
        // Simulate delay if configured
        if (operation_delay_.count() > 0) {
            std::this_thread::sleep_for(operation_delay_);
        }
        
        if (!connected_ || simulate_failures_) {
            metrics_->incrementFailedRequests();
            return false;
        }
        
        auto it = secrets_.find(secretName);
        if (it != secrets_.end()) {
            secrets_.erase(it);
            metrics_->incrementSuccessfulRequests();
            return true;
        }
        
        metrics_->incrementFailedRequests();
        return false;
    }

    std::vector<std::string> listSecrets() override {
        std::lock_guard<std::mutex> lock(secrets_mutex_);
        metrics_->incrementTotalRequests();
        
        // Simulate delay if configured
        if (operation_delay_.count() > 0) {
            std::this_thread::sleep_for(operation_delay_);
        }
        
        std::vector<std::string> secretNames;
        
        if (!connected_ || simulate_failures_) {
            metrics_->incrementFailedRequests();
            return secretNames;
        }
        
        for (const auto& [name, value] : secrets_) {
            secretNames.push_back(name);
        }
        
        metrics_->incrementSuccessfulRequests();
        return secretNames;
    }

    bool hasSecret(const std::string& secretName) override {
        std::lock_guard<std::mutex> lock(secrets_mutex_);
        metrics_->incrementTotalRequests();
        
        if (!connected_ || simulate_failures_) {
            metrics_->incrementFailedRequests();
            return false;
        }
        
        bool exists = secrets_.find(secretName) != secrets_.end();
        if (exists) {
            metrics_->incrementSuccessfulRequests();
            metrics_->incrementCacheHits();
        } else {
            metrics_->incrementSuccessfulRequests(); // Still a successful operation
            metrics_->incrementCacheMisses();
        }
        return exists;
    }

    bool isConnected() const override {
        return connected_;
    }

    bool testConnection() override {
        metrics_->incrementTotalRequests();
        
        if (!connected_ || simulate_failures_) {
            metrics_->incrementFailedRequests();
            return false;
        }
        
        metrics_->incrementSuccessfulRequests();
        return true;
    }

    void clearCache() override {
        // Mock implementation - in a real scenario this would clear caching
        // For mock, we'll just increment the request counter
        metrics_->incrementTotalRequests();
        metrics_->incrementSuccessfulRequests();
    }

    std::shared_ptr<ISecureStoreMetrics> getMetrics() override {
        return metrics_;
    }

    // Mock-specific methods for testing
    
    void setConnected(bool connected) {
        connected_ = connected;
        metrics_->setConnected(connected);
    }
    
    void setSimulateFailures(bool simulate, const std::string& errorMessage = "Mock SecureStore failure") {
        simulate_failures_ = simulate;
        failure_error_message_ = errorMessage;
    }
    
    void setOperationDelay(std::chrono::milliseconds delay) {
        operation_delay_ = delay;
        metrics_->setResponseTime(static_cast<double>(delay.count()));
    }
    
    void clearSecrets() {
        std::lock_guard<std::mutex> lock(secrets_mutex_);
        secrets_.clear();
    }
    
    void addSecret(const std::string& name, const std::string& value) {
        std::lock_guard<std::mutex> lock(secrets_mutex_);
        secrets_[name] = value;
    }
    
    void addSecrets(const std::unordered_map<std::string, std::string>& secrets) {
        std::lock_guard<std::mutex> lock(secrets_mutex_);
        for (const auto& [name, value] : secrets) {
            secrets_[name] = value;
        }
    }
    
    size_t getSecretCount() const {
        std::lock_guard<std::mutex> lock(secrets_mutex_);
        return secrets_.size();
    }
    
    std::unordered_map<std::string, std::string> getAllSecrets() const {
        std::lock_guard<std::mutex> lock(secrets_mutex_);
        return secrets_;
    }
    
    void resetMetrics() {
        metrics_ = std::make_unique<MockSecureStoreMetrics>();
    }
    
    bool isSimulatingFailures() const {
        return simulate_failures_;
    }
    
    const std::string& getFailureErrorMessage() const {
        return failure_error_message_;
    }
    
    std::chrono::milliseconds getOperationDelay() const {
        return operation_delay_;
    }
};

// Mock SecureStore Factory
class MockSecureStoreFactory : public ISecureStoreFactory {
public:
    std::unique_ptr<ISecureStore> create(const SecureStoreConfig& config) override {
        auto mockStore = std::make_unique<MockSecureStore>();
        
        // Apply configuration if needed
        if (!config.key_vault_url.empty() && config.key_vault_url == "mock://fail") {
            mockStore->setSimulateFailures(true);
        }
        
        return mockStore;
    }

    std::unique_ptr<ISecureStore> createKeyVault(const SecureStoreConfig& config, 
                                                std::unique_ptr<IHttpClient> httpClient) override {
        // Ignore the HTTP client for mock implementation
        return create(config);
    }
};

} // namespace mocks
} // namespace infra
} // namespace coyote
