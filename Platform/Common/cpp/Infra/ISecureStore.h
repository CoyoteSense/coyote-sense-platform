#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <memory>
#include <chrono>

namespace coyote {
namespace infra {

// Secure store metrics interface
struct ISecureStoreMetrics {
    virtual ~ISecureStoreMetrics() = default;
    virtual uint64_t getRequestsTotal() const = 0;
    virtual uint64_t getRequestsSuccessful() const = 0;
    virtual uint64_t getRequestsFailed() const = 0;
    virtual uint64_t getCacheHits() const = 0;
    virtual uint64_t getCacheMisses() const = 0;
    virtual std::chrono::steady_clock::time_point getLastRequestTime() const = 0;
    virtual void reset() = 0;
};

// Secure store interface
class ISecureStore {
public:
    virtual ~ISecureStore() = default;
    
    // Authentication and initialization
    virtual bool authenticate(const std::string& role) = 0;
    virtual bool isAuthenticated() const = 0;
    virtual void logout() = 0;
    
    // Secret retrieval operations
    virtual std::string getSecret(const std::string& path) = 0;
    virtual std::unordered_map<std::string, std::string> getSecrets(const std::vector<std::string>& paths) = 0;
    
    // Secret management operations (if supported)
    virtual bool putSecret(const std::string& path, const std::string& value) = 0;
    virtual bool deleteSecret(const std::string& path) = 0;
    virtual bool secretExists(const std::string& path) = 0;
    
    // Configuration and health
    virtual void setRetryPolicy(int maxRetries, std::chrono::milliseconds delay) = 0;
    virtual bool ping() = 0;
    virtual std::unique_ptr<ISecureStoreMetrics> getMetrics() const = 0;
    virtual void resetMetrics() = 0;
    
    // Token management
    virtual bool refreshToken() = 0;
    virtual std::chrono::steady_clock::time_point getTokenExpiry() const = 0;
    virtual bool isTokenValid() const = 0;
};

// Configuration for secure store
struct SecureStoreConfig {
    std::string url;
    std::string unitRole;
    std::string caPath;
    std::string clientCertPath;
    std::string clientKeyPath;
    bool enableMutualTLS = false;
    int tokenRefreshInterval = 300000; // 5 minutes
    int maxRetries = 3;
    std::chrono::milliseconds retryDelay{1000};
    long timeoutMs = 10000;
};

// Factory for creating secure stores
class ISecureStoreFactory {
public:
    virtual ~ISecureStoreFactory() = default;
    virtual std::unique_ptr<ISecureStore> createSecureStore(const SecureStoreConfig& config) = 0;
};

} // namespace infra
} // namespace coyote
