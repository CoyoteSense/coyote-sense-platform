#pragma once

#include "../../../interfaces/cpp/auth_interfaces.h"
#include <memory>
#include <mutex>
#include <unordered_map>
#include <thread>
#include <atomic>
#include <condition_variable>

namespace coyote {
namespace infra {
namespace security {
namespace auth {

// Token cache entry
struct TokenCacheEntry {
    AuthTokenResponse token;
    AuthClientConfig config;
    std::chrono::system_clock::time_point last_refreshed;
    std::atomic<bool> is_refreshing{false};
    
    TokenCacheEntry(const AuthTokenResponse& t, const AuthClientConfig& c)
        : token(t), config(c), last_refreshed(std::chrono::system_clock::now()) {}
};

// Automatic Token Manager with refresh capabilities
// Supports OAuth2 RFC 6749, JWT Bearer RFC 7523, and mTLS RFC 8705
class AutoRefreshTokenManager : public IAuthTokenManager {
private:
    std::shared_ptr<IAuthClient> auth_client_;    std::unordered_map<std::string, std::unique_ptr<TokenCacheEntry>> token_cache_;
    mutable std::mutex cache_mutex_;
    
    // Background refresh thread
    std::thread refresh_thread_;
    std::atomic<bool> shutdown_requested_{false};
    std::condition_variable refresh_cv_;
    std::mutex refresh_mutex_;
    
    // Refresh management
    void startRefreshLoop();
    void refreshLoop();
    void checkAndRefreshTokens();
    std::future<AuthTokenResponse> refreshTokenInternal(TokenCacheEntry& entry);
    
public:
    explicit AutoRefreshTokenManager(std::shared_ptr<IAuthClient> auth_client);
    ~AutoRefreshTokenManager();
    
    // IAuthTokenManager implementation
    std::future<std::string> GetValidTokenAsync(const std::string& client_id) override;
    void StoreToken(const std::string& client_id, const AuthTokenResponse& token) override;
    void RemoveToken(const std::string& client_id) override;
    bool HasValidToken(const std::string& client_id) override;
    std::future<std::string> ForceRefreshAsync(const std::string& client_id) override;
    std::optional<AuthTokenResponse> GetValidToken(const std::string& client_id) override;
    
    // Configuration management
    void SetClientConfig(const std::string& client_id, const AuthClientConfig& config);
    void Shutdown();
};

} // namespace auth
} // namespace security
} // namespace infra
} // namespace coyote
