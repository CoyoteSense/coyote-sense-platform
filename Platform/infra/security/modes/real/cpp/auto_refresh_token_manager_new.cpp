// filepath: c:\CoyoteSense\coyote-sense-platform\Platform\infra\security\modes\real\cpp\auto_refresh_token_manager.cpp
#include "auto_refresh_token_manager.h"
#include <chrono>
#include <stdexcept>

namespace coyote {
namespace infra {
namespace security {
namespace auth {

AutoRefreshTokenManager::AutoRefreshTokenManager(std::shared_ptr<IAuthClient> auth_client)
    : auth_client_(std::move(auth_client)) {
    startRefreshLoop();
}

AutoRefreshTokenManager::~AutoRefreshTokenManager() {
    Shutdown();
}

void AutoRefreshTokenManager::startRefreshLoop() {
    refresh_thread_ = std::thread([this]() { refreshLoop(); });
}

void AutoRefreshTokenManager::refreshLoop() {
    while (!shutdown_requested_) {
        checkAndRefreshTokens();
        
        // Wait for 30 seconds or until shutdown
        std::unique_lock<std::mutex> lock(refresh_mutex_);
        refresh_cv_.wait_for(lock, std::chrono::seconds(30), 
                           [this]() { return shutdown_requested_.load(); });
    }
}

void AutoRefreshTokenManager::checkAndRefreshTokens() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    for (auto& [client_id, entry] : token_cache_) {
        if (!entry) continue;
        
        // Check if token needs refresh (refresh 5 minutes before expiry)
        auto now = std::chrono::system_clock::now();
        auto refresh_threshold = entry->token.expires_at - std::chrono::minutes(5);
        
        if (now >= refresh_threshold && !entry->is_refreshing.exchange(true)) {
            // Launch async refresh
            auto future = refreshTokenInternal(*entry);
            // In a production system, you'd want to handle this future properly
            // For now, just fire and forget
        }
    }
}

std::future<AuthTokenResponse> AutoRefreshTokenManager::refreshTokenInternal(TokenCacheEntry& entry) {
    return std::async(std::launch::async, [this, &entry]() -> AuthTokenResponse {
        try {
            AuthTokenResponse new_token;
            
            if (entry.token.refresh_token) {
                // Use refresh token
                auto refresh_future = auth_client_->RefreshTokenAsync(entry.config, *entry.token.refresh_token);
                new_token = refresh_future.get();
            } else {
                // Perform new authentication (client credentials or JWT)
                if (entry.config.client_secret) {
                    // Client credentials
                    auto token_future = auth_client_->RequestTokenAsync(entry.config);
                    new_token = token_future.get();
                } else if (entry.config.private_key_path) {
                    // JWT Bearer
                    JwtBearerClaims claims;
                    claims.issuer = entry.config.client_id;
                    claims.subject = entry.config.client_id;
                    claims.audience = entry.config.token_endpoint;
                    claims.issued_at = std::chrono::system_clock::now();
                    claims.expires_at = claims.issued_at + std::chrono::minutes(5);
                    
                    auto token_future = auth_client_->RequestTokenWithJwtAsync(entry.config, claims);
                    new_token = token_future.get();
                }
            }
            
            // Update cache entry
            entry.token = new_token;
            entry.last_refreshed = std::chrono::system_clock::now();
            entry.is_refreshing = false;
            
            return new_token;
            
        } catch (const std::exception&) {
            entry.is_refreshing = false;
            throw;
        }
    });
}

std::future<std::string> AutoRefreshTokenManager::GetValidTokenAsync(const std::string& client_id) {
    return std::async(std::launch::async, [this, client_id]() -> std::string {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        
        auto it = token_cache_.find(client_id);
        if (it == token_cache_.end() || !it->second) {
            throw std::runtime_error("No token found for client: " + client_id);
        }
        
        auto& entry = *it->second;
        auto now = std::chrono::system_clock::now();
        
        // Check if token is still valid (with 1 minute buffer)
        if (now >= (entry.token.expires_at - std::chrono::minutes(1))) {
            // Token expired or about to expire - force refresh
            if (!entry.is_refreshing.exchange(true)) {
                try {
                    auto new_token = refreshTokenInternal(entry).get();
                    return new_token.access_token;
                } catch (const std::exception&) {
                    entry.is_refreshing = false;
                    throw;
                }
            } else {
                // Another thread is refreshing, wait and retry
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                return GetValidTokenAsync(client_id).get();
            }
        }
        
        return entry.token.access_token;
    });
}

void AutoRefreshTokenManager::StoreToken(const std::string& client_id, const AuthTokenResponse& token) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    // Create new entry or update existing
    auto it = token_cache_.find(client_id);
    if (it != token_cache_.end() && it->second) {
        it->second->token = token;
        it->second->last_refreshed = std::chrono::system_clock::now();
        it->second->is_refreshing = false;
    } else {
        // Need config for new entry - this is a limitation of the current design
        // In practice, SetClientConfig should be called before StoreToken
        AuthClientConfig empty_config;
        empty_config.client_id = client_id;
        token_cache_[client_id] = std::make_unique<TokenCacheEntry>(token, empty_config);
    }
}

void AutoRefreshTokenManager::RemoveToken(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    token_cache_.erase(client_id);
}

bool AutoRefreshTokenManager::HasValidToken(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    auto it = token_cache_.find(client_id);
    if (it == token_cache_.end() || !it->second) {
        return false;
    }
    
    auto now = std::chrono::system_clock::now();
    return now < it->second->token.expires_at;
}

std::future<std::string> AutoRefreshTokenManager::ForceRefreshAsync(const std::string& client_id) {
    return std::async(std::launch::async, [this, client_id]() -> std::string {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        
        auto it = token_cache_.find(client_id);
        if (it == token_cache_.end() || !it->second) {
            throw std::runtime_error("No token found for client: " + client_id);
        }
        
        auto& entry = *it->second;
        entry.is_refreshing = false; // Reset flag to allow refresh
        
        auto new_token = refreshTokenInternal(entry).get();
        return new_token.access_token;
    });
}

std::optional<AuthTokenResponse> AutoRefreshTokenManager::GetValidToken(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    auto it = token_cache_.find(client_id);
    if (it == token_cache_.end() || !it->second) {
        return std::nullopt;
    }
    
    auto& entry = *it->second;
    auto now = std::chrono::system_clock::now();
    
    // Check if token is still valid
    if (now >= entry.token.expires_at) {
        return std::nullopt;
    }
    
    return entry.token;
}

void AutoRefreshTokenManager::SetClientConfig(const std::string& client_id, const AuthClientConfig& config) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    auto it = token_cache_.find(client_id);
    if (it != token_cache_.end() && it->second) {
        it->second->config = config;
    } else {
        // Create placeholder entry with config
        AuthTokenResponse empty_token;
        empty_token.access_token = "";
        empty_token.expires_at = std::chrono::system_clock::now();
        token_cache_[client_id] = std::make_unique<TokenCacheEntry>(empty_token, config);
    }
}

void AutoRefreshTokenManager::Shutdown() {
    shutdown_requested_ = true;
    refresh_cv_.notify_all();
    
    if (refresh_thread_.joinable()) {
        refresh_thread_.join();
    }
    
    std::lock_guard<std::mutex> lock(cache_mutex_);
    token_cache_.clear();
}

} // namespace auth
} // namespace security
} // namespace infra
} // namespace coyote
