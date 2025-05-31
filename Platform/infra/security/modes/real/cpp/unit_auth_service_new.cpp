// filepath: c:\CoyoteSense\coyote-sense-platform\Platform\infra\security\modes\real\cpp\unit_auth_service.cpp
#include "unit_auth_service.h"
#include <stdexcept>
#include <chrono>

namespace coyote {
namespace infra {
namespace security {
namespace auth {

UnitAuthService::UnitAuthService(
    std::shared_ptr<IAuthClient> auth_client,
    std::shared_ptr<IAuthTokenManager> token_manager,
    const std::string& unit_id)
    : auth_client_(std::move(auth_client))
    , token_manager_(std::move(token_manager))
    , unit_id_(unit_id) {
}

std::future<bool> UnitAuthService::InitializeAsync(const AuthClientConfig& config) {
    return std::async(std::launch::async, [this, config]() -> bool {
        config_ = config;
        
        try {
            performInitialAuthentication();
            is_initialized_ = true;
            return true;
        } catch (const std::exception& e) {
            is_initialized_ = false;
            is_authenticated_ = false;
            throw std::runtime_error("Failed to initialize authentication for unit " + unit_id_ + ": " + e.what());
        }
    });
}

void UnitAuthService::performInitialAuthentication() {
    // Set client config for token manager
    if (auto refresh_manager = std::dynamic_pointer_cast<AutoRefreshTokenManager>(token_manager_)) {
        refresh_manager->setClientConfig(config_.client_id, config_);
    }
    
    // Perform initial authentication based on configured method
    if (config_.client_secret) {
        // Client Credentials Grant - OAuth2 RFC 6749
        auto token_future = auth_client_->RequestTokenAsync(config_);
        auto token = token_future.get();
        
        // Store in token manager for automatic refresh
        token_manager_->StoreToken(config_.client_id, token);
        is_authenticated_ = true;
        
    } else if (config_.private_key_path) {
        // JWT Bearer Assertion Grant - RFC 7523
        JwtBearerClaims claims;
        claims.issuer = config_.client_id;
        claims.subject = config_.client_id;
        claims.audience = config_.token_endpoint;
        claims.issued_at = std::chrono::system_clock::now();
        claims.expires_at = claims.issued_at + std::chrono::minutes(5);
        
        auto token_future = auth_client_->RequestTokenWithJwtAsync(config_, claims);
        auto token = token_future.get();
        
        token_manager_->StoreToken(config_.client_id, token);
        is_authenticated_ = true;
        
    } else if (config_.client_cert_path && config_.client_key_path) {
        // mTLS authentication - RFC 8705
        auto token_future = auth_client_->RequestTokenAsync(config_);
        auto token = token_future.get();
        
        token_manager_->StoreToken(config_.client_id, token);
        is_authenticated_ = true;
        
    } else {
        throw std::runtime_error("No valid authentication method configured for unit " + unit_id_);
    }
}

std::future<std::string> UnitAuthService::GetAccessTokenAsync() {
    return std::async(std::launch::async, [this]() -> std::string {
        if (!is_initialized_) {
            throw std::runtime_error("Authentication service not initialized for unit " + unit_id_);
        }
        
        auto token = token_manager_->GetValidToken(config_.client_id);
        if (!token) {
            throw std::runtime_error("No valid token available for unit " + unit_id_);
        }
        
        return token->access_token;
    });
}

std::future<bool> UnitAuthService::RefreshTokenAsync() {
    return std::async(std::launch::async, [this]() -> bool {
        if (!is_initialized_) {
            return false;
        }
        
        try {
            // Token manager handles refresh automatically
            auto token = token_manager_->GetValidToken(config_.client_id);
            return token.has_value();
        } catch (const std::exception&) {
            is_authenticated_ = false;
            return false;
        }
    });
}

std::future<bool> UnitAuthService::IsAuthenticatedAsync() {
    return std::async(std::launch::async, [this]() -> bool {
        if (!is_initialized_) {
            return false;
        }
        
        auto token = token_manager_->GetValidToken(config_.client_id);
        bool authenticated = token.has_value();
        is_authenticated_ = authenticated;
        return authenticated;
    });
}

bool UnitAuthService::IsInitialized() const {
    return is_initialized_;
}

std::string UnitAuthService::GetUnitId() const {
    return unit_id_;
}

std::future<void> UnitAuthService::ShutdownAsync() {
    return std::async(std::launch::async, [this]() {
        is_initialized_ = false;
        is_authenticated_ = false;
        
        // Clear tokens from manager
        if (token_manager_ && !config_.client_id.empty()) {
            token_manager_->RemoveToken(config_.client_id);
        }
    });
}

} // namespace auth
} // namespace security
} // namespace infra
} // namespace coyote
