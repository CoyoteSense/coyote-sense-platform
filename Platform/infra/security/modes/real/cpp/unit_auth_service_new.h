// filepath: c:\CoyoteSense\coyote-sense-platform\Platform\infra\security\modes\real\cpp\unit_auth_service.h
#pragma once

#include "../../../interfaces/cpp/auth_interfaces.h"
#include <memory>
#include <atomic>
#include <string>

namespace coyote {
namespace infra {
namespace security {
namespace auth {

// Unit Authentication Service - High-level service for units to use
// Implements "On Start" authentication pattern with multi-standard support
// Supports OAuth2 RFC 6749, JWT Bearer RFC 7523, and mTLS RFC 8705
class UnitAuthService : public IAuthService {
private:
    std::shared_ptr<IAuthClient> auth_client_;
    std::shared_ptr<IAuthTokenManager> token_manager_;
    AuthClientConfig config_;
    std::string unit_id_;
    std::atomic<bool> is_initialized_{false};
    std::atomic<bool> is_authenticated_{false};
    
    // Initialize token on startup
    void performInitialAuthentication();
    
public:
    UnitAuthService(
        std::shared_ptr<IAuthClient> auth_client,
        std::shared_ptr<IAuthTokenManager> token_manager,
        const std::string& unit_id
    );
    
    ~UnitAuthService() override = default;
    
    // Initialization
    std::future<bool> InitializeAsync(const AuthClientConfig& config) override;
    
    // Token management
    std::future<std::string> GetAccessTokenAsync() override;
    std::future<bool> RefreshTokenAsync() override;
    std::future<bool> IsAuthenticatedAsync() override;
    
    // Service status
    bool IsInitialized() const override;
    std::string GetUnitId() const;
    
    // Cleanup
    std::future<void> ShutdownAsync() override;
};

} // namespace auth
} // namespace security
} // namespace infra
} // namespace coyote
