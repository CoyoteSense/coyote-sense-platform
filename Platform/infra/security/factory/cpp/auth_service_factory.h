#pragma once

#include "../interfaces/cpp/auth_interfaces.h"
#include "../../http/factory/http_client_factory.h"
#include <memory>
#include <string>

namespace coyote {
namespace infra {
namespace security {

// Authentication Service Factory - creates authentication services based on mode
// Supports multiple authentication standards:
// - OAuth2 Client Credentials (RFC 6749)
// - OAuth2 Authorization Code (RFC 6749) 
// - OAuth2 + PKCE (RFC 7636)
// - JWT Bearer (RFC 7523)
// - mTLS Client Credentials (RFC 8705)
class AuthServiceFactoryImpl : public AuthServiceFactory {
private:
    std::shared_ptr<http::IHttpClientFactory> http_factory_;
    
public:
    explicit AuthServiceFactoryImpl(std::shared_ptr<http::IHttpClientFactory> http_factory);
    
    // AuthServiceFactory implementation
    std::unique_ptr<AuthClient> CreateClient(const std::string& mode = "real") override;
    
    std::unique_ptr<TokenManager> CreateTokenManager(const std::string& mode = "real") override;
    
    std::unique_ptr<AuthenticationService> CreateAuthService(
        const ClientConfig& config,
        const std::string& mode = "real"
    ) override;
    
    // Convenience method for creating fully configured auth service for a unit
    std::unique_ptr<AuthenticationService> CreateUnitAuthService(
        const std::string& unit_id,
        const ClientConfig& config,
        const std::string& mode = "real"
    );
};

// Legacy alias for backward compatibility
using OAuth2ServiceFactoryImpl = AuthServiceFactoryImpl;

} // namespace security
} // namespace infra
} // namespace coyote
