// filepath: c:\CoyoteSense\coyote-sense-platform\Platform\infra\security\factory\cpp\auth_service_factory_impl.cpp
#include "auth_service_factory.h"
#include "../../modes/real/cpp/auth_client_credentials.h"
#include "../../modes/real/cpp/auto_refresh_token_manager.h"
#include "../../modes/real/cpp/unit_auth_service.h"
#include <stdexcept>

namespace coyote {
namespace infra {
namespace security {
namespace auth {

AuthServiceFactory::AuthServiceFactory(std::shared_ptr<http::IHttpClientFactory> http_factory)
    : http_factory_(std::move(http_factory)) {
}

std::unique_ptr<IAuthClient> AuthServiceFactory::CreateAuthClient(const std::string& mode) {
    auto http_client = http_factory_->createClient(mode);
    
    if (mode == "real") {
        return std::make_unique<AuthClientCredentialsClient>(http_client);
    } else if (mode == "mock") {
        // TODO: Implement mock Auth client
        throw std::runtime_error("Mock Auth client not implemented yet");
    } else if (mode == "debug") {
        // For debug mode, use real client but with debug HTTP client
        return std::make_unique<AuthClientCredentialsClient>(http_client);
    } else if (mode == "simulation") {
        // TODO: Implement simulation Auth client
        throw std::runtime_error("Simulation Auth client not implemented yet");
    } else {
        throw std::runtime_error("Unsupported Auth client mode: " + mode);
    }
}

std::unique_ptr<IAuthTokenManager> AuthServiceFactory::CreateTokenManager(const std::string& mode) {
    auto auth_client = CreateAuthClient(mode);
    
    if (mode == "real" || mode == "debug") {
        return std::make_unique<AutoRefreshTokenManager>(std::move(auth_client));
    } else if (mode == "mock") {
        // TODO: Implement mock token manager
        throw std::runtime_error("Mock token manager not implemented yet");
    } else if (mode == "simulation") {
        // TODO: Implement simulation token manager
        throw std::runtime_error("Simulation token manager not implemented yet");
    } else {
        throw std::runtime_error("Unsupported token manager mode: " + mode);
    }
}

std::unique_ptr<IAuthService> AuthServiceFactory::CreateAuthService(
    const AuthClientConfig& config,
    const std::string& mode) {
    
    auto auth_client = CreateAuthClient(mode);
    auto token_manager = CreateTokenManager(mode);
    
    if (mode == "real" || mode == "debug") {
        return std::make_unique<UnitAuthService>(
            std::move(auth_client),
            std::move(token_manager),
            config.client_id
        );
    } else if (mode == "mock") {
        // TODO: Implement mock auth service
        throw std::runtime_error("Mock auth service not implemented yet");
    } else if (mode == "simulation") {
        // TODO: Implement simulation auth service
        throw std::runtime_error("Simulation auth service not implemented yet");
    } else {
        throw std::runtime_error("Unsupported auth service mode: " + mode);
    }
}

std::unique_ptr<IAuthService> AuthServiceFactory::CreateUnitAuthService(
    const std::string& unit_id,
    const AuthClientConfig& config,
    const std::string& mode) {
    
    auto auth_client = CreateAuthClient(mode);
    auto token_manager = CreateTokenManager(mode);
    
    return std::make_unique<UnitAuthService>(
        std::move(auth_client),
        std::move(token_manager),
        unit_id
    );
}

} // namespace auth
} // namespace security
} // namespace infra
} // namespace coyote
