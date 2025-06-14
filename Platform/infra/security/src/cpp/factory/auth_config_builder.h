#pragma once

#include "../interfaces/cpp/auth_types.h"
#include <string>

namespace coyote {
namespace infra {
namespace security {

// Configuration builder for different authentication scenarios
// Supports multiple authentication standards:
// - OAuth2 Client Credentials (RFC 6749)
// - OAuth2 Authorization Code (RFC 6749) 
// - OAuth2 + PKCE (RFC 7636)
// - JWT Bearer (RFC 7523)
// - mTLS Client Credentials (RFC 8705)
class AuthConfigBuilder {
public:
    // Client Credentials Grant (Recommendation #1 - Service-to-Service)
    static ClientConfig buildClientCredentialsConfig(
        const std::string& client_id,
        const std::string& client_secret,
        const std::string& auth_service_base_url,
        const std::string& scope = "keyvault.read"
    ) {
        ClientConfig config;
        config.client_id = client_id;
        config.client_secret = client_secret;
        config.token_endpoint = auth_service_base_url + "/token";
        config.authorize_endpoint = auth_service_base_url + "/authorize";
        config.scope = scope;
        config.auto_refresh = true;
        config.token_refresh_buffer = std::chrono::seconds(60);
        config.timeout = std::chrono::seconds(30);
        config.max_retries = 3;
        return config;
    }
    
    // mTLS Client Credentials (Recommendation #2 - Higher Security)
    static ClientConfig buildMTLSConfig(
        const std::string& client_id,
        const std::string& auth_service_base_url,
        const std::string& client_cert_path,
        const std::string& client_key_path,
        const std::string& scope = "keyvault.read"
    ) {
        ClientConfig config;
        config.client_id = client_id;
        // No client_secret for mTLS
        config.token_endpoint = auth_service_base_url + "/token";
        config.authorize_endpoint = auth_service_base_url + "/authorize";
        config.scope = scope;
        config.client_cert_path = client_cert_path;
        config.client_key_path = client_key_path;
        config.auto_refresh = true;
        config.token_refresh_buffer = std::chrono::seconds(60);
        config.timeout = std::chrono::seconds(30);
        config.max_retries = 3;
        return config;
    }
    
    // JWT Bearer Assertion (Recommendation #3 - No Shared Secrets)
    static ClientConfig buildJWTBearerConfig(
        const std::string& client_id,
        const std::string& auth_service_base_url,
        const std::string& private_key_path,
        const std::string& key_id = "",
        const std::string& scope = "keyvault.read"
    ) {
        ClientConfig config;
        config.client_id = client_id;
        // No client_secret for JWT Bearer
        config.token_endpoint = auth_service_base_url + "/token";
        config.authorize_endpoint = auth_service_base_url + "/authorize";
        config.scope = scope;
        config.private_key_path = private_key_path;
        config.key_id = key_id;
        config.auto_refresh = true;
        config.token_refresh_buffer = std::chrono::seconds(60);
        config.timeout = std::chrono::seconds(30);
        config.max_retries = 3;
        return config;
    }
    
    // Authorization Code + PKCE (Interactive/User-driven flows)
    static ClientConfig buildAuthCodePKCEConfig(
        const std::string& client_id,
        const std::string& auth_service_base_url,
        const std::string& redirect_uri,
        const std::string& scope = "keyvault.read"
    ) {
        ClientConfig config;
        config.client_id = client_id;
        // No client_secret for public clients with PKCE
        config.token_endpoint = auth_service_base_url + "/token";
        config.authorize_endpoint = auth_service_base_url + "/authorize";
        config.scope = scope;
        config.auto_refresh = true;
        config.token_refresh_buffer = std::chrono::seconds(60);
        config.timeout = std::chrono::seconds(30);
        config.max_retries = 3;
        return config;
    }
};

// Example configurations for different CoyoteSense scenarios
namespace examples {

// Trading Unit with Client Credentials
inline ClientConfig getTradingUnitConfig() {
    return AuthConfigBuilder::buildClientCredentialsConfig(
        "trading-unit-001",
        "secret_from_env_or_keyvault", 
        "https://auth-service.coyotesense.local:8443",
        "keyvault.read keyvault.write"
    );
}

// Analytics Unit with mTLS (edge deployment)
inline ClientConfig getAnalyticsUnitConfig() {
    return AuthConfigBuilder::buildMTLSConfig(
        "analytics-unit-002",
        "https://auth-service.coyotesense.local:8443",
        "/opt/coyote/certs/analytics-unit-002.crt",
        "/opt/coyote/certs/analytics-unit-002.key",
        "keyvault.read metrics.write"
    );
}

// Core Service with JWT Bearer
inline ClientConfig getCoreServiceConfig() {
    return AuthConfigBuilder::buildJWTBearerConfig(
        "core-service-keyvault",
        "https://auth-service.coyotesense.local:8443", 
        "/opt/coyote/keys/core-service.key",
        "core-service-key-001",
        "keyvault.admin"
    );
}

// Dashboard/CLI with Auth Code + PKCE
inline ClientConfig getDashboardConfig() {
    return AuthConfigBuilder::buildAuthCodePKCEConfig(
        "coyote-dashboard",
        "https://auth-service.coyotesense.local:8443",
        "https://dashboard.coyotesense.local/callback",
        "keyvault.read dashboard.access"
    );
}

} // namespace examples

// Legacy alias for backward compatibility
using OAuth2ConfigBuilder = AuthConfigBuilder;

} // namespace security
} // namespace infra
} // namespace coyote
