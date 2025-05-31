// OAuth2 Authentication Usage Examples for CoyoteSense Units
// 
// This file demonstrates how different types of units would use the OAuth2
// authentication system to securely interact with the KeyVault unit.

#include "../interfaces/cpp/auth_interfaces.h"
#include "../factory/cpp/auth_service_factory.h"
#include "../factory/cpp/auth_config_builder.h"
#include "../../http/factory/http_client_factory.h"
#include <iostream>
#include <memory>

namespace coyote {
namespace examples {

// Example 1: Trading Unit using Client Credentials (Recommendation #1)
class TradingUnit {
private:
    std::unique_ptr<infra::security::IOAuth2AuthenticationService> auth_service_;
    std::string unit_id_ = "trading-unit-001";

public:
    bool initialize() {
        try {
            // Create HTTP factory
            auto http_factory = std::make_shared<infra::http::HttpClientFactory>();
            
            // Create OAuth2 factory
            auto oauth_factory = std::make_shared<infra::security::OAuth2ServiceFactory>(http_factory);
            
            // Build configuration for Client Credentials flow
            auto config = infra::security::OAuth2ConfigBuilder::buildClientCredentialsConfig(
                unit_id_,
                std::getenv("TRADING_UNIT_SECRET"), // Secret from environment
                "https://auth-service.coyotesense.local:8443",
                "keyvault.read keyvault.write orders.submit"
            );
            
            // Create auth service
            auth_service_ = oauth_factory->createUnitAuthService(unit_id_, config, "real");
            
            // Initialize authentication (performs initial token request)
            auto init_result = auth_service_->initializeAsync(config).get();
            
            if (init_result) {
                std::cout << "Trading unit authenticated successfully" << std::endl;
                return true;
            } else {
                std::cout << "Trading unit authentication failed" << std::endl;
                return false;
            }
            
        } catch (const std::exception& e) {
            std::cout << "Trading unit initialization error: " << e.what() << std::endl;
            return false;
        }
    }
    
    void accessSecrets() {
        try {
            // Get access token for KeyVault requests
            auto token = auth_service_->getAccessTokenAsync().get();
            
            // Use token in HTTP requests to KeyVault
            std::cout << "Making KeyVault request with token: " << token.substr(0, 20) << "..." << std::endl;
            
            // Example: Get trading API key from KeyVault
            // auto api_key = keyvault_client->getSecretAsync("trading-api-key", token).get();
            
        } catch (const std::exception& e) {
            std::cout << "Secret access error: " << e.what() << std::endl;
        }
    }
    
    void shutdown() {
        if (auth_service_) {
            auth_service_->shutdown();
        }
    }
};

// Example 2: Analytics Unit using mTLS (Recommendation #2 - Edge Deployment)
class AnalyticsUnit {
private:
    std::unique_ptr<infra::security::IOAuth2AuthenticationService> auth_service_;
    std::string unit_id_ = "analytics-unit-002";

public:
    bool initialize() {
        try {
            auto http_factory = std::make_shared<infra::http::HttpClientFactory>();
            auto oauth_factory = std::make_shared<infra::security::OAuth2ServiceFactory>(http_factory);
            
            // Build configuration for mTLS authentication
            auto config = infra::security::OAuth2ConfigBuilder::buildMTLSConfig(
                unit_id_,
                "https://auth-service.coyotesense.local:8443",
                "/opt/coyote/certs/analytics-unit-002.crt",
                "/opt/coyote/certs/analytics-unit-002.key",
                "keyvault.read metrics.write analytics.access"
            );
            
            auth_service_ = oauth_factory->createUnitAuthService(unit_id_, config, "real");
            
            auto init_result = auth_service_->initializeAsync(config).get();
            
            if (init_result) {
                std::cout << "Analytics unit authenticated with mTLS successfully" << std::endl;
                return true;
            }
            
        } catch (const std::exception& e) {
            std::cout << "Analytics unit mTLS authentication error: " << e.what() << std::endl;
        }
        
        return false;
    }
    
    void performAnalytics() {
        try {
            auto token = auth_service_->getAccessTokenAsync().get();
            
            // Access ML model keys, database credentials, etc. from KeyVault
            std::cout << "Analytics unit accessing secrets with mTLS token" << std::endl;
            
        } catch (const std::exception& e) {
            std::cout << "Analytics error: " << e.what() << std::endl;
        }
    }
};

// Example 3: Core Service using JWT Bearer (Recommendation #3 - No Shared Secrets)
class CoreKeyvaultService {
private:
    std::unique_ptr<infra::security::IOAuth2AuthenticationService> auth_service_;
    std::string unit_id_ = "core-keyvault-service";

public:
    bool initialize() {
        try {
            auto http_factory = std::make_shared<infra::http::HttpClientFactory>();
            auto oauth_factory = std::make_shared<infra::security::OAuth2ServiceFactory>(http_factory);
            
            // Build configuration for JWT Bearer assertion
            auto config = infra::security::OAuth2ConfigBuilder::buildJWTBearerConfig(
                unit_id_,
                "https://auth-service.coyotesense.local:8443",
                "/opt/coyote/keys/core-service.key",
                "core-service-key-001",
                "keyvault.admin system.admin"
            );
            
            auth_service_ = oauth_factory->createUnitAuthService(unit_id_, config, "real");
            
            auto init_result = auth_service_->initializeAsync(config).get();
            
            if (init_result) {
                std::cout << "Core service authenticated with JWT Bearer successfully" << std::endl;
                return true;
            }
            
        } catch (const std::exception& e) {
            std::cout << "Core service JWT authentication error: " << e.what() << std::endl;
        }
        
        return false;
    }
    
    void manageSecrets() {
        try {
            auto token = auth_service_->getAccessTokenAsync().get();
            
            // Administrative operations on KeyVault
            std::cout << "Core service performing admin operations with JWT token" << std::endl;
            
        } catch (const std::exception& e) {
            std::cout << "Core service error: " << e.what() << std::endl;
        }
    }
};

// Example 4: Batch Processor with automatic token refresh
class BatchProcessor {
private:
    std::unique_ptr<infra::security::IOAuth2AuthenticationService> auth_service_;
    std::string unit_id_ = "batch-processor-001";
    std::atomic<bool> running_{false};

public:
    bool initialize() {
        auto http_factory = std::make_shared<infra::http::HttpClientFactory>();
        auto oauth_factory = std::make_shared<infra::security::OAuth2ServiceFactory>(http_factory);
        
        auto config = infra::security::OAuth2ConfigBuilder::buildClientCredentialsConfig(
            unit_id_,
            std::getenv("BATCH_PROCESSOR_SECRET"),
            "https://auth-service.coyotesense.local:8443",
            "keyvault.read data.process"
        );
        
        auth_service_ = oauth_factory->createUnitAuthService(unit_id_, config, "real");
        
        try {
            auto init_result = auth_service_->initializeAsync(config).get();
            return init_result;
        } catch (const std::exception& e) {
            std::cout << "Batch processor authentication error: " << e.what() << std::endl;
            return false;
        }
    }
    
    void runBatchJob() {
        running_ = true;
        
        while (running_) {
            try {
                // Get fresh token (automatically refreshed by token manager)
                auto token = auth_service_->getAccessTokenAsync().get();
                
                // Process batch with secrets from KeyVault
                processBatchWithSecrets(token);
                
                // Sleep between batches
                std::this_thread::sleep_for(std::chrono::minutes(5));
                
            } catch (const std::exception& e) {
                std::cout << "Batch processing error: " << e.what() << std::endl;
                
                // Try to refresh credentials
                try {
                    auth_service_->refreshCredentialsAsync().get();
                } catch (const std::exception& refresh_error) {
                    std::cout << "Credential refresh failed: " << refresh_error.what() << std::endl;
                    break;
                }
            }
        }
    }
    
private:
    void processBatchWithSecrets(const std::string& token) {
        std::cout << "Processing batch with token: " << token.substr(0, 20) << "..." << std::endl;
        // Actual batch processing logic here
    }
    
public:
    void stop() {
        running_ = false;
    }
    
    void shutdown() {
        stop();
        if (auth_service_) {
            auth_service_->shutdown();
        }
    }
};

// Example 5: Interactive Dashboard (Authorization Code + PKCE)
class DashboardService {
public:
    std::string getAuthorizationUrl() {
        auto http_factory = std::make_shared<infra::http::HttpClientFactory>();
        auto oauth_factory = std::make_shared<infra::security::OAuth2ServiceFactory>(http_factory);
        
        auto oauth_client = oauth_factory->createClient("real");
        
        auto config = infra::security::OAuth2ConfigBuilder::buildAuthCodePKCEConfig(
            "coyote-dashboard",
            "https://auth-service.coyotesense.local:8443",
            "https://dashboard.coyotesense.local/callback",
            "keyvault.read dashboard.access user.profile"
        );
        
        infra::security::OAuth2AuthCodeRequest request;
        request.client_id = config.client_id;
        request.redirect_uri = "https://dashboard.coyotesense.local/callback";
        request.scope = config.scope;
        request.state = "random_state_value";
        request.code_challenge = "generated_code_challenge";
        request.code_challenge_method = "S256";
        
        return oauth_client->buildAuthorizationUrl(config, request);
    }
    
    bool handleCallback(const std::string& code, const std::string& state) {
        // Verify state parameter, exchange code for token
        // Implementation would handle the full Authorization Code flow
        return true;
    }
};

} // namespace examples
} // namespace coyote
