#include "oauth2_auth_server.h"
#include <nlohmann/json.hpp>
#include <jwt-cpp/jwt.h>
#include <iostream>
#include <fstream>
#include <sstream>

namespace coyote {
namespace units {
namespace auth {

OAuth2AuthServer::OAuth2AuthServer() 
    : token_ttl_(std::chrono::seconds(3600))
    , refresh_token_ttl_(std::chrono::seconds(86400)) {
}

bool OAuth2AuthServer::initialize() {
    try {
        // Load configuration from environment
        issuer_ = std::getenv("AUTH_ISSUER") ? std::getenv("AUTH_ISSUER") : "https://auth-service.coyotesense.local";
        private_key_path_ = std::getenv("AUTH_PRIVATE_KEY_PATH") ? std::getenv("AUTH_PRIVATE_KEY_PATH") : "/opt/coyote/keys/auth-service.key";
        public_key_path_ = std::getenv("AUTH_PUBLIC_KEY_PATH") ? std::getenv("AUTH_PUBLIC_KEY_PATH") : "/opt/coyote/keys/auth-service.pub";
        
        if (std::getenv("AUTH_TOKEN_TTL")) {
            token_ttl_ = std::chrono::seconds(std::stoi(std::getenv("AUTH_TOKEN_TTL")));
        }
        
        if (std::getenv("AUTH_REFRESH_TOKEN_TTL")) {
            refresh_token_ttl_ = std::chrono::seconds(std::stoi(std::getenv("AUTH_REFRESH_TOKEN_TTL")));
        }
        
        // Initialize factories
        http_factory_ = std::make_shared<infra::http::HttpClientFactory>();
        oauth_factory_ = std::make_shared<infra::security::OAuth2ServiceFactory>(http_factory_);
        
        // Register default clients (in production, these would come from database/config)
        registerDefaultClients();
        
        std::cout << "OAuth2 Auth Server initialized successfully" << std::endl;
        std::cout << "Issuer: " << issuer_ << std::endl;
        std::cout << "Token TTL: " << token_ttl_.count() << " seconds" << std::endl;
        
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Failed to initialize OAuth2 Auth Server: " << e.what() << std::endl;
        return false;
    }
}

void OAuth2AuthServer::registerDefaultClients() {
    // Trading Unit - Client Credentials
    {
        infra::security::ClientConfig config;
        config.client_id = "trading-unit-001";
        config.client_secret = "trading_secret_from_keyvault";
        config.scope = "keyvault.read keyvault.write orders.submit";
        registerClient(config);
    }
    
    // Analytics Unit - mTLS
    {
        infra::security::ClientConfig config;
        config.client_id = "analytics-unit-002";
        config.client_cert_path = "/opt/coyote/certs/analytics-unit-002.crt";
        config.scope = "keyvault.read metrics.write analytics.access";
        registerClient(config);
    }
    
    // Core KeyVault Service - JWT Bearer
    {
        infra::security::ClientConfig config;
        config.client_id = "core-keyvault-service";
        config.private_key_path = "/opt/coyote/keys/core-service.key";
        config.scope = "keyvault.admin system.admin";
        registerClient(config);
    }
    
    // Dashboard - Authorization Code + PKCE
    {
        infra::security::ClientConfig config;
        config.client_id = "coyote-dashboard";
        config.scope = "keyvault.read dashboard.access user.profile";
        registerClient(config);
    }
}

void OAuth2AuthServer::registerClient(const infra::security::ClientConfig& config) {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    registered_clients_[config.client_id] = config;
    std::cout << "Registered OAuth2 client: " << config.client_id << std::endl;
}

std::string OAuth2AuthServer::handleTokenRequest(const std::map<std::string, std::string>& params) {
    try {
        auto grant_type_it = params.find("grant_type");
        if (grant_type_it == params.end()) {
            return R"({"error": "invalid_request", "error_description": "Missing grant_type parameter"})";
        }
        
        std::string grant_type = grant_type_it->second;
        
        if (grant_type == "client_credentials") {
            return handleClientCredentialsGrant(params);
        } else if (grant_type == "urn:ietf:params:oauth:grant-type:jwt-bearer") {
            return handleJWTBearerGrant(params);
        } else if (grant_type == "authorization_code") {
            return handleAuthorizationCodeGrant(params);
        } else if (grant_type == "refresh_token") {
            return handleRefreshTokenGrant(params);
        } else {
            return R"({"error": "unsupported_grant_type", "error_description": "Grant type not supported"})";
        }
        
    } catch (const std::exception& e) {
        nlohmann::json error_response;
        error_response["error"] = "server_error";
        error_response["error_description"] = e.what();
        return error_response.dump();
    }
}

std::string OAuth2AuthServer::handleClientCredentialsGrant(const std::map<std::string, std::string>& params) {
    auto client_id_it = params.find("client_id");
    auto client_secret_it = params.find("client_secret");
    
    if (client_id_it == params.end() || client_secret_it == params.end()) {
        return R"({"error": "invalid_request", "error_description": "Missing client credentials"})";
    }
    
    std::string client_id = client_id_it->second;
    std::string client_secret = client_secret_it->second;
    
    if (!validateClientCredentials(client_id, client_secret)) {
        return R"({"error": "invalid_client", "error_description": "Invalid client credentials"})";
    }
    
    // Parse scopes
    std::vector<std::string> scopes;
    auto scope_it = params.find("scope");
    if (scope_it != params.end()) {
        std::istringstream scope_stream(scope_it->second);
        std::string scope;
        while (scope_stream >> scope) {
            scopes.push_back(scope);
        }
    }
    
    // Generate tokens
    std::string access_token = generateAccessToken(client_id, scopes);
    std::string refresh_token = generateRefreshToken(client_id);
    
    // Build response
    nlohmann::json response;
    response["access_token"] = access_token;
    response["token_type"] = "Bearer";
    response["expires_in"] = token_ttl_.count();
    response["refresh_token"] = refresh_token;
    if (!scopes.empty()) {
        std::ostringstream scope_str;
        for (size_t i = 0; i < scopes.size(); ++i) {
            if (i > 0) scope_str << " ";
            scope_str << scopes[i];
        }
        response["scope"] = scope_str.str();
    }
    
    return response.dump();
}

std::string OAuth2AuthServer::handleJWTBearerGrant(const std::map<std::string, std::string>& params) {
    auto assertion_it = params.find("assertion");
    if (assertion_it == params.end()) {
        return R"({"error": "invalid_request", "error_description": "Missing assertion parameter"})";
    }
    
    std::string client_id;
    if (!validateJWTBearerAssertion(assertion_it->second, client_id)) {
        return R"({"error": "invalid_grant", "error_description": "Invalid JWT assertion"})";
    }
    
    // Parse scopes
    std::vector<std::string> scopes;
    auto scope_it = params.find("scope");
    if (scope_it != params.end()) {
        std::istringstream scope_stream(scope_it->second);
        std::string scope;
        while (scope_stream >> scope) {
            scopes.push_back(scope);
        }
    }
    
    // Generate tokens
    std::string access_token = generateAccessToken(client_id, scopes);
    
    // Build response
    nlohmann::json response;
    response["access_token"] = access_token;
    response["token_type"] = "Bearer";
    response["expires_in"] = token_ttl_.count();
    if (!scopes.empty()) {
        std::ostringstream scope_str;
        for (size_t i = 0; i < scopes.size(); ++i) {
            if (i > 0) scope_str << " ";
            scope_str << scopes[i];
        }
        response["scope"] = scope_str.str();
    }
    
    return response.dump();
}

std::string OAuth2AuthServer::handleAuthorizationCodeGrant(const std::map<std::string, std::string>& params) {
    // Implementation for Authorization Code flow
    // This would involve validating the authorization code, redirect_uri, etc.
    return R"({"error": "unsupported_grant_type", "error_description": "Authorization code grant not yet implemented"})";
}

std::string OAuth2AuthServer::handleRefreshTokenGrant(const std::map<std::string, std::string>& params) {
    auto refresh_token_it = params.find("refresh_token");
    if (refresh_token_it == params.end()) {
        return R"({"error": "invalid_request", "error_description": "Missing refresh_token parameter"})";
    }
    
    // Validate refresh token and extract client_id
    // For simplicity, using JWT for refresh tokens too
    try {
        auto decoded = jwt::decode(refresh_token_it->second);
        std::string client_id = decoded.get_payload_claim("sub").as_string();
        
        // Verify token
        std::ifstream pub_key_file(public_key_path_);
        std::string public_key((std::istreambuf_iterator<char>(pub_key_file)),
                              std::istreambuf_iterator<char>());
        
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::rs256(public_key, "", "", ""))
            .with_issuer(issuer_);
        
        verifier.verify(decoded);
        
        // Generate new access token
        std::vector<std::string> scopes;
        std::string access_token = generateAccessToken(client_id, scopes);
        
        nlohmann::json response;
        response["access_token"] = access_token;
        response["token_type"] = "Bearer";
        response["expires_in"] = token_ttl_.count();
        
        return response.dump();
        
    } catch (const std::exception& e) {
        return R"({"error": "invalid_grant", "error_description": "Invalid refresh token"})";
    }
}

bool OAuth2AuthServer::validateClientCredentials(const std::string& client_id, const std::string& client_secret) {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    
    auto it = registered_clients_.find(client_id);
    if (it == registered_clients_.end()) {
        return false;
    }
    
    return it->second.client_secret && *it->second.client_secret == client_secret;
}

bool OAuth2AuthServer::validateJWTBearerAssertion(const std::string& assertion, std::string& client_id) {
    try {
        auto decoded = jwt::decode(assertion);
        
        // Extract client_id from issuer or subject
        client_id = decoded.get_payload_claim("iss").as_string();
        
        // Verify the client is registered
        std::lock_guard<std::mutex> lock(clients_mutex_);
        auto it = registered_clients_.find(client_id);
        if (it == registered_clients_.end()) {
            return false;
        }
        
        // Load client's public key for verification
        if (!it->second.private_key_path) {
            return false;
        }
        
        // For simplicity, assume public key is stored alongside private key
        std::string pub_key_path = *it->second.private_key_path + ".pub";
        std::ifstream pub_key_file(pub_key_path);
        if (!pub_key_file.is_open()) {
            return false;
        }
        
        std::string public_key((std::istreambuf_iterator<char>(pub_key_file)),
                              std::istreambuf_iterator<char>());
        
        // Verify JWT signature
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::rs256(public_key, "", "", ""))
            .with_issuer(client_id)
            .with_subject(client_id)
            .with_audience(issuer_ + "/token");
        
        verifier.verify(decoded);
        
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "JWT validation error: " << e.what() << std::endl;
        return false;
    }
}

std::string OAuth2AuthServer::generateAccessToken(const std::string& client_id, const std::vector<std::string>& scopes) {
    // Load private key
    std::ifstream priv_key_file(private_key_path_);
    if (!priv_key_file.is_open()) {
        throw std::runtime_error("Cannot load private key for token signing");
    }
    
    std::string private_key((std::istreambuf_iterator<char>(priv_key_file)),
                           std::istreambuf_iterator<char>());
    
    auto now = std::chrono::system_clock::now();
    auto exp = now + token_ttl_;
    
    auto token = jwt::create()
        .set_issuer(issuer_)
        .set_subject(client_id)
        .set_audience("coyotesense-platform")
        .set_issued_at(now)
        .set_expires_at(exp)
        .set_id(std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count()));
    
    // Add scopes as claim
    if (!scopes.empty()) {
        nlohmann::json scope_array = scopes;
        token.set_payload_claim("scope", jwt::claim(scope_array.dump()));
    }
    
    return token.sign(jwt::algorithm::rs256("", private_key, "", ""));
}

std::string OAuth2AuthServer::generateRefreshToken(const std::string& client_id) {
    // Load private key
    std::ifstream priv_key_file(private_key_path_);
    std::string private_key((std::istreambuf_iterator<char>(priv_key_file)),
                           std::istreambuf_iterator<char>());
    
    auto now = std::chrono::system_clock::now();
    auto exp = now + refresh_token_ttl_;
    
    return jwt::create()
        .set_issuer(issuer_)
        .set_subject(client_id)
        .set_audience("coyotesense-platform")
        .set_issued_at(now)
        .set_expires_at(exp)
        .set_payload_claim("token_type", jwt::claim("refresh"))
        .sign(jwt::algorithm::rs256("", private_key, "", ""));
}

std::string OAuth2AuthServer::handleAuthorizeRequest(const std::map<std::string, std::string>& params) {
    // Implementation for authorization endpoint (interactive flows)
    return R"({"error": "unsupported_response_type", "error_description": "Authorization endpoint not yet implemented"})";
}

std::string OAuth2AuthServer::handleIntrospectRequest(const std::map<std::string, std::string>& params) {
    auto token_it = params.find("token");
    if (token_it == params.end()) {
        return R"({"active": false})";
    }
    
    try {
        auto decoded = jwt::decode(token_it->second);
        
        // Load public key for verification
        std::ifstream pub_key_file(public_key_path_);
        std::string public_key((std::istreambuf_iterator<char>(pub_key_file)),
                              std::istreambuf_iterator<char>());
        
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::rs256(public_key, "", "", ""))
            .with_issuer(issuer_);
        
        verifier.verify(decoded);
        
        // Token is valid
        nlohmann::json response;
        response["active"] = true;
        response["client_id"] = decoded.get_payload_claim("sub").as_string();
        response["exp"] = decoded.get_expires_at().time_since_epoch().count();
        response["iat"] = decoded.get_issued_at().time_since_epoch().count();
        
        if (decoded.has_payload_claim("scope")) {
            response["scope"] = decoded.get_payload_claim("scope").as_string();
        }
        
        return response.dump();
        
    } catch (const std::exception& e) {
        return R"({"active": false})";
    }
}

std::string OAuth2AuthServer::handleRevokeRequest(const std::map<std::string, std::string>& params) {
    // Implementation for token revocation
    // In a real implementation, this would add tokens to a blacklist
    return "{}"; // Empty response indicates success
}

} // namespace auth
} // namespace units
} // namespace coyote
