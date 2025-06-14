#include "auth_client.h"
#include <nlohmann/json.hpp>
#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>
#include <chrono>
#include <thread>
#include <iostream>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

namespace coyote {
namespace infra {
namespace security {
namespace auth {

// AuthClientImpl Implementation

AuthClientImpl::AuthClientImpl(std::unique_ptr<coyote::infra::HttpClient> http_client)
    : http_client_(std::move(http_client))
    , token_storage_(std::make_unique<InMemoryTokenStorage>())
    , logger_(std::make_unique<ConsoleAuthLogger>())
    , auto_refresh_enabled_(false) {
}

AuthClientImpl::AuthClientImpl(const AuthClientConfig& config,                                 std::unique_ptr<coyote::infra::HttpClient> http_client)
    : config_(config)
    , http_client_(std::move(http_client))
    , token_storage_(std::make_unique<InMemoryTokenStorage>())
    , logger_(std::make_unique<ConsoleAuthLogger>())
    , auto_refresh_enabled_(false) {
    
    if (config_.auto_refresh) {
        start_auto_refresh();
    }
}

AuthClientImpl::~AuthClientImpl() {
    stop_auto_refresh();
}

std::future<AuthTokenResponse> AuthClientImpl::authenticate_async() {
    return std::async(std::launch::async, [this]() {
        return authenticate();
    });
}

AuthTokenResponse AuthClientImpl::authenticate() {
    try {
        AuthTokenResponse token;
        
        // Check if we have a valid cached token
        if (token_storage_->get_token(config_.client_id, token) && 
            token_storage_->is_token_valid(token)) {
            log_debug("Using cached valid token");
            return token;
        }
        
        // Perform authentication based on grant type
        if (config_.grant_type == "client_credentials") {
            token = perform_client_credentials_flow();
        } else if (config_.grant_type == "urn:ietf:params:oauth:grant-type:jwt-bearer") {
            token = perform_jwt_bearer_flow();
        } else {
            throw std::runtime_error("Unsupported grant type: " + config_.grant_type);
        }
        
        // Store the token
        std::lock_guard<std::mutex> lock(token_mutex_);
        current_token_ = token;
        token_expiry_ = std::chrono::steady_clock::now() + 
                      std::chrono::seconds(token.expires_in - config_.token_refresh_buffer_seconds);
        
        token_storage_->store_token(config_.client_id, token);
        
        log_info("Authentication successful for client: " + config_.client_id);
        return token;
        
    } catch (const std::exception& e) {
        log_error("Authentication failed: " + std::string(e.what()));
        throw;
    }
}

AuthTokenResponse AuthClientImpl::perform_client_credentials_flow() {
    auto request = create_token_request();
    request->SetMethod(coyote::infra::HttpMethod::kPost);
    request->SetUrl(config_.auth_server_url + "/token");
    request->SetHeader("Content-Type", "application/x-www-form-urlencoded");
    
    // Configure mTLS if enabled
    if (config_.enable_mtls) {
        request->SetClientCert(config_.client_cert_path, config_.client_key_path);
        if (!config_.ca_cert_path.empty()) {
            request->SetCACert(config_.ca_cert_path);
        }
    }
    
    // Build request body
    std::stringstream body;
    body << "grant_type=client_credentials";
    if (!config_.client_id.empty()) {
        body << "&client_id=" << config_.client_id;
    }
    if (!config_.client_secret.empty() && !config_.enable_mtls) {
        body << "&client_secret=" << config_.client_secret;
    }
    if (!config_.scopes.empty()) {
        body << "&scope=";
        for (size_t i = 0; i < config_.scopes.size(); ++i) {
            if (i > 0) body << "%20"; // URL-encoded space
            body << config_.scopes[i];
        }
    }
    
    request->SetBody(body.str());
    
    log_debug("Performing client credentials flow");
    auto response = http_client_->Execute(*request);
    
    if (!response || !response->IsSuccess()) {
        throw std::runtime_error("Token request failed: " + 
            (response ? std::to_string(response->GetStatusCode()) : "No response"));
    }
    
    return parse_token_response(response->GetBody());
}

AuthTokenResponse AuthClientImpl::perform_jwt_bearer_flow() {
    auto request = create_token_request();
    request->SetMethod(coyote::infra::HttpMethod::kPost);
    request->SetUrl(config_.auth_server_url + "/token");
    request->SetHeader("Content-Type", "application/x-www-form-urlencoded");
    
    // Create JWT assertion
    std::string assertion = create_jwt_assertion();
    
    // Build request body
    std::stringstream body;
    body << "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer";
    body << "&assertion=" << assertion;
    if (!config_.scopes.empty()) {
        body << "&scope=";
        for (size_t i = 0; i < config_.scopes.size(); ++i) {
            if (i > 0) body << "%20";
            body << config_.scopes[i];
        }
    }
    
    request->SetBody(body.str());
    
    log_debug("Performing JWT Bearer flow");
    auto response = http_client_->Execute(*request);
    
    if (!response || !response->IsSuccess()) {
        throw std::runtime_error("JWT Bearer token request failed: " + 
            (response ? std::to_string(response->GetStatusCode()) : "No response"));
    }
    
    return parse_token_response(response->GetBody());
}

std::string AuthClientImpl::create_jwt_assertion() {
    // This is a simplified JWT creation - in production, use a proper JWT library
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::seconds(300); // 5 minutes
    
    nlohmann::json header = {
        {"alg", config_.jwt_algorithm},
        {"typ", "JWT"}
    };
    
    nlohmann::json payload = {
        {"iss", config_.client_id},
        {"sub", config_.client_id},
        {"aud", config_.auth_server_url + "/token"},
        {"iat", std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count()},
        {"exp", std::chrono::duration_cast<std::chrono::seconds>(exp.time_since_epoch()).count()},
        {"jti", generate_code_verifier().substr(0, 16)} // Use as unique ID
    };
    
    // Base64URL encode header and payload
    std::string header_b64 = base64_url_encode(header.dump());
    std::string payload_b64 = base64_url_encode(payload.dump());
    
    // Create signature (simplified - should use proper JWT signing)
    std::string message = header_b64 + "." + payload_b64;
    std::string signature = "signature_placeholder"; // TODO: Implement proper RSA signing
    
    return message + "." + base64_url_encode(signature);
}

std::string AuthClientImpl::base64_url_encode(const std::string& data) {
    // Simplified Base64URL encoding
    // In production, use a proper Base64URL library
    std::string result;
    // TODO: Implement proper Base64URL encoding
    return result;
}

std::future<AuthTokenResponse> AuthClientImpl::refresh_token_async(const std::string& refresh_token) {
    return std::async(std::launch::async, [this, refresh_token]() {
        return refresh_token(refresh_token);
    });
}

AuthTokenResponse AuthClientImpl::refresh_token(const std::string& refresh_token) {
    try {
        auto request = create_token_request();
        request->SetMethod(coyote::infra::HttpMethod::kPost);
        request->SetUrl(config_.auth_server_url + "/token");
        request->SetHeader("Content-Type", "application/x-www-form-urlencoded");
        
        std::stringstream body;
        body << "grant_type=refresh_token";
        body << "&refresh_token=" << refresh_token;
        if (!config_.client_id.empty()) {
            body << "&client_id=" << config_.client_id;
        }
        if (!config_.client_secret.empty()) {
            body << "&client_secret=" << config_.client_secret;
        }
        
        request->SetBody(body.str());
        
        log_debug("Refreshing token");
        auto response = http_client_->Execute(*request);
        
        if (!response || !response->IsSuccess()) {
            throw std::runtime_error("Token refresh failed: " + 
                (response ? std::to_string(response->GetStatusCode()) : "No response"));
        }
        
        auto token = parse_token_response(response->GetBody());
        
        // Update stored token
        std::lock_guard<std::mutex> lock(token_mutex_);
        current_token_ = token;
        token_expiry_ = std::chrono::steady_clock::now() + 
                      std::chrono::seconds(token.expires_in - config_.token_refresh_buffer_seconds);
        
        token_storage_->store_token(config_.client_id, token);
        
        log_info("Token refreshed successfully");
        return token;
        
    } catch (const std::exception& e) {
        log_error("Token refresh failed: " + std::string(e.what()));
        throw;
    }
}

std::string AuthClientImpl::get_authorization_url(const std::string& state) {
    std::stringstream url;
    url << config_.auth_server_url << "/authorize";
    url << "?response_type=code";
    url << "&client_id=" << config_.client_id;
    url << "&redirect_uri=" << config_.redirect_uri;
    
    if (!config_.scopes.empty()) {
        url << "&scope=";
        for (size_t i = 0; i < config_.scopes.size(); ++i) {
            if (i > 0) url << "%20";
            url << config_.scopes[i];
        }
    }
    
    if (!state.empty()) {
        url << "&state=" << state;
    }
    
    if (config_.use_pkce) {
        // Store code verifier for later use
        std::string code_verifier = generate_code_verifier();
        std::string code_challenge = generate_pkce_challenge(code_verifier);
        
        // TODO: Store code_verifier securely for later retrieval
        
        url << "&code_challenge=" << code_challenge;
        url << "&code_challenge_method=S256";
    }
    
    return url.str();
}

std::future<AuthTokenResponse> AuthClientImpl::exchange_code_async(const std::string& code, const std::string& code_verifier) {
    return std::async(std::launch::async, [this, code, code_verifier]() {
        return exchange_code(code, code_verifier);
    });
}

AuthTokenResponse AuthClientImpl::exchange_code(const std::string& code, const std::string& code_verifier) {
    try {
        auto request = create_token_request();
        request->SetMethod(coyote::infra::HttpMethod::kPost);
        request->SetUrl(config_.auth_server_url + "/token");
        request->SetHeader("Content-Type", "application/x-www-form-urlencoded");
        
        std::stringstream body;
        body << "grant_type=authorization_code";
        body << "&code=" << code;
        body << "&redirect_uri=" << config_.redirect_uri;
        body << "&client_id=" << config_.client_id;
        if (!config_.client_secret.empty()) {
            body << "&client_secret=" << config_.client_secret;
        }
        if (config_.use_pkce && !code_verifier.empty()) {
            body << "&code_verifier=" << code_verifier;
        }
        
        request->SetBody(body.str());
        
        log_debug("Exchanging authorization code for token");
        auto response = http_client_->Execute(*request);
        
        if (!response || !response->IsSuccess()) {
            throw std::runtime_error("Code exchange failed: " + 
                (response ? std::to_string(response->GetStatusCode()) : "No response"));
        }
        
        auto token = parse_token_response(response->GetBody());
        
        // Store the token
        std::lock_guard<std::mutex> lock(token_mutex_);
        current_token_ = token;
        token_expiry_ = std::chrono::steady_clock::now() + 
                      std::chrono::seconds(token.expires_in - config_.token_refresh_buffer_seconds);
        
        token_storage_->store_token(config_.client_id, token);
        
        log_info("Authorization code exchanged successfully");
        return token;
        
    } catch (const std::exception& e) {
        log_error("Code exchange failed: " + std::string(e.what()));
        throw;
    }
}

bool AuthClientImpl::is_token_valid(const AuthTokenResponse& token) {
    return token_storage_->is_token_valid(token);
}

std::future<bool> AuthClientImpl::revoke_token_async(const std::string& token) {
    return std::async(std::launch::async, [this, token]() {
        return revoke_token(token);
    });
}

bool AuthClientImpl::revoke_token(const std::string& token) {
    try {
        auto request = create_token_request();
        request->SetMethod(coyote::infra::HttpMethod::kPost);
        request->SetUrl(config_.auth_server_url + "/revoke");
        request->SetHeader("Content-Type", "application/x-www-form-urlencoded");
        
        std::stringstream body;
        body << "token=" << token;
        if (!config_.client_id.empty()) {
            body << "&client_id=" << config_.client_id;
        }
        if (!config_.client_secret.empty()) {
            body << "&client_secret=" << config_.client_secret;
        }
        
        request->SetBody(body.str());
        
        log_debug("Revoking token");
        auto response = http_client_->Execute(*request);
        
        bool success = response && response->IsSuccess();
        if (success) {
            log_info("Token revoked successfully");
            token_storage_->delete_token(config_.client_id);
        } else {
            log_warning("Token revocation failed");
        }
        
        return success;
        
    } catch (const std::exception& e) {
        log_error("Token revocation error: " + std::string(e.what()));
        return false;
    }
}

std::future<AuthIntrospectResponse> AuthClientImpl::introspect_token_async(const std::string& token) {
    return std::async(std::launch::async, [this, token]() {
        return introspect_token(token);
    });
}

AuthIntrospectResponse AuthClientImpl::introspect_token(const std::string& token) {
    try {
        auto request = create_token_request();
        request->SetMethod(coyote::infra::HttpMethod::kPost);
        request->SetUrl(config_.auth_server_url + "/introspect");
        request->SetHeader("Content-Type", "application/x-www-form-urlencoded");
        request->SetHeader("Authorization", "Bearer " + current_token_.access_token);
        
        std::stringstream body;
        body << "token=" << token;
        
        request->SetBody(body.str());
        
        log_debug("Introspecting token");
        auto response = http_client_->Execute(*request);
        
        if (!response || !response->IsSuccess()) {
            log_warning("Token introspection failed");
            return OAuth2IntrospectResponse{};
        }
        
        return parse_introspect_response(response->GetBody());
        
    } catch (const std::exception& e) {
        log_error("Token introspection error: " + std::string(e.what()));
        return OAuth2IntrospectResponse{};
    }
}

void AuthClientImpl::set_config(const AuthClientConfig& config) {
    config_ = config;
    
    // Restart auto-refresh if configuration changed
    if (config_.auto_refresh && !auto_refresh_enabled_) {
        start_auto_refresh();
    } else if (!config_.auto_refresh && auto_refresh_enabled_) {
        stop_auto_refresh();
    }
}

AuthClientConfig AuthClientImpl::get_config() const {
    return config_;
}

void AuthClientImpl::set_token_storage(std::unique_ptr<IAuthTokenStorage> storage) {
    token_storage_ = std::move(storage);
}

void AuthClientImpl::set_logger(std::unique_ptr<IAuthLogger> logger) {
    logger_ = std::move(logger);
}

bool AuthClientImpl::test_connection() {
    try {
        log_debug("Testing connection to auth server");
        return http_client_->Ping(config_.auth_server_url);
    } catch (const std::exception& e) {
        log_error("Connection test failed: " + std::string(e.what()));
        return false;
    }
}

std::string AuthClientImpl::get_server_info() {
    try {
        auto request = create_token_request();
        request->SetMethod(coyote::infra::HttpMethod::kGet);
        request->SetUrl(config_.auth_server_url + "/.well-known/oauth-authorization-server");
        
        auto response = http_client_->Execute(*request);
        
        if (response && response->IsSuccess()) {
            return response->GetBody();
        }
        
        return "{}";
        
    } catch (const std::exception& e) {
        log_error("Failed to get server info: " + std::string(e.what()));
        return "{}";
    }
}

// Helper methods

std::unique_ptr<coyote::infra::HttpRequest> AuthClientImpl::create_token_request() {
    auto request = std::make_unique<coyote::infra::HttpRequestReal>();
    request->SetTimeout(config_.timeout_ms);
    request->SetVerifyPeer(config_.verify_ssl);
    return request;
}

AuthTokenResponse AuthClientImpl::parse_token_response(const std::string& response_body) {
    AuthTokenResponse token;
    
    try {
        auto json = nlohmann::json::parse(response_body);
        
        if (json.contains("error")) {
            throw std::runtime_error("Auth error: " + json["error"].get<std::string>() + 
                " - " + json.value("error_description", "Unknown error"));
        }
        
        token.access_token = json.value("access_token", "");
        token.token_type = json.value("token_type", "Bearer");
        token.expires_in = json.value("expires_in", 3600);
        token.refresh_token = json.value("refresh_token", "");
        token.scope = json.value("scope", "");
        
        if (token.access_token.empty()) {
            throw std::runtime_error("No access token in response");
        }
        
    } catch (const nlohmann::json::exception& e) {
        throw std::runtime_error("Failed to parse token response: " + std::string(e.what()));
    }
    
    return token;
}

AuthIntrospectResponse AuthClientImpl::parse_introspect_response(const std::string& response_body) {
    AuthIntrospectResponse introspect;
    
    try {
        auto json = nlohmann::json::parse(response_body);
        
        introspect.active = json.value("active", false);
        introspect.scope = json.value("scope", "");
        introspect.client_id = json.value("client_id", "");
        introspect.username = json.value("username", "");
        introspect.token_type = json.value("token_type", "");
        introspect.exp = json.value("exp", 0);
        introspect.iat = json.value("iat", 0);
        introspect.sub = json.value("sub", "");
        introspect.aud = json.value("aud", "");
        introspect.iss = json.value("iss", "");
        introspect.jti = json.value("jti", "");
        
    } catch (const nlohmann::json::exception& e) {
        log_error("Failed to parse introspect response: " + std::string(e.what()));
    }
    
    return introspect;
}

std::string AuthClientImpl::generate_code_verifier() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 61);
    
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::string verifier;
    verifier.reserve(128);
    
    for (int i = 0; i < 128; ++i) {
        verifier += chars[dis(gen)];
    }
    
    return verifier;
}

std::string AuthClientImpl::generate_pkce_challenge(const std::string& verifier) {
    // SHA256 hash of the verifier
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(verifier.c_str()), verifier.length(), hash);
    
    // Base64URL encode the hash
    return base64_url_encode(std::string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH));
}

bool AuthClientImpl::should_refresh_token() const {
    std::lock_guard<std::mutex> lock(token_mutex_);
    return std::chrono::steady_clock::now() >= token_expiry_;
}

void AuthClientImpl::start_auto_refresh() {
    if (auto_refresh_enabled_) return;
    
    auto_refresh_enabled_ = true;
    refresh_thread_ = std::thread(&AuthClientImpl::auto_refresh_loop, this);
    log_info("Auto-refresh enabled");
}

void AuthClientImpl::stop_auto_refresh() {
    if (!auto_refresh_enabled_) return;
    
    auto_refresh_enabled_ = false;
    refresh_cv_.notify_all();
    
    if (refresh_thread_.joinable()) {
        refresh_thread_.join();
    }
    
    log_info("Auto-refresh disabled");
}

void AuthClientImpl::auto_refresh_loop() {
    while (auto_refresh_enabled_) {
        std::unique_lock<std::mutex> lock(refresh_mutex_);
        
        // Wait until token needs refresh or auto-refresh is disabled
        refresh_cv_.wait_for(lock, std::chrono::seconds(60), [this]() {
            return !auto_refresh_enabled_ || should_refresh_token();
        });
        
        if (!auto_refresh_enabled_) break;
        
        if (should_refresh_token() && !current_token_.refresh_token.empty()) {
            try {
                log_debug("Auto-refreshing token");
                refresh_token(current_token_.refresh_token);
            } catch (const std::exception& e) {
                log_error("Auto-refresh failed: " + std::string(e.what()));
                // Wait before retry
                std::this_thread::sleep_for(std::chrono::milliseconds(config_.retry_delay_ms));
            }
        }
    }
}

void AuthClientImpl::log_info(const std::string& message) {
    if (logger_) logger_->log_info(message);
}

void AuthClientImpl::log_warning(const std::string& message) {
    if (logger_) logger_->log_warning(message);
}

void AuthClientImpl::log_error(const std::string& message) {
    if (logger_) logger_->log_error(message);
}

void AuthClientImpl::log_debug(const std::string& message) {
    if (logger_) logger_->log_debug(message);
}

// InMemoryTokenStorage Implementation

bool InMemoryTokenStorage::store_token(const std::string& key, const AuthTokenResponse& token) {
    std::lock_guard<std::mutex> lock(storage_mutex_);
    tokens_[key] = token;
    return true;
}

bool InMemoryTokenStorage::get_token(const std::string& key, AuthTokenResponse& token) {
    std::lock_guard<std::mutex> lock(storage_mutex_);
    auto it = tokens_.find(key);
    if (it != tokens_.end()) {
        token = it->second;
        return true;
    }
    return false;
}

bool InMemoryTokenStorage::delete_token(const std::string& key) {
    std::lock_guard<std::mutex> lock(storage_mutex_);
    return tokens_.erase(key) > 0;
}

bool InMemoryTokenStorage::is_token_valid(const AuthTokenResponse& token) {
    // Simple validation - check if token exists and is not expired
    // In production, this should also verify the token with the auth server
    return !token.access_token.empty() && token.expires_in > 0;
}

// ConsoleAuthLogger Implementation

void ConsoleAuthLogger::log_info(const std::string& message) {
    std::cout << "[INFO] Auth: " << message << std::endl;
}

void ConsoleAuthLogger::log_warning(const std::string& message) {
    std::cout << "[WARN] Auth: " << message << std::endl;
}

void ConsoleAuthLogger::log_error(const std::string& message) {
    std::cerr << "[ERROR] Auth: " << message << std::endl;
}

void ConsoleAuthLogger::log_debug(const std::string& message) {
    std::cout << "[DEBUG] Auth: " << message << std::endl;
}

// AuthClientFactory Implementation

std::unique_ptr<AuthClient> AuthClientFactory::CreateClientCredentialsClient(
    const std::string& auth_server_url,
    const std::string& client_id,
    const std::string& client_secret,
    const std::vector<std::string>& scopes,
    std::unique_ptr<coyote::infra::HttpClient> http_client) {
    
    AuthClientConfig config;
    config.auth_server_url = auth_server_url;
    config.client_id = client_id;
    config.client_secret = client_secret;
    config.scopes = scopes;    config.grant_type = "client_credentials";
    
    if (!http_client) {
        http_client = std::make_unique<coyote::infra::HttpClientReal>();
    }
    
    return std::make_unique<AuthClientImpl>(config, std::move(http_client));
}

std::unique_ptr<AuthClient> AuthClientFactory::CreateMtlsClient(
    const std::string& auth_server_url,
    const std::string& client_id,
    const std::string& client_cert_path,
    const std::string& client_key_path,    const std::string& ca_cert_path,
    const std::vector<std::string>& scopes,
    std::unique_ptr<coyote::infra::HttpClient> http_client) {
    
    AuthClientConfig config;
    config.auth_server_url = auth_server_url;
    config.client_id = client_id;
    config.scopes = scopes;
    config.grant_type = "client_credentials";
    config.enable_mtls = true;
    config.client_cert_path = client_cert_path;
    config.client_key_path = client_key_path;
    config.ca_cert_path = ca_cert_path;
    
    if (!http_client) {
        http_client = std::make_unique<coyote::infra::HttpClientReal>();
    }
    
    return std::make_unique<AuthClientImpl>(config, std::move(http_client));
}

std::unique_ptr<AuthClient> AuthClientFactory::CreateJwtBearerClient(
    const std::string& auth_server_url,
    const std::string& client_id,    const std::string& jwt_private_key_path,
    const std::vector<std::string>& scopes,
    std::unique_ptr<coyote::infra::HttpClient> http_client) {
    
    AuthClientConfig config;
    config.auth_server_url = auth_server_url;
    config.client_id = client_id;
    config.scopes = scopes;
    config.grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    config.jwt_private_key_path = jwt_private_key_path;
    
    if (!http_client) {
        http_client = std::make_unique<coyote::infra::HttpClientReal>();
    }
    
    return std::make_unique<AuthClientImpl>(config, std::move(http_client));
}

std::unique_ptr<AuthClient> AuthClientFactory::CreateAuthorizationCodeClient(
    const std::string& auth_server_url,
    const std::string& client_id,    const std::string& redirect_uri,
    const std::vector<std::string>& scopes,
    bool use_pkce,
    std::unique_ptr<coyote::infra::HttpClient> http_client) {
    
    AuthClientConfig config;
    config.auth_server_url = auth_server_url;
    config.client_id = client_id;
    config.redirect_uri = redirect_uri;
    config.scopes = scopes;
    config.grant_type = "authorization_code";
    config.use_pkce = use_pkce;
    
    if (!http_client) {
        http_client = std::make_unique<coyote::infra::HttpClientReal>();
    }
    
    return std::make_unique<AuthClientImpl>(config, std::move(http_client));
}

} // namespace auth
} // namespace infra
} // namespace coyote
