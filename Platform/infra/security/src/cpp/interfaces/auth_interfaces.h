#pragma once

#include "auth_types.h"
#include <future>
#include <memory>
#include <vector>
#include <string>
#include <tuple>
#include <optional>
#include <mutex>
#include <map>
#include <iostream>
#include <iomanip>
#include <chrono>

namespace coyote {
namespace infra {

// Forward declare HTTP client interface
class IHttpClient;

namespace security {
namespace auth {

/**
 * @brief Multi-standard authentication client interface supporting OAuth2 (RFC 6749), 
 * JWT Bearer (RFC 7523), and mTLS (RFC 8705) authentication methods.
 * 
 * This interface provides a unified API for multiple authentication standards:
 * - OAuth2 Client Credentials (RFC 6749)
 * - OAuth2 Authorization Code (RFC 6749) 
 * - JWT Bearer Token (RFC 7523)
 * - Mutual TLS (RFC 8705)
 */
class IAuthClient {
public:
    virtual ~IAuthClient() = default;

    /**
     * @brief Authenticate using Client Credentials flow (OAuth2 RFC 6749)
     * @param scopes Optional scopes to request
     * @return Future containing authentication result
     */
    virtual std::future<AuthResult> authenticate_client_credentials_async(
        const std::vector<std::string>& scopes = {}) = 0;

    /**
     * @brief Authenticate using JWT Bearer flow (RFC 7523)
     * @param subject Optional subject for the JWT
     * @param scopes Optional scopes to request
     * @return Future containing authentication result
     */
    virtual std::future<AuthResult> authenticate_jwt_bearer_async(
        const std::string& subject = "",
        const std::vector<std::string>& scopes = {}) = 0;

    /**
     * @brief Authenticate using Authorization Code flow (OAuth2 RFC 6749)
     * @param authorization_code Authorization code from redirect
     * @param redirect_uri Redirect URI used in authorization request
     * @param code_verifier Optional PKCE code verifier
     * @return Future containing authentication result
     */
    virtual std::future<AuthResult> authenticate_authorization_code_async(
        const std::string& authorization_code,
        const std::string& redirect_uri,
        const std::string& code_verifier = "") = 0;

    /**
     * @brief Start Authorization Code + PKCE flow (OAuth2 RFC 7636)
     * @param redirect_uri Redirect URI for the flow
     * @param scopes Optional scopes to request
     * @param state Optional state parameter
     * @return Tuple of (authorization_url, code_verifier, state)
     */
    virtual std::tuple<std::string, std::string, std::string> start_authorization_code_flow(
        const std::string& redirect_uri,
        const std::vector<std::string>& scopes = {},
        const std::string& state = "") = 0;

    /**
     * @brief Refresh access token using refresh token
     * @param refresh_token Refresh token
     * @return Future containing authentication result
     */
    virtual std::future<AuthResult> refresh_token_async(
        const std::string& refresh_token) = 0;

    /**
     * @brief Get current valid token (automatically refreshes if needed)
     * @return Future containing optional valid token
     */
    virtual std::future<std::optional<AuthToken>> get_valid_token_async() = 0;

    /**
     * @brief Revoke a token
     * @param token Token to revoke
     * @return Future indicating success/failure
     */
    virtual std::future<bool> revoke_token_async(const std::string& token) = 0;

    /**
     * @brief Validate/introspect a token
     * @param token Token to validate
     * @return Future containing introspection result
     */
    virtual std::future<IntrospectResponse> introspect_token_async(
        const std::string& token) = 0;

    /**
     * @brief Get server information (discovery endpoint)
     * @return Future containing server information
     */
    virtual std::future<AuthServerInfo> get_server_info_async() = 0;

    /**
     * @brief Check if client is authenticated
     * @return True if client has valid credentials
     */
    virtual bool is_authenticated() const = 0;

    /**
     * @brief Clear stored authentication state
     */
    virtual void clear_authentication() = 0;
};

/**
 * @brief Authentication token storage interface
 */
class IAuthTokenStorage {
public:
    virtual ~IAuthTokenStorage() = default;
    
    /**
     * @brief Store a token for a client
     * @param client_id Client identifier
     * @param token Token to store
     */
    virtual std::future<void> store_token_async(const std::string& client_id, const AuthToken& token) = 0;
    
    /**
     * @brief Retrieve a token for a client
     * @param client_id Client identifier
     * @return Token if found, nullopt otherwise
     */
    virtual std::optional<AuthToken> get_token(const std::string& client_id) = 0;
    
    /**
     * @brief Clear stored token for a client
     * @param client_id Client identifier
     */
    virtual void clear_token(const std::string& client_id) = 0;
    
    /**
     * @brief Clear all stored tokens
     */
    virtual void clear_all_tokens() = 0;
};

/**
 * @brief Authentication logger interface
 */
class IAuthLogger {
public:
    virtual ~IAuthLogger() = default;
    
    /**
     * @brief Log information message
     * @param message Message to log
     */
    virtual void log_info(const std::string& message) = 0;
    
    /**
     * @brief Log error message
     * @param message Message to log
     */
    virtual void log_error(const std::string& message) = 0;
    
    /**
     * @brief Log debug message
     * @param message Message to log
     */
    virtual void log_debug(const std::string& message) = 0;
};

/**
 * @brief Concrete implementation of AuthClient
 */
class AuthClient : public IAuthClient {
public:
    /**
     * @brief Constructor
     * @param options Authentication client options
     * @param http_client HTTP client implementation
     * @param token_storage Token storage implementation
     * @param logger Logger implementation
     */
    AuthClient(const AuthClientOptions& options,
               std::shared_ptr<coyote::infra::IHttpClient> http_client,
               std::shared_ptr<IAuthTokenStorage> token_storage,
               std::shared_ptr<IAuthLogger> logger);

    virtual ~AuthClient() = default;

    // IAuthClient implementation
    std::future<AuthResult> authenticate_client_credentials_async(
        const std::vector<std::string>& scopes = {}) override;

    std::future<AuthResult> authenticate_jwt_bearer_async(
        const std::string& subject = "",
        const std::vector<std::string>& scopes = {}) override;

    std::future<AuthResult> authenticate_authorization_code_async(
        const std::string& authorization_code,
        const std::string& redirect_uri,
        const std::string& code_verifier = "") override;

    std::tuple<std::string, std::string, std::string> start_authorization_code_flow(
        const std::string& redirect_uri,
        const std::vector<std::string>& scopes = {},
        const std::string& state = "") override;

    std::future<AuthResult> refresh_token_async(
        const std::string& refresh_token) override;

    std::future<std::optional<AuthToken>> get_valid_token_async() override;

    std::future<bool> revoke_token_async(const std::string& token) override;

    std::future<IntrospectResponse> introspect_token_async(
        const std::string& token) override;

    std::future<AuthServerInfo> get_server_info_async() override;

    bool is_authenticated() const override;

    void clear_authentication() override;

private:
    AuthClientOptions options_;
    std::shared_ptr<coyote::infra::IHttpClient> http_client_;
    std::shared_ptr<IAuthTokenStorage> token_storage_;
    std::shared_ptr<IAuthLogger> logger_;
    mutable std::mutex mutex_;
    std::optional<AuthToken> current_token_;
};

/**
 * @brief In-memory token storage implementation
 */
class InMemoryTokenStorage : public IAuthTokenStorage {
private:
    std::map<std::string, AuthToken> tokens_;
    mutable std::mutex mutex_;

public:
    /**
     * @brief Store a token for a client
     * @param client_id Client identifier
     * @param token Token to store
     */
    std::future<void> store_token_async(const std::string& client_id, const AuthToken& token) override {
        return std::async(std::launch::async, [this, client_id, token]() {
            std::lock_guard<std::mutex> lock(mutex_);
            tokens_[client_id] = token;
        });
    }
    
    /**
     * @brief Retrieve a token for a client
     * @param client_id Client identifier
     * @return Token if found, nullopt otherwise
     */
    std::optional<AuthToken> get_token(const std::string& client_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tokens_.find(client_id);
        return (it != tokens_.end()) ? std::make_optional(it->second) : std::nullopt;
    }
    
    /**
     * @brief Clear stored token for a client
     * @param client_id Client identifier
     */
    void clear_token(const std::string& client_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        tokens_.erase(client_id);
    }
    
    /**
     * @brief Clear all stored tokens
     */
    void clear_all_tokens() override {
        std::lock_guard<std::mutex> lock(mutex_);
        tokens_.clear();
    }
};

/**
 * @brief Console logger implementation
 */
class ConsoleAuthLogger : public IAuthLogger {
private:
    std::string prefix_;

public:
    /**
     * @brief Constructor
     * @param prefix Log prefix (default: "Auth")
     */
    explicit ConsoleAuthLogger(const std::string& prefix = "Auth") 
        : prefix_(prefix) {}
    
    /**
     * @brief Log information message
     * @param message Message to log
     */
    void log_info(const std::string& message) override {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto tm = *std::gmtime(&time_t);
        
        std::cout << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") 
                  << "] [" << prefix_ << "] INFO: " << message << std::endl;
    }
    
    /**
     * @brief Log error message
     * @param message Message to log
     */
    void log_error(const std::string& message) override {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto tm = *std::gmtime(&time_t);
        
        std::cout << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") 
                  << "] [" << prefix_ << "] ERROR: " << message << std::endl;
    }
    
    /**
     * @brief Log debug message
     * @param message Message to log
     */
    void log_debug(const std::string& message) override {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto tm = *std::gmtime(&time_t);
        
        std::cout << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") 
                  << "] [" << prefix_ << "] DEBUG: " << message << std::endl;
    }
};

/**
 * @brief Null logger implementation (no logging)
 */
class NullAuthLogger : public IAuthLogger {
public:
    /**
     * @brief Log information message (no-op)
     * @param message Message to log
     */
    void log_info(const std::string& message) override {}
    
    /**
     * @brief Log error message (no-op)
     * @param message Message to log
     */
    void log_error(const std::string& message) override {}
    
    /**
     * @brief Log debug message (no-op)
     * @param message Message to log
     */
    void log_debug(const std::string& message) override {}
};

}  // namespace auth
}  // namespace security
}  // namespace infra
}  // namespace coyote
