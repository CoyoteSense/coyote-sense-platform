#pragma once

#include <string>
#include <chrono>
#include <optional>
#include <map>
#include <vector>

namespace coyote {
namespace infra {
namespace security {
namespace auth {

/**
 * @brief Multi-standard authentication modes supported by the platform
 */
enum class AuthMode {
    /// Standard OAuth2 client credentials flow (RFC 6749)
    ClientCredentials,
    
    /// Client credentials with mutual TLS authentication (RFC 8705)
    ClientCredentialsMtls,
    
    /// JWT Bearer assertion flow (RFC 7523)
    JwtBearer,
    
    /// Authorization code flow (RFC 6749)
    AuthorizationCode,
    
    /// Authorization code flow with PKCE (RFC 7636)
    AuthorizationCodePkce
};

/**
 * @brief Authentication Grant Types
 */
enum class GrantType {
  kClientCredentials,
  kJwtBearerAssertion,
  kAuthorizationCode,
  kRefreshToken
};

/**
 * @brief Authentication token information
 */
struct AuthToken {
    /// Access token
    std::string access_token;
    
    /// Token type (usually "Bearer")
    std::string token_type = "Bearer";
    
    /// Token expiration time
    std::chrono::system_clock::time_point expires_at;
    
    /// Refresh token (if available)
    std::optional<std::string> refresh_token;
    
    /// Token scopes
    std::vector<std::string> scopes;
    
    /**
     * @brief Check if token is expired
     * @return true if token is expired
     */
    bool is_expired() const {
        return std::chrono::system_clock::now() >= expires_at;
    }
    
    /**
     * @brief Check if token needs refresh (within buffer time)
     * @param buffer_seconds Buffer time in seconds (default: 300 = 5 minutes)
     * @return true if token needs refresh
     */
    bool needs_refresh(int buffer_seconds = 300) const {
        auto buffer_time = std::chrono::seconds(buffer_seconds);
        return std::chrono::system_clock::now() + buffer_time >= expires_at;
    }
    
    /**
     * @brief Get authorization header value
     * @return Authorization header value (e.g., "Bearer <token>")
     */
    std::string get_authorization_header() const {
        return token_type + " " + access_token;
    }
};

/**
 * @brief Authentication result
 */
struct AuthResult {
    /// Whether authentication was successful
    bool is_success = false;
    
    /// Authentication token (if successful)
    std::optional<AuthToken> token;
    
    /// Error code (if failed)
    std::optional<std::string> error_code;
    
    /// Error description (if failed)
    std::optional<std::string> error_description;
    
    /// Additional error details
    std::optional<std::string> error_details;
    
    /**
     * @brief Create success result
     * @param token Authentication token
     * @return Success result
     */
    static AuthResult success(const AuthToken& token) {
        AuthResult result;
        result.is_success = true;
        result.token = token;
        return result;
    }
    
    /**
     * @brief Create error result
     * @param error_code Error code
     * @param error_description Error description (optional)
     * @param error_details Additional error details (optional)
     * @return Error result
     */
    static AuthResult error(const std::string& error_code,
                           const std::optional<std::string>& error_description = std::nullopt,
                           const std::optional<std::string>& error_details = std::nullopt) {
        AuthResult result;
        result.is_success = false;
        result.error_code = error_code;
        result.error_description = error_description;
        result.error_details = error_details;
        return result;
    }
};

/**
 * @brief Authentication server information
 */
struct AuthServerInfo {
    /// Authorization endpoint URL
    std::string authorization_endpoint;
    
    /// Token endpoint URL
    std::string token_endpoint;
    
    /// Token introspection endpoint URL
    std::optional<std::string> introspection_endpoint;
    
    /// Token revocation endpoint URL
    std::optional<std::string> revocation_endpoint;
    
    /// Supported grant types
    std::vector<std::string> grant_types_supported;
    
    /// Supported scopes
    std::vector<std::string> scopes_supported;
};

/**
 * @brief Authentication client options
 */
struct AuthClientOptions {
    /// Server URL (authorization server)
    std::string server_url;
    
    /// Client ID
    std::string client_id;
    
    /// Client secret (optional for public clients)
    std::optional<std::string> client_secret;
    
    /// Default scopes
    std::vector<std::string> scopes;
    
    /// Redirect URI for authorization flows
    std::optional<std::string> redirect_uri;
    
    /// Authentication mode
    AuthMode mode = AuthMode::ClientCredentials;
    
    /// Enable automatic token refresh
    bool auto_refresh = true;
    
    /// Token refresh buffer time
    std::chrono::seconds token_refresh_buffer{300};
    
    /// HTTP timeout
    std::chrono::seconds timeout{30};
    
    /// Verify SSL certificates
    bool verify_ssl = true;
    
    /// Maximum retry attempts
    int max_retries = 3;
    
    // mTLS configuration
    std::optional<std::string> client_cert_path;
    std::optional<std::string> client_key_path;
    std::optional<std::string> ca_cert_path;
    
    // JWT Bearer configuration
    std::optional<std::string> private_key_path;
    std::optional<std::string> key_id;
    
    // PKCE configuration
    bool use_pkce = true;
    std::string code_challenge_method = "S256";
};

// Authentication Token Request
struct TokenRequest {
  GrantType grant_type;
  std::optional<std::string> client_id;
  std::optional<std::string> client_secret;
  std::optional<std::string> scope;
  std::optional<std::string> assertion;  // For JWT Bearer
  std::optional<std::string> code;       // For Auth Code flow
  std::optional<std::string> refresh_token;
  std::optional<std::string> redirect_uri;
  std::map<std::string, std::string> additional_params;
};

// Authentication Token Response (legacy compatibility)
struct TokenResponse {
  std::string access_token;
  std::string token_type = "Bearer";
  std::chrono::seconds expires_in;
  std::optional<std::string> refresh_token;
  std::optional<std::string> scope;
  std::optional<std::string> id_token;  // For OpenID Connect
  
  // Computed fields
  std::chrono::system_clock::time_point issued_at;
  std::chrono::system_clock::time_point expires_at;
  
  TokenResponse() : issued_at(std::chrono::system_clock::now()) {
    expires_at = issued_at + expires_in;
  }
  
  bool IsExpired() const {
    return std::chrono::system_clock::now() >= expires_at;
  }
  
  bool NeedsRefresh(std::chrono::seconds buffer = std::chrono::seconds(60)) const {
    return std::chrono::system_clock::now() >= (expires_at - buffer);
  }
};

// Authentication Error Response
struct ErrorResponse {
  std::string error;
  std::optional<std::string> error_description;
  std::optional<std::string> error_uri;
  int http_status_code = 400;
  
  std::string ToString() const {
    std::string result = error;
    if (error_description.has_value()) {
      result += ": " + error_description.value();
    }
    return result;
  }
};

// Authentication Token Introspection Response
struct IntrospectResponse {
  bool active = false;
  std::optional<std::string> scope;
  std::optional<std::string> client_id;
  std::optional<std::string> username;
  std::optional<std::string> token_type;
  std::optional<std::chrono::system_clock::time_point> exp;
  std::optional<std::chrono::system_clock::time_point> iat;
  std::optional<std::chrono::system_clock::time_point> nbf;
  std::optional<std::string> sub;
  std::optional<std::string> aud;
  std::optional<std::string> iss;
  std::optional<std::string> jti;
  
  bool IsExpired() const {
    if (!exp.has_value()) {
      return false;
    }
    return std::chrono::system_clock::now() >= exp.value();
  }
};

/**
 * @brief Authentication Client Configuration (legacy compatibility)
 */
struct ClientConfig {
  std::string client_id;
  std::optional<std::string> client_secret;
  std::string token_endpoint;
  std::string authorize_endpoint;
  std::optional<std::string> scope;
  
  // mTLS settings (RFC 8705)
  std::optional<std::string> client_cert_path;
  std::optional<std::string> client_key_path;
  
  // JWT Bearer settings (RFC 7523)
  std::optional<std::string> private_key_path;
  std::optional<std::string> key_id;
  
  // Token management
  std::chrono::seconds token_refresh_buffer = std::chrono::seconds(60);
  bool auto_refresh = true;
  
  // HTTP settings
  std::chrono::seconds timeout = std::chrono::seconds(30);
  int max_retries = 3;
};

// Authorization Code Flow specific
struct AuthCodeRequest {
  std::string client_id;
  std::string redirect_uri;
  std::optional<std::string> scope;
  std::optional<std::string> state;
  std::optional<std::string> code_challenge;
  std::optional<std::string> code_challenge_method = "S256"; // PKCE
};

struct AuthCodeResponse {
  std::string code;
  std::optional<std::string> state;
  std::optional<std::string> error;
  std::optional<std::string> error_description;
};

// JWT Bearer Assertion specific (RFC 7523)
struct JwtBearerClaims {
  std::string issuer;      // iss - unit-id
  std::string subject;     // sub - unit-id  
  std::string audience;    // aud - auth service token endpoint
  std::chrono::system_clock::time_point issued_at;   // iat
  std::chrono::system_clock::time_point expires_at;  // exp
  std::optional<std::string> jwt_id;  // jti
  std::map<std::string, std::string> additional_claims;
};

}  // namespace auth
}  // namespace security
}  // namespace infra
}  // namespace coyote
