#pragma once

#include <string>
#include <chrono>
#include <optional>
#include <map>

namespace coyote {
namespace infra {
namespace security {
namespace auth {

/**
 * @brief Authentication Grant Types
 * 
 * This system supports multiple authentication standards:
 * - OAuth2 RFC 6749 (Client Credentials, Authorization Code)
 * - JWT Bearer RFC 7523 (JWT Bearer Assertion)
 * - mTLS RFC 8705 (Mutual TLS Client Authentication)
 */
enum class GrantType {
  kClientCredentials,
  kJwtBearerAssertion,
  kAuthorizationCode,
  kRefreshToken
};

/**
 * @brief Authentication Modes
 * 
 * Comprehensive authentication modes supporting multiple standards:
 * - OAuth2 flows (RFC 6749)
 * - JWT Bearer assertions (RFC 7523)
 * - mTLS authentication (RFC 8705)
 */
enum class AuthMode {
  kClientCredentials,    // Standard OAuth2 client credentials flow
  kClientCredentialsMtls, // Client credentials with mTLS
  kJwtBearer,           // JWT Bearer assertion flow
  kAuthorizationCode,   // Authorization code flow
  kAuthorizationCodePkce // Authorization code flow with PKCE
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

// Authentication Token Response
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
};

// Authentication Token Introspection Response
struct IntrospectResponse {
  bool active;
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
};

/**
 * @brief Authentication Client Configuration
 * 
 * Supports configuration for multiple authentication standards:
 * - OAuth2 client credentials and authorization code flows
 * - JWT Bearer assertions with private key signing
 * - mTLS client certificate authentication
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
