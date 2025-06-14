#pragma once

#include "auth_types.h"
#include <future>
#include <memory>

namespace coyote {
namespace infra {
namespace security {
namespace auth {

/**
 * @brief Generic Authentication Client Interface
 * 
 * This interface provides a unified API for multiple authentication standards:
 * 
 * - OAuth2 RFC 6749: Client Credentials and Authorization Code flows
 * - JWT Bearer RFC 7523: JWT Bearer assertion flow for service-to-service auth
 * - mTLS RFC 8705: Mutual TLS client authentication
 * - OpenID Connect: Authorization code flow with ID tokens
 * 
 * The interface abstracts the complexity of different authentication methods
 * while providing a consistent API for all supported standards.
 */
class AuthClient {
 public:
  virtual ~AuthClient() = default;
  
  // Client Credentials Grant (Service-to-Service)
  virtual std::future<TokenResponse> RequestTokenAsync(
      const ClientConfig& config,
      const std::vector<std::string>& scopes = {}
  ) = 0;
  
  // JWT Bearer Assertion Grant (RFC 7523)
  virtual std::future<TokenResponse> RequestTokenWithJwtAsync(
      const ClientConfig& config,
      const JwtBearerClaims& claims,
      const std::vector<std::string>& scopes = {}
  ) = 0;
  
  // Authorization Code Grant (Interactive flows)
  virtual std::string BuildAuthorizationUrl(
      const ClientConfig& config,
      const AuthCodeRequest& request
  ) = 0;
  
  virtual std::future<TokenResponse> ExchangeCodeForTokenAsync(
      const ClientConfig& config,
      const std::string& code,
      const std::string& redirect_uri,
      const std::optional<std::string>& code_verifier = std::nullopt
  ) = 0;
  
  // Refresh Token
  virtual std::future<TokenResponse> RefreshTokenAsync(
      const ClientConfig& config,
      const std::string& refresh_token
  ) = 0;
  
  // Token validation/introspection
  virtual std::future<bool> ValidateTokenAsync(
      const std::string& token,
      const ClientConfig& config
  ) = 0;
  
  // Revoke token
  virtual std::future<bool> RevokeTokenAsync(
      const std::string& token,
      const ClientConfig& config
  ) = 0;
};

/**
 * @brief Token Manager - handles automatic refresh and caching
 * 
 * Manages authentication tokens across different authentication standards,
 * providing automatic refresh, secure storage, and validation.
 */
class TokenManager {
 public:
  virtual ~TokenManager() = default;
  
  // Get valid token (automatically refreshes if needed)
  virtual std::future<std::string> GetValidTokenAsync(
      const std::string& client_id
  ) = 0;
  
  // Store token (after initial authentication)
  virtual void StoreToken(
      const std::string& client_id,
      const TokenResponse& token
  ) = 0;
  
  // Remove token (logout/cleanup)
  virtual void RemoveToken(const std::string& client_id) = 0;
  
  // Check if token exists and is valid
  virtual bool HasValidToken(const std::string& client_id) = 0;
  
  // Force refresh token
  virtual std::future<std::string> ForceRefreshAsync(
      const std::string& client_id
  ) = 0;
};

/**
 * @brief Authentication Service - high-level interface for units
 * 
 * Provides a simplified authentication interface that automatically handles
 * token management, refresh, and validation across all supported standards.
 * Units should primarily use this interface rather than the lower-level
 * AuthClient interface.
 */
class AuthenticationService {
 public:
  virtual ~AuthenticationService() = default;
  
  // Initialize authentication for a unit (called on startup)
  virtual std::future<bool> InitializeAsync(
      const ClientConfig& config
  ) = 0;
  
  // Get access token for making authenticated requests
  virtual std::future<std::string> GetAccessTokenAsync() = 0;
  
  // Refresh credentials if needed
  virtual std::future<void> RefreshCredentialsAsync() = 0;
  
  // Check authentication status
  virtual bool IsAuthenticated() const = 0;
  
  // Shutdown and cleanup
  virtual void Shutdown() = 0;
};

/**
 * @brief Factory for creating authentication services
 * 
 * Creates instances of authentication clients, token managers, and services
 * with appropriate configurations for different authentication standards.
 */
class AuthServiceFactory {
 public:
  virtual ~AuthServiceFactory() = default;
  
  virtual std::unique_ptr<AuthClient> CreateClient(
      const std::string& mode = "real"
  ) = 0;
  
  virtual std::unique_ptr<TokenManager> CreateTokenManager(
      const std::string& mode = "real"
  ) = 0;
  
  virtual std::unique_ptr<AuthenticationService> CreateAuthService(
      const ClientConfig& config,
      const std::string& mode = "real"
  ) = 0;
};

}  // namespace auth
}  // namespace security
}  // namespace infra
}  // namespace coyote
