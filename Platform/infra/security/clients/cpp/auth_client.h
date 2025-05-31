#pragma once

#include "../../interfaces/cpp/auth_types.h"
#include "http_client.h"
#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <future>

namespace coyote {
namespace infra {
namespace auth {

// Import types from security namespace
using coyote::infra::security::AuthMode;
using coyote::infra::security::TokenResponse;
using coyote::infra::security::IntrospectResponse;

// Forward declarations
class AuthTokenStorage;
class AuthLogger;

// OAuth2 Authentication Client Configuration
struct AuthClientConfig {
    AuthMode auth_mode = AuthMode::kClientCredentials;
    std::string auth_server_url = "https://auth-service.coyotesense.local";
    std::string client_id;
    std::string client_secret;
    std::vector<std::string> scopes;
    
    // mTLS configuration (for kClientCredentialsMtls mode)
    std::string client_cert_path;
    std::string client_key_path;
    std::string ca_cert_path;
    
    // JWT Bearer configuration (for kJwtBearer mode)
    std::string jwt_private_key_path;
    std::string jwt_algorithm = "RS256";
      // Authorization Code + PKCE configuration (for kAuthorizationCode* modes)
    std::string redirect_uri;
    bool use_pkce = true;
    
    // Token management
    bool auto_refresh = true;
    int token_refresh_buffer_seconds = 300; // Refresh 5 minutes before expiry
    int max_retry_attempts = 3;
    int retry_delay_ms = 1000;
    
    // HTTP configuration
    int timeout_ms = 10000;
    bool verify_ssl = true;
    
    // Helper methods
    bool IsClientCredentialsMode() const {
        return auth_mode == AuthMode::kClientCredentials;
    }
    
    bool IsMtlsMode() const {
        return auth_mode == AuthMode::kClientCredentialsMtls;
    }
    
    bool IsJwtBearerMode() const {
        return auth_mode == AuthMode::kJwtBearer;
    }
    
    bool IsAuthorizationCodeMode() const {
        return auth_mode == AuthMode::kAuthorizationCode || 
               auth_mode == AuthMode::kAuthorizationCodePkce;
    }
    
    bool RequiresCertificates() const {
        return IsMtlsMode();
    }
    
    bool RequiresClientSecret() const {
        return IsClientCredentialsMode() || IsMtlsMode();
    }
    
    bool RequiresJwtKey() const {
        return IsJwtBearerMode();
    }
    
    bool RequiresRedirectUri() const {
        return IsAuthorizationCodeMode();
    }
    
    // Validation method
    bool IsValid() const {
        if (client_id.empty() || auth_server_url.empty()) {
            return false;
        }
        
        switch (auth_mode) {
            case AuthMode::kClientCredentials:
                return !client_secret.empty();
                
            case AuthMode::kClientCredentialsMtls:
                return !client_secret.empty() && !client_cert_path.empty() && 
                       !client_key_path.empty();
                       
            case AuthMode::kJwtBearer:
                return !jwt_private_key_path.empty();
                
            case AuthMode::kAuthorizationCode:
            case AuthMode::kAuthorizationCodePkce:
                return !redirect_uri.empty();
                
            default:
                return false;
        }
    }
};

// Auth Token Storage Interface
class AuthTokenStorage {
 public:
  virtual ~AuthTokenStorage() = default;
  virtual bool StoreToken(const std::string& key, const TokenResponse& token) = 0;
  virtual bool GetToken(const std::string& key, TokenResponse& token) = 0;
  virtual bool DeleteToken(const std::string& key) = 0;
  virtual bool IsTokenValid(const TokenResponse& token) = 0;
};

// Auth Logger Interface
class AuthLogger {
 public:
  virtual ~AuthLogger() = default;
  virtual void LogInfo(const std::string& message) = 0;
  virtual void LogWarning(const std::string& message) = 0;
  virtual void LogError(const std::string& message) = 0;
  virtual void LogDebug(const std::string& message) = 0;
};

// Auth Authentication Client Interface
class AuthClient {
 public:
  virtual ~AuthClient() = default;
  
  // Token acquisition methods
  virtual std::future<TokenResponse> AuthenticateAsync() = 0;
  virtual TokenResponse Authenticate() = 0;
    virtual std::future<TokenResponse> RefreshTokenAsync(const std::string& refresh_token) = 0;
  virtual TokenResponse RefreshToken(const std::string& refresh_token) = 0;
  
  // Authorization Code flow methods
  virtual std::string GetAuthorizationUrl(const std::string& state = "") = 0;
  virtual std::future<TokenResponse> ExchangeCodeAsync(const std::string& code, const std::string& code_verifier = "") = 0;
  virtual TokenResponse ExchangeCode(const std::string& code, const std::string& code_verifier = "") = 0;
  
  // Token management
  virtual bool IsTokenValid(const TokenResponse& token) = 0;
  virtual std::future<bool> RevokeTokenAsync(const std::string& token) = 0;
  virtual bool RevokeToken(const std::string& token) = 0;
  virtual std::future<IntrospectResponse> IntrospectTokenAsync(const std::string& token) = 0;
  virtual IntrospectResponse IntrospectToken(const std::string& token) = 0;
  
  // Configuration
  virtual void SetConfig(const AuthClientConfig& config) = 0;
  virtual AuthClientConfig GetConfig() const = 0;  virtual void SetTokenStorage(std::unique_ptr<AuthTokenStorage> storage) = 0;
  virtual void SetLogger(std::unique_ptr<AuthLogger> logger) = 0;
  
  // Health check
  virtual bool TestConnection() = 0;
  virtual std::string GetServerInfo() = 0;
};

// Auth Authentication Client Implementation
class AuthClientImpl : public AuthClient {
 private:
  AuthClientConfig config_;
  std::unique_ptr<coyote::infra::HttpClient> http_client_;
  std::unique_ptr<AuthTokenStorage> token_storage_;
  std::unique_ptr<AuthLogger> logger_;
  
  // Internal state
  mutable std::mutex token_mutex_;
  TokenResponse current_token_;
  std::chrono::steady_clock::time_point token_expiry_;
    
    // Background refresh
      // Background refresh
  std::atomic<bool> auto_refresh_enabled_;
  std::thread refresh_thread_;
  std::condition_variable refresh_cv_;
  std::mutex refresh_mutex_;
  
  // Helper methods
  TokenResponse PerformClientCredentialsFlow();
  TokenResponse PerformJwtBearerFlow();
  TokenResponse PerformAuthorizationCodeFlow(const std::string& code, const std::string& code_verifier);
  TokenResponse PerformRefreshTokenFlow(const std::string& refresh_token);
  
  std::string CreateJwtAssertion();
  std::string GeneratePkceChallenge(const std::string& verifier);
  std::string GenerateCodeVerifier();
  
  bool ShouldRefreshToken() const;
  void StartAutoRefresh();
  void StopAutoRefresh();
  void AutoRefreshLoop();
  
  std::unique_ptr<coyote::infra::HttpRequest> CreateTokenRequest();
  TokenResponse ParseTokenResponse(const std::string& response_body);
  IntrospectResponse ParseIntrospectResponse(const std::string& response_body);
  
  void LogInfo(const std::string& message);
  void LogWarning(const std::string& message);
  void LogError(const std::string& message);
  void LogDebug(const std::string& message);

 public:  explicit AuthClientImpl(std::unique_ptr<coyote::infra::HttpClient> http_client);
  explicit AuthClientImpl(const AuthClientConfig& config, 
                               std::unique_ptr<coyote::infra::HttpClient> http_client);
  ~AuthClientImpl() override;
  
  // AuthClient implementation
  std::future<TokenResponse> AuthenticateAsync() override;
  TokenResponse Authenticate() override;
  std::future<TokenResponse> RefreshTokenAsync(const std::string& refresh_token) override;
  TokenResponse RefreshToken(const std::string& refresh_token) override;
  
  std::string GetAuthorizationUrl(const std::string& state = "") override;
  std::future<TokenResponse> ExchangeCodeAsync(const std::string& code, const std::string& code_verifier = "") override;
  TokenResponse ExchangeCode(const std::string& code, const std::string& code_verifier = "") override;
  
  bool IsTokenValid(const TokenResponse& token) override;
  std::future<bool> RevokeTokenAsync(const std::string& token) override;
  bool RevokeToken(const std::string& token) override;
  std::future<IntrospectResponse> IntrospectTokenAsync(const std::string& token) override;
  IntrospectResponse IntrospectToken(const std::string& token) override;
  
  void SetConfig(const AuthClientConfig& config) override;
  AuthClientConfig GetConfig() const override;  void SetTokenStorage(std::unique_ptr<AuthTokenStorage> storage) override;
  void SetLogger(std::unique_ptr<AuthLogger> logger) override;
  
  bool TestConnection() override;
  std::string GetServerInfo() override;
};

// In-Memory Token Storage Implementation
class InMemoryTokenStorage : public AuthTokenStorage {
 private:
  mutable std::mutex storage_mutex_;
  std::unordered_map<std::string, TokenResponse> tokens_;
  
 public:
  bool StoreToken(const std::string& key, const TokenResponse& token) override;
  bool GetToken(const std::string& key, TokenResponse& token) override;
  bool DeleteToken(const std::string& key) override;
  bool IsTokenValid(const TokenResponse& token) override;
};

// Console Logger Implementation
class ConsoleAuthLogger : public AuthLogger {
 public:
  void LogInfo(const std::string& message) override;
  void LogWarning(const std::string& message) override;
  void LogError(const std::string& message) override;
  void LogDebug(const std::string& message) override;
};

// Auth Authentication Client Factory
class AuthClientFactory {
 public:
  static std::unique_ptr<AuthClient> CreateClientCredentialsClient(
      const std::string& auth_server_url,
      const std::string& client_id,
      const std::string& client_secret,
      const std::vector<std::string>& scopes = {},
      std::unique_ptr<coyote::infra::HttpClient> http_client = nullptr);
  
  static std::unique_ptr<AuthClient> CreateMtlsClient(
      const std::string& auth_server_url,
      const std::string& client_id,
      const std::string& client_cert_path,
      const std::string& client_key_path,
      const std::string& ca_cert_path,
      const std::vector<std::string>& scopes = {},
      std::unique_ptr<coyote::infra::HttpClient> http_client = nullptr);
  
  static std::unique_ptr<AuthClient> CreateJwtBearerClient(
      const std::string& auth_server_url,
      const std::string& client_id,
      const std::string& jwt_private_key_path,
      const std::vector<std::string>& scopes = {},
      std::unique_ptr<coyote::infra::HttpClient> http_client = nullptr);
  
  static std::unique_ptr<AuthClient> CreateAuthorizationCodeClient(
      const std::string& auth_server_url,
      const std::string& client_id,
      const std::string& redirect_uri,
      const std::vector<std::string>& scopes = {},
      bool use_pkce = true,
      std::unique_ptr<coyote::infra::HttpClient> http_client = nullptr);
};
};

} // namespace auth
} // namespace infra
} // namespace coyote
