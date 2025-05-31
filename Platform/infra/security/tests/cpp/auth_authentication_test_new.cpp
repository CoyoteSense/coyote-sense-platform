// filepath: c:\CoyoteSense\coyote-sense-platform\Platform\infra\security\tests\cpp\auth_authentication_test.cpp
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../../interfaces/cpp/auth_interfaces.h"
#include "../../factory/cpp/auth_config_builder.h"
#include <future>
#include <memory>

namespace coyote {
namespace infra {
namespace security {
namespace auth {
namespace tests {

// Mock Auth Client for testing
class MockAuthClient : public IAuthClient {
public:
    MOCK_METHOD(std::future<AuthTokenResponse>, RequestTokenAsync,
                (const AuthClientConfig& config, const std::vector<std::string>& scopes),
                (override));
    
    MOCK_METHOD(std::future<AuthTokenResponse>, RequestTokenWithJwtAsync,
                (const AuthClientConfig& config, const JwtBearerClaims& claims, 
                 const std::vector<std::string>& scopes),
                (override));
    
    MOCK_METHOD(std::string, BuildAuthorizationUrl,
                (const AuthClientConfig& config, const AuthCodeRequest& request),
                (override));
    
    MOCK_METHOD(std::future<AuthTokenResponse>, ExchangeCodeForTokenAsync,
                (const AuthClientConfig& config, const std::string& code,
                 const std::string& redirect_uri, const std::optional<std::string>& code_verifier),
                (override));
    
    MOCK_METHOD(std::future<AuthTokenResponse>, RefreshTokenAsync,
                (const AuthClientConfig& config, const std::string& refresh_token),
                (override));
    
    MOCK_METHOD(std::future<bool>, ValidateTokenAsync,
                (const std::string& token, const AuthClientConfig& config),
                (override));
    
    MOCK_METHOD(std::future<bool>, RevokeTokenAsync,
                (const std::string& token, const AuthClientConfig& config),
                (override));
};

// Mock Token Manager for testing
class MockAuthTokenManager : public IAuthTokenManager {
public:
    MOCK_METHOD(std::future<std::string>, GetValidTokenAsync, (const std::string& client_id), (override));
    MOCK_METHOD(void, StoreToken, (const std::string& client_id, const AuthTokenResponse& token), (override));
    MOCK_METHOD(void, RemoveToken, (const std::string& client_id), (override));
    MOCK_METHOD(bool, HasValidToken, (const std::string& client_id), (override));
    MOCK_METHOD(std::future<std::string>, ForceRefreshAsync, (const std::string& client_id), (override));
};

// Test Auth Configuration Builder
class AuthConfigBuilderTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(AuthConfigBuilderTest, BuildClientCredentialsConfig) {
    auto config = AuthConfigBuilder::BuildClientCredentialsConfig(
        "test-client",
        "test-secret",
        "https://auth.example.com",
        "test.scope"
    );
    
    EXPECT_EQ(config.client_id, "test-client");
    EXPECT_EQ(config.client_secret.value(), "test-secret");
    EXPECT_EQ(config.token_endpoint, "https://auth.example.com/token");
    EXPECT_EQ(config.authorize_endpoint, "https://auth.example.com/authorize");
    EXPECT_EQ(config.scope.value(), "test.scope");
    EXPECT_TRUE(config.auto_refresh);
    EXPECT_EQ(config.token_refresh_buffer, std::chrono::seconds(60));
}

TEST_F(AuthConfigBuilderTest, BuildMTLSConfig) {
    auto config = AuthConfigBuilder::BuildMTLSConfig(
        "test-client",
        "https://auth.example.com",
        "/path/to/cert.crt",
        "/path/to/key.key",
        "test.scope"
    );
    
    EXPECT_EQ(config.client_id, "test-client");
    EXPECT_FALSE(config.client_secret.has_value());
    EXPECT_EQ(config.client_cert_path.value(), "/path/to/cert.crt");
    EXPECT_EQ(config.client_key_path.value(), "/path/to/key.key");
    EXPECT_EQ(config.scope.value(), "test.scope");
}

TEST_F(AuthConfigBuilderTest, BuildJWTBearerConfig) {
    auto config = AuthConfigBuilder::BuildJWTBearerConfig(
        "test-client",
        "https://auth.example.com",
        "/path/to/private.key",
        "key-001",
        "test.scope"
    );
    
    EXPECT_EQ(config.client_id, "test-client");
    EXPECT_FALSE(config.client_secret.has_value());
    EXPECT_EQ(config.private_key_path.value(), "/path/to/private.key");
    EXPECT_EQ(config.key_id.value(), "key-001");
    EXPECT_EQ(config.scope.value(), "test.scope");
}

// Test Auth Token Response
class AuthTokenResponseTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(AuthTokenResponseTest, TokenExpirationCheck) {
    AuthTokenResponse token;
    token.access_token = "test-token";
    token.expires_in = std::chrono::seconds(3600);
    token.issued_at = std::chrono::system_clock::now();
    token.expires_at = token.issued_at + token.expires_in;
    
    EXPECT_FALSE(token.is_expired());
    EXPECT_FALSE(token.needs_refresh(std::chrono::seconds(60)));
    
    // Simulate token nearing expiration
    token.expires_at = std::chrono::system_clock::now() + std::chrono::seconds(30);
    EXPECT_TRUE(token.needs_refresh(std::chrono::seconds(60)));
}

TEST_F(AuthTokenResponseTest, ExpiredToken) {
    AuthTokenResponse token;
    token.access_token = "expired-token";
    token.expires_in = std::chrono::seconds(3600);
    token.issued_at = std::chrono::system_clock::now() - std::chrono::hours(2);
    token.expires_at = token.issued_at + token.expires_in;
    
    EXPECT_TRUE(token.is_expired());
    EXPECT_TRUE(token.needs_refresh());
}

// Test Unit Authentication Service
class UnitAuthServiceTest : public ::testing::Test {
protected:
    void SetUp() override {
        mock_auth_client_ = std::make_shared<MockAuthClient>();
        mock_token_manager_ = std::make_shared<MockAuthTokenManager>();
    }
    
    void TearDown() override {}
    
    std::shared_ptr<MockAuthClient> mock_auth_client_;
    std::shared_ptr<MockAuthTokenManager> mock_token_manager_;
};

TEST_F(UnitAuthServiceTest, InitializeWithClientCredentials) {
    // Arrange
    AuthTokenResponse expected_token;
    expected_token.access_token = "test-access-token";
    expected_token.expires_in = std::chrono::seconds(3600);
    expected_token.issued_at = std::chrono::system_clock::now();
    expected_token.expires_at = expected_token.issued_at + expected_token.expires_in;
    
    auto config = AuthConfigBuilder::BuildClientCredentialsConfig(
        "test-unit",
        "test-secret",
        "https://auth.example.com",
        "test.scope"
    );
    
    // Set up expectations
    EXPECT_CALL(*mock_auth_client_, RequestTokenAsync(testing::_, testing::_))
        .WillOnce(testing::Return(std::async(std::launch::deferred, [=]() { return expected_token; })));
    
    EXPECT_CALL(*mock_token_manager_, StoreToken(config.client_id, testing::_))
        .Times(1);
    
    // Act
    auto auth_service = std::make_unique<UnitAuthService>(
        mock_auth_client_, mock_token_manager_, "test-unit"
    );
    
    auto result = auth_service->InitializeAsync(config).get();
    
    // Assert
    EXPECT_TRUE(result);
    EXPECT_TRUE(auth_service->IsAuthenticated());
}

TEST_F(UnitAuthServiceTest, GetAccessToken) {
    // Arrange
    auto config = AuthConfigBuilder::BuildClientCredentialsConfig(
        "test-unit", "test-secret", "https://auth.example.com", "test.scope"
    );
    
    EXPECT_CALL(*mock_token_manager_, GetValidTokenAsync("test-unit"))
        .WillOnce(testing::Return(std::async(std::launch::deferred, []() { return std::string("valid-token"); })));
    
    EXPECT_CALL(*mock_token_manager_, HasValidToken("test-unit"))
        .WillReturn(true);
    
    // Create auth service and initialize
    auto auth_service = std::make_unique<UnitAuthService>(
        mock_auth_client_, mock_token_manager_, "test-unit"
    );
    
    // Mock successful initialization
    AuthTokenResponse init_token;
    init_token.access_token = "init-token";
    init_token.expires_in = std::chrono::seconds(3600);
    
    EXPECT_CALL(*mock_auth_client_, RequestTokenAsync(testing::_, testing::_))
        .WillOnce(testing::Return(std::async(std::launch::deferred, [=]() { return init_token; })));
    
    EXPECT_CALL(*mock_token_manager_, StoreToken(testing::_, testing::_))
        .Times(1);
    
    auth_service->InitializeAsync(config).get();
    
    // Act
    auto token = auth_service->GetAccessTokenAsync().get();
    
    // Assert
    EXPECT_EQ(token, "valid-token");
}

TEST_F(UnitAuthServiceTest, RefreshCredentials) {
    // Arrange
    auto config = AuthConfigBuilder::BuildClientCredentialsConfig(
        "test-unit", "test-secret", "https://auth.example.com", "test.scope"
    );
    
    EXPECT_CALL(*mock_token_manager_, ForceRefreshAsync("test-unit"))
        .WillOnce(testing::Return(std::async(std::launch::deferred, []() { return std::string("refreshed-token"); })));
    
    // Create and initialize auth service
    auto auth_service = std::make_unique<UnitAuthService>(
        mock_auth_client_, mock_token_manager_, "test-unit"
    );
    
    AuthTokenResponse init_token;
    init_token.access_token = "init-token";
    init_token.expires_in = std::chrono::seconds(3600);
    
    EXPECT_CALL(*mock_auth_client_, RequestTokenAsync(testing::_, testing::_))
        .WillOnce(testing::Return(std::async(std::launch::deferred, [=]() { return init_token; })));
    
    EXPECT_CALL(*mock_token_manager_, StoreToken(testing::_, testing::_))
        .Times(1);
    
    auth_service->InitializeAsync(config).get();
    
    // Act
    auth_service->RefreshCredentialsAsync().get();
    
    // Assert - no exception thrown means success
    EXPECT_TRUE(auth_service->IsAuthenticated());
}

} // namespace tests
} // namespace auth
} // namespace security
} // namespace infra
} // namespace coyote
