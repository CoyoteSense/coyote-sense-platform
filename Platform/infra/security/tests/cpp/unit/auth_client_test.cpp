#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "oauth2_auth_client.h"
#include "../mocks/oauth2_test_mocks.h"
#include <thread>
#include <chrono>

using namespace coyote::infra::auth;
using namespace coyote::infra::auth::test;
using ::testing::_;
using ::testing::Return;
using ::testing::StrictMock;
using ::testing::InSequence;

class OAuth2AuthClientUnitTest : public OAuth2AuthClientTestBase {
protected:
    void SetUp() override {
        OAuth2AuthClientTestBase::SetUp();
        
        // Create client with mocked dependencies
        client_ = std::make_unique<OAuth2AuthClient>(
            config_, 
            mock_http_client_, 
            mock_token_storage_, 
            mock_logger_
        );
    }

protected:
    std::unique_ptr<OAuth2AuthClient> client_;
};

// Configuration Tests
TEST_F(OAuth2AuthClientUnitTest, ConstructorWithValidConfig) {
    EXPECT_NE(client_, nullptr);
    EXPECT_EQ(client_->GetConfig().auth_server_url, config_.auth_server_url);
    EXPECT_EQ(client_->GetConfig().client_id, config_.client_id);
}

TEST_F(OAuth2AuthClientUnitTest, ConstructorWithInvalidConfig) {
    OAuth2AuthClientConfig invalid_config;
    // Missing required fields should throw
    EXPECT_THROW(
        OAuth2AuthClient(invalid_config, mock_http_client_, mock_token_storage_, mock_logger_),
        std::invalid_argument
    );
}

// Client Credentials Flow Tests
TEST_F(OAuth2AuthClientUnitTest, ClientCredentialsFlow_Success) {
    // Arrange
    auto expected_response = CreateTokenResponse("access-token-123", "Bearer", 3600);
    
    EXPECT_CALL(*mock_http_client_, Post(_, _, _))
        .WillOnce(Return(testing::ByMove(std::move(expected_response))));
    
    EXPECT_CALL(*mock_token_storage_, StoreToken(_, _))
        .WillOnce(Return(true));

    // Act
    auto result = client_->ClientCredentials({"read", "write"});

    // Assert
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.token.access_token, "access-token-123");
    EXPECT_EQ(result.token.token_type, "Bearer");
    EXPECT_EQ(result.token.expires_in, 3600);
}

TEST_F(OAuth2AuthClientUnitTest, ClientCredentialsFlow_HttpError) {
    // Arrange
    auto error_response = CreateErrorResponse("invalid_client", "Authentication failed", 401);
    
    EXPECT_CALL(*mock_http_client_, Post(_, _, _))
        .WillOnce(Return(testing::ByMove(std::move(error_response))));

    // Act
    auto result = client_->ClientCredentials({"read", "write"});

    // Assert
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.error, "invalid_client");
    EXPECT_EQ(result.error_description, "Authentication failed");
}

TEST_F(OAuth2AuthClientUnitTest, ClientCredentialsFlow_NetworkError) {
    // Arrange
    EXPECT_CALL(*mock_http_client_, Post(_, _, _))
        .WillOnce(Return(nullptr)); // Simulate network error

    // Act
    auto result = client_->ClientCredentials({"read", "write"});

    // Assert
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.error.empty());
}

// JWT Bearer Flow Tests
TEST_F(OAuth2AuthClientUnitTest, JwtBearerFlow_Success) {
    // Arrange
    config_.jwt_private_key_path = "test-key.pem";
    config_.jwt_algorithm = "RS256";
    
    auto expected_response = CreateTokenResponse("jwt-access-token", "Bearer", 3600);
    
    EXPECT_CALL(*mock_http_client_, Post(_, _, _))
        .WillOnce(Return(testing::ByMove(std::move(expected_response))));
    
    EXPECT_CALL(*mock_token_storage_, StoreToken(_, _))
        .WillOnce(Return(true));

    // Act
    auto result = client_->JwtBearer("test-subject", {"read", "write"});

    // Assert
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.token.access_token, "jwt-access-token");
}

TEST_F(OAuth2AuthClientUnitTest, JwtBearerFlow_MissingKeyPath) {
    // Arrange - Don't set JWT key path
    
    // Act & Assert
    EXPECT_THROW(
        client_->JwtBearer("test-subject", {"read", "write"}),
        std::runtime_error
    );
}

// Authorization Code Flow Tests
TEST_F(OAuth2AuthClientUnitTest, AuthorizationCodeFlow_Success) {
    // Arrange
    auto expected_response = CreateTokenResponse("auth-code-token", "Bearer", 3600, "refresh-token-123");
    
    EXPECT_CALL(*mock_http_client_, Post(_, _, _))
        .WillOnce(Return(testing::ByMove(std::move(expected_response))));
    
    EXPECT_CALL(*mock_token_storage_, StoreToken(_, _))
        .WillOnce(Return(true));

    // Act
    auto result = client_->AuthorizationCode("test-auth-code", "test-verifier", {"read", "write"});

    // Assert
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.token.access_token, "auth-code-token");
    EXPECT_EQ(result.token.refresh_token, "refresh-token-123");
}

TEST_F(OAuth2AuthClientUnitTest, AuthorizationCodeFlow_InvalidCode) {
    // Arrange
    auto error_response = CreateErrorResponse("invalid_grant", "Authorization code is invalid", 400);
    
    EXPECT_CALL(*mock_http_client_, Post(_, _, _))
        .WillOnce(Return(testing::ByMove(std::move(error_response))));

    // Act
    auto result = client_->AuthorizationCode("invalid-code", "test-verifier", {"read", "write"});

    // Assert
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.error, "invalid_grant");
}

// Refresh Token Tests
TEST_F(OAuth2AuthClientUnitTest, RefreshToken_Success) {
    // Arrange
    auto expected_response = CreateTokenResponse("new-access-token", "Bearer", 3600, "new-refresh-token");
    
    EXPECT_CALL(*mock_http_client_, Post(_, _, _))
        .WillOnce(Return(testing::ByMove(std::move(expected_response))));
    
    EXPECT_CALL(*mock_token_storage_, StoreToken(_, _))
        .WillOnce(Return(true));

    // Act
    auto result = client_->RefreshToken("existing-refresh-token");

    // Assert
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.token.access_token, "new-access-token");
    EXPECT_EQ(result.token.refresh_token, "new-refresh-token");
}

TEST_F(OAuth2AuthClientUnitTest, RefreshToken_InvalidRefreshToken) {
    // Arrange
    auto error_response = CreateErrorResponse("invalid_grant", "Refresh token is invalid", 400);
    
    EXPECT_CALL(*mock_http_client_, Post(_, _, _))
        .WillOnce(Return(testing::ByMove(std::move(error_response))));

    // Act
    auto result = client_->RefreshToken("invalid-refresh-token");

    // Assert
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.error, "invalid_grant");
}

// Token Introspection Tests
TEST_F(OAuth2AuthClientUnitTest, IntrospectToken_ActiveToken) {
    // Arrange
    auto expected_response = CreateIntrospectionResponse(true, "read write", "test-client-id");
    
    EXPECT_CALL(*mock_http_client_, Post(_, _, _))
        .WillOnce(Return(testing::ByMove(std::move(expected_response))));

    // Act
    auto result = client_->IntrospectToken("test-access-token");

    // Assert
    EXPECT_TRUE(result.success);
    EXPECT_TRUE(result.active);
    EXPECT_EQ(result.scope, "read write");
    EXPECT_EQ(result.client_id, "test-client-id");
}

TEST_F(OAuth2AuthClientUnitTest, IntrospectToken_InactiveToken) {
    // Arrange
    auto expected_response = CreateIntrospectionResponse(false);
    
    EXPECT_CALL(*mock_http_client_, Post(_, _, _))
        .WillOnce(Return(testing::ByMove(std::move(expected_response))));

    // Act
    auto result = client_->IntrospectToken("inactive-token");

    // Assert
    EXPECT_TRUE(result.success);
    EXPECT_FALSE(result.active);
}

// Token Revocation Tests
TEST_F(OAuth2AuthClientUnitTest, RevokeToken_Success) {
    // Arrange
    auto expected_response = std::make_unique<MockHttpResponse>(200, "");
    
    EXPECT_CALL(*mock_http_client_, Post(_, _, _))
        .WillOnce(Return(testing::ByMove(std::move(expected_response))));
    
    EXPECT_CALL(*mock_token_storage_, DeleteToken(_))
        .WillOnce(Return(true));

    // Act
    auto result = client_->RevokeToken("test-access-token");

    // Assert
    EXPECT_TRUE(result.success);
}

TEST_F(OAuth2AuthClientUnitTest, RevokeToken_ServerError) {
    // Arrange
    auto error_response = std::make_unique<MockHttpResponse>(500, "Internal Server Error", false);
    
    EXPECT_CALL(*mock_http_client_, Post(_, _, _))
        .WillOnce(Return(testing::ByMove(std::move(error_response))));

    // Act
    auto result = client_->RevokeToken("test-access-token");

    // Assert
    EXPECT_FALSE(result.success);
}

// Token Storage Tests
TEST_F(OAuth2AuthClientUnitTest, StoreAndRetrieveToken) {
    // Arrange
    auto test_token = CreateTestToken("stored-token", "Bearer", 3600);
    
    EXPECT_CALL(*mock_token_storage_, StoreToken("test-key", _))
        .WillOnce(Return(true));
    
    EXPECT_CALL(*mock_token_storage_, GetToken("test-key"))
        .WillOnce(Return(test_token));

    // Act
    bool stored = client_->StoreToken("test-key", test_token);
    auto retrieved = client_->GetStoredToken("test-key");

    // Assert
    EXPECT_TRUE(stored);
    EXPECT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->access_token, "stored-token");
}

TEST_F(OAuth2AuthClientUnitTest, DeleteStoredToken) {
    // Arrange
    EXPECT_CALL(*mock_token_storage_, DeleteToken("test-key"))
        .WillOnce(Return(true));

    // Act
    bool deleted = client_->DeleteStoredToken("test-key");

    // Assert
    EXPECT_TRUE(deleted);
}

// Server Discovery Tests
TEST_F(OAuth2AuthClientUnitTest, DiscoverServer_Success) {
    // Arrange
    nlohmann::json discovery_response = {
        {"issuer", "https://test-auth.example.com"},
        {"authorization_endpoint", "https://test-auth.example.com/oauth2/authorize"},
        {"token_endpoint", "https://test-auth.example.com/oauth2/token"},
        {"introspection_endpoint", "https://test-auth.example.com/oauth2/introspect"},
        {"revocation_endpoint", "https://test-auth.example.com/oauth2/revoke"},
        {"grant_types_supported", {"client_credentials", "authorization_code", "refresh_token"}},
        {"token_endpoint_auth_methods_supported", {"client_secret_basic", "client_secret_post", "tls_client_auth"}}
    };
    
    auto expected_response = std::make_unique<MockHttpResponse>(200, discovery_response.dump());
    
    EXPECT_CALL(*mock_http_client_, Get(_, _))
        .WillOnce(Return(testing::ByMove(std::move(expected_response))));

    // Act
    auto result = client_->DiscoverServer();

    // Assert
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.server_info.issuer, "https://test-auth.example.com");
    EXPECT_EQ(result.server_info.token_endpoint, "https://test-auth.example.com/oauth2/token");
    EXPECT_TRUE(result.server_info.supports_client_credentials);
}

// Token Expiration Tests
TEST_F(OAuth2AuthClientUnitTest, IsTokenExpired_ExpiredToken) {
    // Arrange
    auto expired_token = CreateTestToken("expired-token", "Bearer", -3600); // Expired 1 hour ago
    
    // Act
    bool is_expired = client_->IsTokenExpired(expired_token);

    // Assert
    EXPECT_TRUE(is_expired);
}

TEST_F(OAuth2AuthClientUnitTest, IsTokenExpired_ValidToken) {
    // Arrange
    auto valid_token = CreateTestToken("valid-token", "Bearer", 3600); // Expires in 1 hour
    
    // Act
    bool is_expired = client_->IsTokenExpired(valid_token);

    // Assert
    EXPECT_FALSE(is_expired);
}

// Auto-Refresh Tests
class OAuth2AuthClientAutoRefreshTest : public OAuth2AuthClientTestBase {
protected:
    void SetUp() override {
        OAuth2AuthClientTestBase::SetUp();
        
        // Enable auto-refresh for these tests
        config_.auto_refresh = true;
        config_.token_refresh_buffer_seconds = 60; // Refresh 1 minute before expiry
        
        client_ = std::make_unique<OAuth2AuthClient>(
            config_, 
            mock_http_client_, 
            mock_token_storage_, 
            mock_logger_
        );
    }

protected:
    std::unique_ptr<OAuth2AuthClient> client_;
};

TEST_F(OAuth2AuthClientAutoRefreshTest, AutoRefresh_TriggersWhenNeeded) {
    // Arrange
    auto expiring_token = CreateTestToken("expiring-token", "Bearer", 30, "refresh-token"); // Expires in 30 seconds
    auto refreshed_token_response = CreateTokenResponse("refreshed-token", "Bearer", 3600, "new-refresh-token");
    
    EXPECT_CALL(*mock_token_storage_, GetToken(_))
        .WillOnce(Return(expiring_token));
    
    EXPECT_CALL(*mock_http_client_, Post(_, _, _))
        .WillOnce(Return(testing::ByMove(std::move(refreshed_token_response))));
    
    EXPECT_CALL(*mock_token_storage_, StoreToken(_, _))
        .WillOnce(Return(true));

    // Act
    client_->StartAutoRefresh("test-key");
    
    // Wait for auto-refresh to trigger (it should trigger immediately since token expires soon)
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    client_->StopAutoRefresh();

    // Assert - Verify refresh was called
    // (This is verified through the mock expectations above)
}

// Thread Safety Tests
TEST_F(OAuth2AuthClientUnitTest, ConcurrentTokenRequests) {
    // Arrange
    std::vector<std::future<OAuth2AuthResult>> futures;
    const int num_threads = 5;
    
    // Set up expectations for multiple calls
    EXPECT_CALL(*mock_http_client_, Post(_, _, _))
        .Times(num_threads)
        .WillRepeatedly([this]() {
            return CreateTokenResponse("concurrent-token-" + std::to_string(rand()));
        });
    
    EXPECT_CALL(*mock_token_storage_, StoreToken(_, _))
        .Times(num_threads)
        .WillRepeatedly(Return(true));

    // Act - Launch multiple concurrent requests
    for (int i = 0; i < num_threads; ++i) {
        futures.push_back(std::async(std::launch::async, [this]() {
            return client_->ClientCredentials({"read"});
        }));
    }

    // Wait for all requests to complete
    std::vector<OAuth2AuthResult> results;
    for (auto& future : futures) {
        results.push_back(future.get());
    }

    // Assert - All requests should succeed
    for (const auto& result : results) {
        EXPECT_TRUE(result.success);
    }
}

// Error Handling and Retry Tests
TEST_F(OAuth2AuthClientUnitTest, RetryOnNetworkFailure) {
    // Arrange
    config_.max_retry_attempts = 3;
    config_.retry_delay_ms = 10; // Short delay for testing
    
    InSequence seq;
    
    // First two attempts fail
    EXPECT_CALL(*mock_http_client_, Post(_, _, _))
        .WillOnce(Return(nullptr))
        .WillOnce(Return(nullptr))
        .WillOnce(Return(CreateTokenResponse("retry-success-token")));
    
    EXPECT_CALL(*mock_token_storage_, StoreToken(_, _))
        .WillOnce(Return(true));

    // Act
    auto result = client_->ClientCredentials({"read", "write"});

    // Assert
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.token.access_token, "retry-success-token");
}

TEST_F(OAuth2AuthClientUnitTest, MaxRetriesExceeded) {
    // Arrange
    config_.max_retry_attempts = 2;
    config_.retry_delay_ms = 10;
    
    // All attempts fail
    EXPECT_CALL(*mock_http_client_, Post(_, _, _))
        .Times(3) // Initial attempt + 2 retries
        .WillRepeatedly(Return(nullptr));

    // Act
    auto result = client_->ClientCredentials({"read", "write"});

    // Assert
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.error.empty());
}

// Logging Tests
TEST_F(OAuth2AuthClientUnitTest, LoggingIntegration) {
    // Arrange
    auto expected_response = CreateTokenResponse("logged-token");
    
    EXPECT_CALL(*mock_http_client_, Post(_, _, _))
        .WillOnce(Return(testing::ByMove(std::move(expected_response))));
    
    EXPECT_CALL(*mock_token_storage_, StoreToken(_, _))
        .WillOnce(Return(true));
    
    // Expect logging calls
    EXPECT_CALL(*mock_logger_, Info(_))
        .Times(testing::AtLeast(1));

    // Act
    auto result = client_->ClientCredentials({"read", "write"});

    // Assert
    EXPECT_TRUE(result.success);
    // Logging verification is done through mock expectations
}
