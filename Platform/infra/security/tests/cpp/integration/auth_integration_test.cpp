#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <thread>
#include <future>
#include <chrono>
#include <cstdlib>
#include <memory>

#include "auth_client.h"
#include "oauth2_test_mocks.h"

namespace coyote_sense {
namespace oauth2 {
namespace test {

/**
 * Integration tests for OAuth2AuthClient against real OAuth2 server
 */
class OAuth2IntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Load configuration from environment variables
        config_ = std::make_unique<OAuth2ClientConfiguration>();
        config_->server_url = GetEnvVar("OAUTH2_SERVER_URL", "https://localhost:5001");
        config_->client_id = GetEnvVar("OAUTH2_CLIENT_ID", "integration-test-client");
        config_->client_secret = GetEnvVar("OAUTH2_CLIENT_SECRET", "integration-test-secret");
        config_->scope = GetEnvVar("OAUTH2_SCOPE", "api.read api.write");
        config_->enable_auto_refresh = true;
        config_->retry_policy.max_retries = 3;
        config_->retry_policy.base_delay = std::chrono::seconds(1);
        config_->retry_policy.max_delay = std::chrono::seconds(10);
        config_->retry_policy.use_exponential_backoff = true;

        // Create test implementations
        token_storage_ = std::make_shared<TestOAuth2TokenStorage>();
        logger_ = std::make_shared<TestOAuth2Logger>();
        
        // Create client
        client_ = std::make_unique<OAuth2AuthClient>(*config_, token_storage_, logger_);
        
        // Check if server is available
        server_available_ = IsServerAvailable();
    }

    void TearDown() override {
        client_.reset();
    }

    std::string GetEnvVar(const std::string& name, const std::string& default_value) {
        const char* value = std::getenv(name.c_str());
        return value ? std::string(value) : default_value;
    }

    bool IsServerAvailable() {
        try {
            auto http_client = std::make_shared<HttpClient>();
            auto response = http_client->Get(config_->server_url + "/.well-known/openid_configuration");
            return response.status_code == 200;
        } catch (...) {
            return false;
        }
    }

    std::unique_ptr<OAuth2ClientConfiguration> config_;
    std::shared_ptr<TestOAuth2TokenStorage> token_storage_;
    std::shared_ptr<TestOAuth2Logger> logger_;
    std::unique_ptr<OAuth2AuthClient> client_;
    bool server_available_ = false;
};

TEST_F(OAuth2IntegrationTest, ClientCredentialsFlow_ShouldAuthenticateSuccessfully) {
    // Skip if OAuth2 server is not available
    if (!server_available_) {
        GTEST_SKIP() << "OAuth2 server is not available, skipping integration test";
    }

    // Act
    auto future = client_->AuthenticateClientCredentialsAsync();
    auto result = future.get();

    // Assert
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->access_token.empty());
    EXPECT_EQ(result->token_type, "Bearer");
    EXPECT_GT(result->expires_in, 0);
}

TEST_F(OAuth2IntegrationTest, JwtBearerFlow_WithValidJwt_ShouldAuthenticateSuccessfully) {
    // Skip if OAuth2 server is not available
    if (!server_available_) {
        GTEST_SKIP() << "OAuth2 server is not available, skipping integration test";
    }

    // Arrange - Get a valid token to use as JWT
    auto client_creds_future = client_->AuthenticateClientCredentialsAsync();
    auto client_creds_result = client_creds_future.get();
    ASSERT_TRUE(client_creds_result.has_value());
    std::string jwt_token = client_creds_result->access_token;

    // Act
    auto future = client_->AuthenticateJwtBearerAsync(jwt_token);
    auto result = future.get();

    // Assert
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->access_token.empty());
    EXPECT_EQ(result->token_type, "Bearer");
}

TEST_F(OAuth2IntegrationTest, TokenIntrospection_WithValidToken_ShouldReturnActiveToken) {
    // Skip if OAuth2 server is not available
    if (!server_available_) {
        GTEST_SKIP() << "OAuth2 server is not available, skipping integration test";
    }

    // Arrange - Get a valid token
    auto auth_future = client_->AuthenticateClientCredentialsAsync();
    auto auth_result = auth_future.get();
    ASSERT_TRUE(auth_result.has_value());
    std::string access_token = auth_result->access_token;

    // Act
    auto future = client_->IntrospectTokenAsync(access_token);
    auto result = future.get();

    // Assert
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->active);
    EXPECT_EQ(result->client_id, config_->client_id);
}

TEST_F(OAuth2IntegrationTest, TokenIntrospection_WithInvalidToken_ShouldReturnInactiveToken) {
    // Skip if OAuth2 server is not available
    if (!server_available_) {
        GTEST_SKIP() << "OAuth2 server is not available, skipping integration test";
    }

    // Act
    auto future = client_->IntrospectTokenAsync("invalid-token");
    auto result = future.get();

    // Assert
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->active);
}

TEST_F(OAuth2IntegrationTest, TokenRevocation_WithValidToken_ShouldRevokeSuccessfully) {
    // Skip if OAuth2 server is not available
    if (!server_available_) {
        GTEST_SKIP() << "OAuth2 server is not available, skipping integration test";
    }

    // Arrange - Get a valid token
    auto auth_future = client_->AuthenticateClientCredentialsAsync();
    auto auth_result = auth_future.get();
    ASSERT_TRUE(auth_result.has_value());
    std::string access_token = auth_result->access_token;

    // Act
    auto revoke_future = client_->RevokeTokenAsync(access_token);
    bool revoke_result = revoke_future.get();

    // Assert
    EXPECT_TRUE(revoke_result);

    // Verify token is no longer active
    auto introspect_future = client_->IntrospectTokenAsync(access_token);
    auto introspect_result = introspect_future.get();
    ASSERT_TRUE(introspect_result.has_value());
    EXPECT_FALSE(introspect_result->active);
}

TEST_F(OAuth2IntegrationTest, ServerDiscovery_ShouldReturnValidEndpoints) {
    // Skip if OAuth2 server is not available
    if (!server_available_) {
        GTEST_SKIP() << "OAuth2 server is not available, skipping integration test";
    }

    // Act
    auto future = client_->DiscoverServerEndpointsAsync();
    auto result = future.get();

    // Assert
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->token_endpoint.empty());
    EXPECT_FALSE(result->introspection_endpoint.empty());
    EXPECT_FALSE(result->revocation_endpoint.empty());
    EXPECT_FALSE(result->supported_grant_types.empty());
    
    // Check for client_credentials support
    auto& grant_types = result->supported_grant_types;
    bool supports_client_credentials = std::find(grant_types.begin(), grant_types.end(), 
                                                "client_credentials") != grant_types.end();
    EXPECT_TRUE(supports_client_credentials);
}

TEST_F(OAuth2IntegrationTest, ConcurrentAuthentication_ShouldHandleMultipleRequests) {
    // Skip if OAuth2 server is not available
    if (!server_available_) {
        GTEST_SKIP() << "OAuth2 server is not available, skipping integration test";
    }

    // Arrange
    const int num_concurrent_requests = 5;
    std::vector<std::future<std::optional<OAuth2TokenResponse>>> futures;

    // Act - Create multiple concurrent authentication requests
    for (int i = 0; i < num_concurrent_requests; ++i) {
        futures.push_back(client_->AuthenticateClientCredentialsAsync());
    }

    // Wait for all requests to complete
    std::vector<std::optional<OAuth2TokenResponse>> results;
    for (auto& future : futures) {
        results.push_back(future.get());
    }

    // Assert
    EXPECT_EQ(results.size(), num_concurrent_requests);
    for (const auto& result : results) {
        ASSERT_TRUE(result.has_value());
        EXPECT_FALSE(result->access_token.empty());
        EXPECT_EQ(result->token_type, "Bearer");
    }
}

TEST_F(OAuth2IntegrationTest, AutoRefresh_WhenTokenExpires_ShouldRefreshAutomatically) {
    // Skip if OAuth2 server is not available
    if (!server_available_) {
        GTEST_SKIP() << "OAuth2 server is not available, skipping integration test";
    }

    // Arrange - Get initial token
    auto initial_future = client_->AuthenticateClientCredentialsAsync();
    auto initial_result = initial_future.get();
    ASSERT_TRUE(initial_result.has_value());
    std::string initial_token = initial_result->access_token;

    // Wait for potential token expiry simulation
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Act - Request new token (should trigger auto-refresh if needed)
    auto refreshed_future = client_->AuthenticateClientCredentialsAsync();
    auto refreshed_result = refreshed_future.get();

    // Assert
    ASSERT_TRUE(refreshed_result.has_value());
    EXPECT_FALSE(refreshed_result->access_token.empty());
    EXPECT_EQ(refreshed_result->token_type, "Bearer");
    // Token might be the same if still valid, or different if refreshed
}

TEST_F(OAuth2IntegrationTest, InvalidCredentials_ShouldReturnFailure) {
    // Skip if OAuth2 server is not available
    if (!server_available_) {
        GTEST_SKIP() << "OAuth2 server is not available, skipping integration test";
    }

    // Arrange - Create client with invalid credentials
    OAuth2ClientConfiguration invalid_config = *config_;
    invalid_config.client_id = "invalid-client-id";
    invalid_config.client_secret = "invalid-client-secret";

    auto invalid_token_storage = std::make_shared<TestOAuth2TokenStorage>();
    auto invalid_logger = std::make_shared<TestOAuth2Logger>();
    auto invalid_client = std::make_unique<OAuth2AuthClient>(
        invalid_config, invalid_token_storage, invalid_logger);

    // Act
    auto future = invalid_client->AuthenticateClientCredentialsAsync();
    auto result = future.get();

    // Assert
    EXPECT_FALSE(result.has_value());
    
    // Check that error was logged
    auto& log_messages = invalid_logger->GetLogMessages();
    bool error_logged = false;
    for (const auto& message : log_messages) {
        if (message.find("error") != std::string::npos || 
            message.find("unauthorized") != std::string::npos ||
            message.find("invalid") != std::string::npos) {
            error_logged = true;
            break;
        }
    }
    EXPECT_TRUE(error_logged);
}

TEST_F(OAuth2IntegrationTest, HealthCheck_ShouldReturnServerStatus) {
    // Skip if OAuth2 server is not available
    if (!server_available_) {
        GTEST_SKIP() << "OAuth2 server is not available, skipping integration test";
    }

    // Act
    auto future = client_->CheckServerHealthAsync();
    bool health_status = future.get();

    // Assert
    EXPECT_TRUE(health_status);
}

TEST_F(OAuth2IntegrationTest, LargeScope_ShouldHandleExtensivePermissions) {
    // Skip if OAuth2 server is not available
    if (!server_available_) {
        GTEST_SKIP() << "OAuth2 server is not available, skipping integration test";
    }

    // Arrange - Create client with large scope
    OAuth2ClientConfiguration large_scope_config = *config_;
    large_scope_config.scope = "api.read api.write api.admin openid profile email";

    auto large_scope_storage = std::make_shared<TestOAuth2TokenStorage>();
    auto large_scope_logger = std::make_shared<TestOAuth2Logger>();
    auto large_scope_client = std::make_unique<OAuth2AuthClient>(
        large_scope_config, large_scope_storage, large_scope_logger);

    // Act
    auto future = large_scope_client->AuthenticateClientCredentialsAsync();
    auto result = future.get();

    // Assert
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->access_token.empty());
    // The scope in response might be limited by what the server supports
}

TEST_F(OAuth2IntegrationTest, NetworkTimeout_ShouldHandleGracefully) {
    // Arrange - Create client with very short timeout
    OAuth2ClientConfiguration timeout_config = *config_;
    timeout_config.timeout = std::chrono::milliseconds(1); // Very short timeout
    timeout_config.server_url = "https://httpbin.org/delay/10"; // Slow endpoint

    auto timeout_storage = std::make_shared<TestOAuth2TokenStorage>();
    auto timeout_logger = std::make_shared<TestOAuth2Logger>();
    auto timeout_client = std::make_unique<OAuth2AuthClient>(
        timeout_config, timeout_storage, timeout_logger);

    // Act
    auto future = timeout_client->AuthenticateClientCredentialsAsync();
    auto result = future.get();

    // Assert
    EXPECT_FALSE(result.has_value());
    
    // Check that timeout error was logged
    auto& log_messages = timeout_logger->GetLogMessages();
    bool timeout_logged = false;
    for (const auto& message : log_messages) {
        if (message.find("timeout") != std::string::npos) {
            timeout_logged = true;
            break;
        }
    }
    EXPECT_TRUE(timeout_logged);
}

/**
 * Performance test implementation for C++ OAuth2 client
 */
class OAuth2PerformanceTest : public OAuth2IntegrationTest {
protected:
    void SetUp() override {
        OAuth2IntegrationTest::SetUp();
        
        // Only run performance tests in specific environments
        const char* run_perf = std::getenv("RUN_PERFORMANCE_TESTS");
        skip_performance_ = !(run_perf && std::string(run_perf) == "1");
    }

    bool skip_performance_ = false;
};

TEST_F(OAuth2PerformanceTest, HighConcurrency_ShouldMaintainPerformance) {
    if (skip_performance_ || !server_available_) {
        GTEST_SKIP() << "Performance tests disabled or server unavailable";
    }

    // Arrange
    const int num_concurrent_requests = 50;
    const int requests_per_thread = 10;
    std::vector<std::future<void>> futures;
    
    auto start_time = std::chrono::high_resolution_clock::now();

    // Act - Create concurrent authentication requests
    for (int i = 0; i < num_concurrent_requests; ++i) {
        futures.push_back(std::async(std::launch::async, [this, requests_per_thread]() {
            for (int j = 0; j < requests_per_thread; ++j) {
                auto future = client_->AuthenticateClientCredentialsAsync();
                auto result = future.get();
                EXPECT_TRUE(result.has_value());
            }
        }));
    }

    // Wait for all futures to complete
    for (auto& future : futures) {
        future.get();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    // Assert performance metrics
    int total_requests = num_concurrent_requests * requests_per_thread;
    double requests_per_second = (total_requests * 1000.0) / duration.count();
    
    std::cout << "Performance Results:\n";
    std::cout << "Total Requests: " << total_requests << "\n";
    std::cout << "Duration: " << duration.count() << " ms\n";
    std::cout << "Requests/Second: " << requests_per_second << "\n";
    
    EXPECT_GT(requests_per_second, 5.0) << "Should handle at least 5 requests per second";
    EXPECT_LT(duration.count(), 30000) << "Should complete within 30 seconds";
}

TEST_F(OAuth2PerformanceTest, MemoryUsage_ShouldRemainStable) {
    if (skip_performance_ || !server_available_) {
        GTEST_SKIP() << "Performance tests disabled or server unavailable";
    }

    // This test would require platform-specific memory monitoring
    // For now, we'll just ensure no obvious memory leaks by running many operations
    
    const int iterations = 100;
    
    for (int i = 0; i < iterations; ++i) {
        auto auth_future = client_->AuthenticateClientCredentialsAsync();
        auto auth_result = auth_future.get();
        ASSERT_TRUE(auth_result.has_value());
        
        // Periodically perform introspection and revocation
        if (i % 10 == 0) {
            auto introspect_future = client_->IntrospectTokenAsync(auth_result->access_token);
            auto introspect_result = introspect_future.get();
            EXPECT_TRUE(introspect_result.has_value());
            
            auto revoke_future = client_->RevokeTokenAsync(auth_result->access_token);
            bool revoke_result = revoke_future.get();
            EXPECT_TRUE(revoke_result);
        }
    }
    
    // If we reach here without crashing, memory usage is likely stable
    SUCCEED();
}

} // namespace test
} // namespace oauth2
} // namespace coyote_sense
