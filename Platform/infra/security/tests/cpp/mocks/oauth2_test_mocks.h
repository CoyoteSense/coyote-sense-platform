#pragma once

#include <gmock/gmock.h>
#include <memory>
#include <vector>
#include <string>
#include <map>

// Include the interfaces we're mocking
#include "../../src/cpp/interfaces/oauth2_interfaces.h"
#include "../../src/cpp/interfaces/oauth2_types.h"

namespace coyote_sense {
namespace oauth2 {
namespace test {

/**
 * Mock implementation of OAuth2TokenStorage for testing
 */
class MockOAuth2TokenStorage : public OAuth2TokenStorage {
public:
    MOCK_METHOD(bool, StoreToken, (const std::string& client_id, const OAuth2TokenResponse& token), (override));
    MOCK_METHOD(std::optional<OAuth2TokenResponse>, GetToken, (const std::string& client_id), (override));
    MOCK_METHOD(bool, DeleteToken, (const std::string& client_id), (override));
    MOCK_METHOD(bool, HasToken, (const std::string& client_id), (override));
    MOCK_METHOD(void, ClearAllTokens, (), (override));
};

/**
 * Mock implementation of OAuth2Logger for testing
 */
class MockOAuth2Logger : public OAuth2Logger {
public:
    MOCK_METHOD(void, LogInfo, (const std::string& message), (override));
    MOCK_METHOD(void, LogWarning, (const std::string& message), (override));
    MOCK_METHOD(void, LogError, (const std::string& message), (override));
    MOCK_METHOD(void, LogDebug, (const std::string& message), (override));
};

/**
 * Mock implementation of HttpClient for testing
 */
class MockHttpClient : public HttpClient {
public:
    MOCK_METHOD(std::unique_ptr<HttpResponse>, Get, (const std::string& url, const std::map<std::string, std::string>& headers), (override));
    MOCK_METHOD(std::unique_ptr<HttpResponse>, Post, (const std::string& url, const std::string& body, const std::map<std::string, std::string>& headers), (override));
    MOCK_METHOD(std::unique_ptr<HttpResponse>, Put, (const std::string& url, const std::string& body, const std::map<std::string, std::string>& headers), (override));
    MOCK_METHOD(std::unique_ptr<HttpResponse>, Delete, (const std::string& url, const std::map<std::string, std::string>& headers), (override));
    MOCK_METHOD(void, SetTimeout, (int timeout_ms), (override));
    MOCK_METHOD(void, SetUserAgent, (const std::string& user_agent), (override));
    MOCK_METHOD(bool, SetCertificatePath, (const std::string& cert_path), (override));
    MOCK_METHOD(bool, SetPrivateKeyPath, (const std::string& key_path), (override));
    MOCK_METHOD(void, SetVerifySSL, (bool verify), (override));
};

/**
 * Mock implementation of OAuth2SecretManager for testing
 */
class MockOAuth2SecretManager : public OAuth2SecretManager {
public:
    MOCK_METHOD(std::optional<std::string>, GetSecret, (const std::string& key), (override));
    MOCK_METHOD(bool, StoreSecret, (const std::string& key, const std::string& value), (override));
    MOCK_METHOD(bool, DeleteSecret, (const std::string& key), (override));
    MOCK_METHOD(bool, HasSecret, (const std::string& key), (override));
    MOCK_METHOD(void, ClearAllSecrets, (), (override));
};

/**
 * Capturing logger implementation that captures log messages for testing
 */
class CapturingOAuth2Logger : public OAuth2Logger {
public:
    void LogInfo(const std::string& message) override {
        captured_logs_.push_back("[INFO] " + message);
    }
    
    void LogWarning(const std::string& message) override {
        captured_logs_.push_back("[WARN] " + message);
    }
    
    void LogError(const std::string& message) override {
        captured_logs_.push_back("[ERROR] " + message);
    }
    
    void LogDebug(const std::string& message) override {
        captured_logs_.push_back("[DEBUG] " + message);
    }
    
    const std::vector<std::string>& GetCapturedLogs() const {
        return captured_logs_;
    }
    
    void ClearLogs() {
        captured_logs_.clear();
    }

private:
    std::vector<std::string> captured_logs_;
};

/**
 * Test base class for OAuth2AuthClient tests
 */
class OAuth2AuthClientTestBase : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup default configuration
        config_.server_url = "https://test-auth.example.com";
        config_.client_id = "test-client-id";
        config_.client_secret = "test-client-secret";
        config_.default_scope = "api.read api.write";
        config_.timeout_ms = 5000;
        config_.retry_policy.max_retries = 3;
        config_.retry_policy.base_delay = std::chrono::milliseconds(100);
        config_.retry_policy.max_delay = std::chrono::seconds(10);
        config_.retry_policy.use_exponential_backoff = true;
        
        // Create mocks
        mock_token_storage_ = std::make_shared<testing::StrictMock<MockOAuth2TokenStorage>>();
        mock_logger_ = std::make_shared<testing::StrictMock<MockOAuth2Logger>>();
        mock_http_client_ = std::make_shared<testing::StrictMock<MockHttpClient>>();
        mock_secret_manager_ = std::make_shared<testing::StrictMock<MockOAuth2SecretManager>>();
    }

    void TearDown() override {
        // Clean up
    }

    // Helper methods for creating test responses
    std::unique_ptr<HttpClient::HttpResponse> CreateTokenResponse(
        const std::string& access_token,
        const std::string& token_type = "Bearer",
        int expires_in = 3600,
        const std::string& refresh_token = "") {
        
        auto response = std::make_unique<HttpClient::HttpResponse>();
        response->status_code = 200;
        
        std::string json = R"({
            "access_token": ")" + access_token + R"(",
            "token_type": ")" + token_type + R"(",
            "expires_in": )" + std::to_string(expires_in);
        
        if (!refresh_token.empty()) {
            json += R"(,
            "refresh_token": ")" + refresh_token + R"(")";
        }
        
        json += "}";
        response->body = json;
        response->headers["Content-Type"] = "application/json";
        
        return response;
    }

    std::unique_ptr<HttpClient::HttpResponse> CreateErrorResponse(
        const std::string& error,
        const std::string& error_description = "",
        int status_code = 400) {
        
        auto response = std::make_unique<HttpClient::HttpResponse>();
        response->status_code = status_code;
        
        std::string json = R"({
            "error": ")" + error + R"(")";
        
        if (!error_description.empty()) {
            json += R"(,
            "error_description": ")" + error_description + R"(")";
        }
        
        json += "}";
        response->body = json;
        response->headers["Content-Type"] = "application/json";
        
        return response;
    }

protected:
    OAuth2ClientConfiguration config_;
    std::shared_ptr<testing::StrictMock<MockOAuth2TokenStorage>> mock_token_storage_;
    std::shared_ptr<testing::StrictMock<MockOAuth2Logger>> mock_logger_;
    std::shared_ptr<testing::StrictMock<MockHttpClient>> mock_http_client_;
    std::shared_ptr<testing::StrictMock<MockOAuth2SecretManager>> mock_secret_manager_;
};

} // namespace test
} // namespace oauth2
} // namespace coyote_sense
