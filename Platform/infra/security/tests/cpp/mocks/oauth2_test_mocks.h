#pragma once

#include <gmock/gmock.h>
#include <memory>
#include <vector>
#include <string>
#include <map>
#include <unordered_map>
#include <future>
#include <optional>
#include <chrono>

// Include the interfaces we're mocking
#include "../../src/cpp/interfaces/auth_interfaces.h"
#include "../../src/cpp/interfaces/auth_types.h"
#include "../../../http/src/cpp/interfaces/http_client.h"

namespace coyote_sense {
namespace oauth2 {
namespace test {

using coyote::infra::security::auth::TokenResponse;
using coyote::infra::security::auth::AuthResult;

/**
 * Mock implementation of Token Storage for testing
 */
class MockTokenStorage : public coyote::infra::security::auth::IAuthTokenStorage {
public:
    MOCK_METHOD(std::future<void>, store_token_async, (const std::string& client_id, const coyote::infra::security::auth::AuthToken& token), (override));
    MOCK_METHOD(std::optional<coyote::infra::security::auth::AuthToken>, get_token, (const std::string& client_id), (override));
    MOCK_METHOD(void, clear_token, (const std::string& client_id), (override));
    MOCK_METHOD(void, clear_all_tokens, (), (override));
};

/**
 * Mock implementation of Auth Logger for testing
 */
class MockAuthLogger : public coyote::infra::security::auth::IAuthLogger {
public:
    MOCK_METHOD(void, log_info, (const std::string& message), (override));
    MOCK_METHOD(void, log_error, (const std::string& message), (override));
};

/**
 * Mock implementation of HttpClient for testing
 */
class MockHttpClient : public coyote::infra::HttpClient {
public:
    MOCK_METHOD(std::unique_ptr<coyote::infra::HttpResponse>, Execute, (const coyote::infra::HttpRequest& request), (override));
    MOCK_METHOD(std::unique_ptr<coyote::infra::HttpResponse>, Get, (const std::string& url, const std::unordered_map<std::string, std::string>& headers), (override));
    MOCK_METHOD(std::unique_ptr<coyote::infra::HttpResponse>, Post, (const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers), (override));
    MOCK_METHOD(std::unique_ptr<coyote::infra::HttpResponse>, Put, (const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers), (override));
    MOCK_METHOD(std::unique_ptr<coyote::infra::HttpResponse>, Delete, (const std::string& url, const std::unordered_map<std::string, std::string>& headers), (override));
    MOCK_METHOD(void, SetDefaultTimeout, (long timeout_ms), (override));
    MOCK_METHOD(void, SetDefaultHeaders, (const std::unordered_map<std::string, std::string>& headers), (override));
    MOCK_METHOD(void, SetClientCertificate, (const std::string& cert_path, const std::string& key_path), (override));
    MOCK_METHOD(void, SetCACertificate, (const std::string& ca_path), (override));
    MOCK_METHOD(void, SetVerifyPeer, (bool verify), (override));
    MOCK_METHOD(bool, Ping, (const std::string& url), (override));
};

/**
 * Mock implementation of OAuth2SecretManager for testing
 */
class MockOAuth2SecretManager {
public:
    MOCK_METHOD(std::optional<std::string>, GetSecret, (const std::string& key), ());
    MOCK_METHOD(bool, StoreSecret, (const std::string& key, const std::string& value), ());
    MOCK_METHOD(bool, DeleteSecret, (const std::string& key), ());
    MOCK_METHOD(bool, HasSecret, (const std::string& key), ());
    MOCK_METHOD(void, ClearAllSecrets, (), ());
};

/**
 * Capturing logger implementation that captures log messages for testing
 */
class CapturingOAuth2Logger : public coyote::infra::security::auth::IAuthLogger {
public:
    void log_info(const std::string& message) override {
        captured_logs_.push_back("[INFO] " + message);
    }
    
    void log_error(const std::string& message) override {
        captured_logs_.push_back("[ERROR] " + message);
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
        config_.client_id = "test-client-id";
        config_.client_secret = "test-client-secret";
        config_.token_endpoint = "https://test-auth.example.com/token";
        config_.authorize_endpoint = "https://test-auth.example.com/authorize";
        config_.scope = "api.read api.write";
        config_.timeout = std::chrono::seconds(5);
        config_.max_retries = 3;
        
        // Create mocks
        mock_token_storage_ = std::make_shared<testing::StrictMock<MockTokenStorage>>();
        mock_logger_ = std::make_shared<testing::StrictMock<MockAuthLogger>>();
        mock_http_client_ = std::make_shared<testing::StrictMock<MockHttpClient>>();
        mock_secret_manager_ = std::make_shared<testing::StrictMock<MockOAuth2SecretManager>>();
    }

    void TearDown() override {
        // Clean up
    }

    // Helper methods for creating test responses
    std::unique_ptr<coyote::infra::HttpResponse> CreateTokenResponse(
        const std::string& access_token,
        const std::string& token_type = "Bearer",
        int expires_in = 3600,
        const std::string& refresh_token = "") {
        
        // Note: This would need a concrete implementation class for HttpResponse
        // For now this is a placeholder that would need to be implemented
        return nullptr;
    }

    std::unique_ptr<coyote::infra::HttpResponse> CreateErrorResponse(
        const std::string& error,
        const std::string& error_description = "",
        int status_code = 400) {
        
        // Note: This would need a concrete implementation class for HttpResponse
        // For now this is a placeholder that would need to be implemented
        return nullptr;
    }

protected:
    coyote::infra::security::auth::ClientConfig config_;
    std::shared_ptr<testing::StrictMock<MockTokenStorage>> mock_token_storage_;
    std::shared_ptr<testing::StrictMock<MockAuthLogger>> mock_logger_;
    std::shared_ptr<testing::StrictMock<MockHttpClient>> mock_http_client_;
    std::shared_ptr<testing::StrictMock<MockOAuth2SecretManager>> mock_secret_manager_;
};

} // namespace test
} // namespace oauth2
} // namespace coyote_sense
