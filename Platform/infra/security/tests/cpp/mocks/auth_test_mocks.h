#pragma once

#include "oauth2_auth_client.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace coyote {
namespace infra {
namespace auth {
namespace test {

// Mock HTTP Client for OAuth2 testing
class MockHttpClient : public HttpClient {
public:
    MOCK_METHOD(std::unique_ptr<HttpResponse>, Get, 
        (const std::string& url, const std::unordered_map<std::string, std::string>& headers), (override));
    MOCK_METHOD(std::unique_ptr<HttpResponse>, Post, 
        (const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers), (override));
    MOCK_METHOD(std::unique_ptr<HttpResponse>, Put, 
        (const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers), (override));
    MOCK_METHOD(std::unique_ptr<HttpResponse>, Delete, 
        (const std::string& url, const std::unordered_map<std::string, std::string>& headers), (override));
    MOCK_METHOD(bool, Ping, (const std::string& url), (override));
    MOCK_METHOD(void, SetDefaultHeaders, (const std::unordered_map<std::string, std::string>& headers), (override));
    MOCK_METHOD(void, SetDefaultTimeout, (int timeout_ms), (override));
    MOCK_METHOD(void, SetVerifyPeer, (bool verify), (override));
};

// Mock HTTP Response for OAuth2 testing
class MockHttpResponse : public HttpResponse {
private:
    int status_code_;
    std::string body_;
    std::unordered_map<std::string, std::string> headers_;
    bool success_;

public:
    MockHttpResponse(int status_code, const std::string& body, bool success = true) 
        : status_code_(status_code), body_(body), success_(success) {}

    int GetStatusCode() const override { return status_code_; }
    std::string GetBody() const override { return body_; }
    std::unordered_map<std::string, std::string> GetHeaders() const override { return headers_; }
    bool IsSuccess() const override { return success_; }
    std::string GetErrorMessage() const override { return success_ ? "" : "Mock error"; }

    void SetHeaders(const std::unordered_map<std::string, std::string>& headers) {
        headers_ = headers;
    }
};

// Mock OAuth2 Token Storage
class MockOAuth2TokenStorage : public IOAuth2TokenStorage {
private:
    std::unordered_map<std::string, OAuth2Token> tokens_;

public:
    MOCK_METHOD(bool, StoreToken, (const std::string& key, const OAuth2Token& token), (override));
    MOCK_METHOD(std::optional<OAuth2Token>, GetToken, (const std::string& key), (override));
    MOCK_METHOD(bool, DeleteToken, (const std::string& key), (override));
    MOCK_METHOD(void, Clear, (), (override));

    // Helper methods for testing
    void SetToken(const std::string& key, const OAuth2Token& token) {
        tokens_[key] = token;
    }

    bool HasToken(const std::string& key) const {
        return tokens_.find(key) != tokens_.end();
    }
};

// Mock OAuth2 Logger
class MockOAuth2Logger : public IOAuth2Logger {
public:
    MOCK_METHOD(void, Debug, (const std::string& message), (override));
    MOCK_METHOD(void, Info, (const std::string& message), (override));
    MOCK_METHOD(void, Warning, (const std::string& message), (override));
    MOCK_METHOD(void, Error, (const std::string& message), (override));

    // Helper to capture logged messages
    std::vector<std::pair<std::string, std::string>> logged_messages; // level, message

    void CaptureLog(const std::string& level, const std::string& message) {
        logged_messages.push_back({level, message});
    }
};

// Test Fixtures and Utilities
class OAuth2AuthClientTestBase : public ::testing::Test {
protected:
    void SetUp() override {
        mock_http_client_ = std::make_shared<MockHttpClient>();
        mock_token_storage_ = std::make_shared<MockOAuth2TokenStorage>();
        mock_logger_ = std::make_shared<MockOAuth2Logger>();

        // Default configuration for testing
        config_.auth_server_url = "https://test-auth.example.com";
        config_.client_id = "test-client-id";
        config_.client_secret = "test-client-secret";
        config_.scopes = {"read", "write"};
        config_.auto_refresh = false; // Disable for most tests
        config_.timeout_ms = 5000;
    }

    void TearDown() override {
        // Clean up
    }

    // Helper methods for creating test responses
    std::unique_ptr<MockHttpResponse> CreateTokenResponse(
        const std::string& access_token = "test-access-token",
        const std::string& token_type = "Bearer",
        int expires_in = 3600,
        const std::string& refresh_token = "",
        const std::string& scope = "read write") {
        
        nlohmann::json response_json = {
            {"access_token", access_token},
            {"token_type", token_type},
            {"expires_in", expires_in}
        };

        if (!refresh_token.empty()) {
            response_json["refresh_token"] = refresh_token;
        }

        if (!scope.empty()) {
            response_json["scope"] = scope;
        }

        return std::make_unique<MockHttpResponse>(200, response_json.dump());
    }

    std::unique_ptr<MockHttpResponse> CreateErrorResponse(
        const std::string& error = "invalid_request",
        const std::string& error_description = "Test error",
        int status_code = 400) {
        
        nlohmann::json error_json = {
            {"error", error},
            {"error_description", error_description}
        };

        return std::make_unique<MockHttpResponse>(status_code, error_json.dump(), false);
    }

    std::unique_ptr<MockHttpResponse> CreateIntrospectionResponse(
        bool active = true,
        const std::string& scope = "read write",
        const std::string& client_id = "test-client-id",
        int exp = 0) {
        
        nlohmann::json response_json = {
            {"active", active}
        };

        if (active) {
            response_json["scope"] = scope;
            response_json["client_id"] = client_id;
            if (exp > 0) {
                response_json["exp"] = exp;
            }
        }

        return std::make_unique<MockHttpResponse>(200, response_json.dump());
    }

    OAuth2Token CreateTestToken(
        const std::string& access_token = "test-access-token",
        const std::string& token_type = "Bearer",
        int expires_in = 3600,
        const std::string& refresh_token = "",
        const std::string& scope = "read write") {
        
        OAuth2Token token;
        token.access_token = access_token;
        token.token_type = token_type;
        token.expires_in = expires_in;
        token.refresh_token = refresh_token;
        token.scope = scope;
        token.issued_at = std::chrono::system_clock::now();
        return token;
    }

protected:
    std::shared_ptr<MockHttpClient> mock_http_client_;
    std::shared_ptr<MockOAuth2TokenStorage> mock_token_storage_;
    std::shared_ptr<MockOAuth2Logger> mock_logger_;
    OAuth2AuthClientConfig config_;
};

// JWT Helper for testing JWT Bearer flow
class JWTTestHelper {
public:
    static std::string CreateTestJWT(
        const std::string& issuer = "test-issuer",
        const std::string& subject = "test-subject",
        const std::string& audience = "test-audience",
        int expires_in = 3600) {
        
        // This is a simplified JWT for testing - in real implementation,
        // this would use proper JWT library with RSA signing
        nlohmann::json header = {
            {"alg", "RS256"},
            {"typ", "JWT"}
        };

        auto now = std::chrono::system_clock::now();
        auto exp = now + std::chrono::seconds(expires_in);
        auto iat = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        auto exp_timestamp = std::chrono::duration_cast<std::chrono::seconds>(exp.time_since_epoch()).count();

        nlohmann::json payload = {
            {"iss", issuer},
            {"sub", subject},
            {"aud", audience},
            {"exp", exp_timestamp},
            {"iat", iat}
        };

        // Base64 encode (simplified for testing)
        std::string header_b64 = Base64UrlEncode(header.dump());
        std::string payload_b64 = Base64UrlEncode(payload.dump());
        std::string signature = "test-signature"; // In real implementation, this would be RSA signed

        return header_b64 + "." + payload_b64 + "." + signature;
    }

private:
    static std::string Base64UrlEncode(const std::string& input) {
        // Simplified base64url encoding for testing
        // In real implementation, use proper base64url encoder
        return "base64url_" + std::to_string(std::hash<std::string>{}(input));
    }
};

// PKCE Helper for testing Authorization Code flow
class PKCETestHelper {
public:
    struct PKCEChallenge {
        std::string code_verifier;
        std::string code_challenge;
        std::string code_challenge_method = "S256";
    };

    static PKCEChallenge GenerateTestChallenge() {
        PKCEChallenge challenge;
        challenge.code_verifier = "test-code-verifier-123456789";
        challenge.code_challenge = "test-code-challenge-hash";
        challenge.code_challenge_method = "S256";
        return challenge;
    }
};

} // namespace test
} // namespace auth
} // namespace infra
} // namespace coyote
