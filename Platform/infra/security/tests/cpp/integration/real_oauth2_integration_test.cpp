#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <thread>
#include <future>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <string>
#include <iostream>
#include <fstream>

// Include HTTP client for server connectivity tests
#include <curl/curl.h>
#include <nlohmann/json.hpp>

namespace coyote {
namespace infra {
namespace security {
namespace integration {

// Simple HTTP client for testing OAuth2 server connectivity
class SimpleHttpClient {
public:
    struct HttpResponse {
        int status_code;
        std::string body;
        std::string headers;
    };

    SimpleHttpClient() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl_ = curl_easy_init();
    }

    ~SimpleHttpClient() {
        if (curl_) {
            curl_easy_cleanup(curl_);
        }
        curl_global_cleanup();
    }

    HttpResponse Get(const std::string& url) {
        HttpResponse response;
        response.status_code = 0;

        if (!curl_) {
            return response;
        }

        // Set URL
        curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());

        // Set callback for response data
        curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response.body);

        // Set callback for headers
        curl_easy_setopt(curl_, CURLOPT_HEADERFUNCTION, HeaderCallback);
        curl_easy_setopt(curl_, CURLOPT_HEADERDATA, &response.headers);

        // Set timeout
        curl_easy_setopt(curl_, CURLOPT_TIMEOUT, 10L);

        // Perform the request
        CURLcode res = curl_easy_perform(curl_);

        if (res == CURLE_OK) {
            long response_code;
            curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &response_code);
            response.status_code = static_cast<int>(response_code);
        }

        return response;
    }

    HttpResponse Post(const std::string& url, const std::string& post_data, const std::string& content_type = "application/x-www-form-urlencoded") {
        HttpResponse response;
        response.status_code = 0;

        if (!curl_) {
            return response;
        }

        // Set URL
        curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());

        // Set POST data
        curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, post_data.c_str());

        // Set content type
        struct curl_slist* headers = nullptr;
        std::string content_type_header = "Content-Type: " + content_type;
        headers = curl_slist_append(headers, content_type_header.c_str());
        curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers);

        // Set callbacks
        curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response.body);

        curl_easy_setopt(curl_, CURLOPT_HEADERFUNCTION, HeaderCallback);
        curl_easy_setopt(curl_, CURLOPT_HEADERDATA, &response.headers);

        // Set timeout
        curl_easy_setopt(curl_, CURLOPT_TIMEOUT, 10L);

        // Perform the request
        CURLcode res = curl_easy_perform(curl_);

        if (res == CURLE_OK) {
            long response_code;
            curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &response_code);
            response.status_code = static_cast<int>(response_code);
        }

        // Clean up headers
        curl_slist_free_all(headers);

        return response;
    }

private:
    CURL* curl_;

    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        size_t realsize = size * nmemb;
        std::string* response = static_cast<std::string*>(userp);
        response->append(static_cast<char*>(contents), realsize);
        return realsize;
    }

    static size_t HeaderCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        size_t realsize = size * nmemb;
        std::string* headers = static_cast<std::string*>(userp);
        headers->append(static_cast<char*>(contents), realsize);
        return realsize;
    }
};

/**
 * Real OAuth2 Integration Tests using Docker OAuth2 Server
 */
class RealOAuth2IntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Use the same OAuth2 server configuration as the C# tests
        server_url_ = GetEnvVar("OAUTH2_SERVER_URL", "http://localhost:8081");
        client_id_ = GetEnvVar("OAUTH2_CLIENT_ID", "test-client-id");
        client_secret_ = GetEnvVar("OAUTH2_CLIENT_SECRET", "test-client-secret");
        scope_ = GetEnvVar("OAUTH2_SCOPE", "api.read api.write");

        http_client_ = std::make_unique<SimpleHttpClient>();
        
        // Check if server is available
        server_available_ = IsServerAvailable();
        
        if (!server_available_) {
            std::cout << "OAuth2 server is not available at " << server_url_ << std::endl;
            std::cout << "Please start the OAuth2 server using: docker-compose -f docker-compose.oauth2.yml up" << std::endl;
        }
    }

    void TearDown() override {
        http_client_.reset();
    }

    std::string GetEnvVar(const std::string& name, const std::string& default_value) {
        const char* value = std::getenv(name.c_str());
        return value ? std::string(value) : default_value;
    }

    bool IsServerAvailable() {
        try {
            auto response = http_client_->Get(server_url_ + "/.well-known/oauth2");
            return response.status_code == 200;
        } catch (...) {
            return false;
        }
    }

    std::string UrlEncode(const std::string& value) {
        std::ostringstream escaped;
        escaped.fill('0');
        escaped << std::hex;

        for (char c : value) {
            if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                escaped << c;
            } else {
                escaped << std::uppercase;
                escaped << '%' << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
                escaped << std::nouppercase;
            }
        }

        return escaped.str();
    }

    std::string server_url_;
    std::string client_id_;
    std::string client_secret_;
    std::string scope_;
    std::unique_ptr<SimpleHttpClient> http_client_;
    bool server_available_ = false;
};

TEST_F(RealOAuth2IntegrationTest, ServerConnection_ShouldBeReachable) {
    // Test that we can reach the OAuth2 server
    auto response = http_client_->Get(server_url_ + "/.well-known/oauth2");
    
    EXPECT_GT(response.status_code, 0) << "Failed to connect to OAuth2 server";
    
    if (response.status_code == 200) {
        std::cout << "✓ OAuth2 server is reachable at " << server_url_ << std::endl;
        std::cout << "✓ Discovery endpoint response: " << response.body.substr(0, 200) << "..." << std::endl;
    } else {
        std::cout << "✗ OAuth2 server returned status: " << response.status_code << std::endl;
        std::cout << "✗ Response body: " << response.body << std::endl;
    }
}

TEST_F(RealOAuth2IntegrationTest, ClientCredentialsFlow_ShouldAuthenticateSuccessfully) {
    // Skip if OAuth2 server is not available
    if (!server_available_) {
        GTEST_SKIP() << "OAuth2 server is not available, skipping integration test";
    }

    // Prepare client credentials grant request
    std::string post_data = "grant_type=client_credentials";
    post_data += "&client_id=" + UrlEncode(client_id_);
    post_data += "&client_secret=" + UrlEncode(client_secret_);
    post_data += "&scope=" + UrlEncode(scope_);

    // Make the token request
    auto response = http_client_->Post(server_url_ + "/token", post_data);

    // Assert response
    ASSERT_EQ(response.status_code, 200) << "Token request failed. Response: " << response.body;

    // Parse JSON response
    nlohmann::json token_response;
    try {
        token_response = nlohmann::json::parse(response.body);
    } catch (const std::exception& e) {
        FAIL() << "Failed to parse token response JSON: " << e.what() << ". Response: " << response.body;
    }

    // Verify token response structure
    ASSERT_TRUE(token_response.contains("access_token")) << "Missing access_token in response";
    ASSERT_TRUE(token_response.contains("token_type")) << "Missing token_type in response";
    ASSERT_TRUE(token_response.contains("expires_in")) << "Missing expires_in in response";

    // Verify token values
    EXPECT_FALSE(token_response["access_token"].get<std::string>().empty()) << "access_token should not be empty";
    EXPECT_EQ(token_response["token_type"].get<std::string>(), "Bearer") << "token_type should be Bearer";
    EXPECT_GT(token_response["expires_in"].get<int>(), 0) << "expires_in should be positive";

    std::cout << "✓ Client credentials flow successful" << std::endl;
    std::cout << "✓ Access token received (length: " << token_response["access_token"].get<std::string>().length() << ")" << std::endl;
    std::cout << "✓ Token type: " << token_response["token_type"].get<std::string>() << std::endl;
    std::cout << "✓ Expires in: " << token_response["expires_in"].get<int>() << " seconds" << std::endl;
}

TEST_F(RealOAuth2IntegrationTest, TokenIntrospection_WithValidToken_ShouldReturnActive) {
    // Skip if OAuth2 server is not available
    if (!server_available_) {
        GTEST_SKIP() << "OAuth2 server is not available, skipping integration test";
    }

    // First, get a valid token
    std::string post_data = "grant_type=client_credentials";
    post_data += "&client_id=" + UrlEncode(client_id_);
    post_data += "&client_secret=" + UrlEncode(client_secret_);
    post_data += "&scope=" + UrlEncode(scope_);

    auto token_response = http_client_->Post(server_url_ + "/token", post_data);
    ASSERT_EQ(token_response.status_code, 200) << "Failed to get token for introspection test";

    nlohmann::json token_json = nlohmann::json::parse(token_response.body);
    std::string access_token = token_json["access_token"].get<std::string>();

    // Now introspect the token
    std::string introspect_data = "token=" + UrlEncode(access_token);
    introspect_data += "&client_id=" + UrlEncode(client_id_);
    introspect_data += "&client_secret=" + UrlEncode(client_secret_);

    auto introspect_response = http_client_->Post(server_url_ + "/introspect", introspect_data);

    // Assert introspection response
    ASSERT_EQ(introspect_response.status_code, 200) << "Token introspection failed. Response: " << introspect_response.body;

    // Parse introspection response
    nlohmann::json introspect_json;
    try {
        introspect_json = nlohmann::json::parse(introspect_response.body);
    } catch (const std::exception& e) {
        FAIL() << "Failed to parse introspection response JSON: " << e.what() << ". Response: " << introspect_response.body;
    }

    // Verify introspection response
    ASSERT_TRUE(introspect_json.contains("active")) << "Missing active field in introspection response";
    EXPECT_TRUE(introspect_json["active"].get<bool>()) << "Token should be active";

    std::cout << "✓ Token introspection successful" << std::endl;
    std::cout << "✓ Token is active: " << introspect_json["active"].get<bool>() << std::endl;
}

TEST_F(RealOAuth2IntegrationTest, InvalidClientCredentials_ShouldReturnError) {
    // Skip if OAuth2 server is not available
    if (!server_available_) {
        GTEST_SKIP() << "OAuth2 server is not available, skipping integration test";
    }

    // Prepare client credentials grant request with invalid credentials
    std::string post_data = "grant_type=client_credentials";
    post_data += "&client_id=" + UrlEncode("invalid-client");
    post_data += "&client_secret=" + UrlEncode("invalid-secret");
    post_data += "&scope=" + UrlEncode(scope_);

    // Make the token request
    auto response = http_client_->Post(server_url_ + "/token", post_data);

    // Assert error response
    EXPECT_EQ(response.status_code, 401) << "Invalid credentials should return 401. Response: " << response.body;

    // Parse JSON response
    nlohmann::json error_response;
    try {
        error_response = nlohmann::json::parse(response.body);
    } catch (const std::exception& e) {
        FAIL() << "Failed to parse error response JSON: " << e.what() << ". Response: " << response.body;
    }

    // Verify error response structure
    ASSERT_TRUE(error_response.contains("error")) << "Missing error field in response";
    EXPECT_EQ(error_response["error"].get<std::string>(), "invalid_client") << "Expected invalid_client error";

    std::cout << "✓ Invalid credentials properly rejected" << std::endl;
    std::cout << "✓ Error response: " << error_response["error"].get<std::string>() << std::endl;
}

TEST_F(RealOAuth2IntegrationTest, DiscoveryEndpoint_ShouldReturnValidConfiguration) {
    // Skip if OAuth2 server is not available
    if (!server_available_) {
        GTEST_SKIP() << "OAuth2 server is not available, skipping integration test";
    }

    // Make discovery request
    auto response = http_client_->Get(server_url_ + "/.well-known/oauth2");

    // Assert discovery response
    ASSERT_EQ(response.status_code, 200) << "Discovery endpoint failed. Response: " << response.body;

    // Parse JSON response
    nlohmann::json discovery_response;
    try {
        discovery_response = nlohmann::json::parse(response.body);
    } catch (const std::exception& e) {
        FAIL() << "Failed to parse discovery response JSON: " << e.what() << ". Response: " << response.body;
    }

    // Verify discovery response structure
    ASSERT_TRUE(discovery_response.contains("issuer")) << "Missing issuer in discovery response";
    ASSERT_TRUE(discovery_response.contains("token_endpoint")) << "Missing token_endpoint in discovery response";
    ASSERT_TRUE(discovery_response.contains("grant_types_supported")) << "Missing grant_types_supported in discovery response";

    // Verify expected values
    EXPECT_EQ(discovery_response["issuer"].get<std::string>(), server_url_) << "Issuer should match server URL";
    EXPECT_EQ(discovery_response["token_endpoint"].get<std::string>(), server_url_ + "/token") << "Token endpoint should be correct";

    std::cout << "✓ Discovery endpoint successful" << std::endl;
    std::cout << "✓ Issuer: " << discovery_response["issuer"].get<std::string>() << std::endl;
    std::cout << "✓ Token endpoint: " << discovery_response["token_endpoint"].get<std::string>() << std::endl;
}

// Performance test
TEST_F(RealOAuth2IntegrationTest, PerformanceTest_MultipleTokenRequests_ShouldHandleLoad) {
    // Skip if OAuth2 server is not available
    if (!server_available_) {
        GTEST_SKIP() << "OAuth2 server is not available, skipping integration test";
    }

    const int num_requests = 10;
    const int max_concurrent = 5;
    
    std::vector<std::future<SimpleHttpClient::HttpResponse>> futures;
    std::vector<std::chrono::high_resolution_clock::time_point> start_times;
    
    // Prepare request data
    std::string post_data = "grant_type=client_credentials";
    post_data += "&client_id=" + UrlEncode(client_id_);
    post_data += "&client_secret=" + UrlEncode(client_secret_);
    post_data += "&scope=" + UrlEncode(scope_);

    auto overall_start = std::chrono::high_resolution_clock::now();

    // Launch concurrent requests
    for (int i = 0; i < num_requests; ++i) {
        start_times.push_back(std::chrono::high_resolution_clock::now());
        
        futures.push_back(std::async(std::launch::async, [this, post_data]() {
            SimpleHttpClient client;
            return client.Post(server_url_ + "/token", post_data);
        }));

        // Limit concurrency
        if (futures.size() >= max_concurrent) {
            // Wait for some to complete
            for (auto& future : futures) {
                future.wait();
            }
            futures.clear();
        }
    }

    // Wait for remaining requests
    for (auto& future : futures) {
        future.wait();
    }

    auto overall_end = std::chrono::high_resolution_clock::now();
    auto total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(overall_end - overall_start);

    std::cout << "✓ Performance test completed" << std::endl;
    std::cout << "✓ " << num_requests << " requests completed in " << total_duration.count() << "ms" << std::endl;
    std::cout << "✓ Average: " << (total_duration.count() / num_requests) << "ms per request" << std::endl;

    // Basic performance assertions
    EXPECT_LT(total_duration.count(), 10000) << "All requests should complete within 10 seconds";
    EXPECT_GT(total_duration.count(), 0) << "Duration should be positive";
}

} // namespace integration
} // namespace security
} // namespace infra
} // namespace coyote

// Main function for running the tests
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    
    std::cout << "=================================" << std::endl;
    std::cout << "C++ OAuth2 Integration Tests" << std::endl;
    std::cout << "=================================" << std::endl;
    
    return RUN_ALL_TESTS();
}
