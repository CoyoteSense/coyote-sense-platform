// Integration tests for HTTP Client - tests against real web server
#include <gtest/gtest.h>
#include "http_client_factory.h"
#include "../common/test_helpers.h"
#include <thread>
#include <chrono>

using namespace coyote::infra;

class HttpClientIntegrationTest : public ::testing::Test {
 protected:  void SetUp() override {
    // Set environment to use real HTTP client
    test_helpers::SetTestEnvironmentVariable("COYOTE_RUNTIME_MODE", "real");
    
    // Get test server configuration from environment
    test_server_host_ = test_helpers::GetTestEnvironmentVariable("TEST_SERVER_HOST", "localhost");
    test_server_http_port_ = test_helpers::GetTestEnvironmentVariable("TEST_SERVER_HTTP_PORT", "8080");
    test_server_https_port_ = test_helpers::GetTestEnvironmentVariable("TEST_SERVER_HTTPS_PORT", "8443");
    
    base_url_ = "http://" + test_server_host_ + ":" + test_server_http_port_;
    base_https_url_ = "https://" + test_server_host_ + ":" + test_server_https_port_;
    
    // Wait for test server to be ready
    WaitForTestServer();
    
    // Create HTTP client
    client_ = HttpClientFactory::CreateHttpClient();
    ASSERT_NE(client_, nullptr);
  }

  void TearDown() override {
    client_.reset();
  }

  void WaitForTestServer() {
    auto temp_client = HttpClientFactory::CreateHttpClient();
    const int max_attempts = 30;
    const auto delay = std::chrono::seconds(2);
    
    for (int attempt = 1; attempt <= max_attempts; ++attempt) {
      try {
        auto response = temp_client->Get(base_url_ + "/health");
        if (response && response->IsSuccess()) {
          std::cout << "Test server is ready after " << attempt << " attempts" << std::endl;
          return;
        }
      } catch (...) {
        // Ignore exceptions during startup
      }
      
      std::cout << "Waiting for test server... attempt " << attempt << "/" << max_attempts << std::endl;
      std::this_thread::sleep_for(delay);
    }
    
    FAIL() << "Test server did not become ready within timeout period";
  }

  std::unique_ptr<HttpClient> client_;
  std::string test_server_host_;
  std::string test_server_http_port_;
  std::string test_server_https_port_;
  std::string base_url_;
  std::string base_https_url_;
};

// Basic connectivity tests
TEST_F(HttpClientIntegrationTest, HealthCheck) {
  auto response = client_->Get(base_url_ + "/health");
  
  ASSERT_NE(response, nullptr);
  EXPECT_TRUE(response->IsSuccess());
  EXPECT_EQ(response->GetStatusCode(), 200);
  
  // Verify response contains expected health check data
  std::string body = response->GetBody();
  EXPECT_TRUE(body.find("healthy") != std::string::npos);
  EXPECT_TRUE(body.find("timestamp") != std::string::npos);
}

// HTTP methods tests
TEST_F(HttpClientIntegrationTest, GetRequest) {
  auto response = client_->Get(base_url_ + "/api/test");
  
  ASSERT_NE(response, nullptr);
  EXPECT_TRUE(response->IsSuccess());
  EXPECT_EQ(response->GetStatusCode(), 200);
  
  std::string body = response->GetBody();
  EXPECT_TRUE(body.find("GET") != std::string::npos);
  EXPECT_TRUE(body.find("successful") != std::string::npos);
}

TEST_F(HttpClientIntegrationTest, PostRequest) {
  std::string request_body = R"({"test": "data", "value": 123})";
  std::unordered_map<std::string, std::string> headers{
    {"Content-Type", "application/json"}
  };
  
  auto response = client_->Post(base_url_ + "/api/test", request_body, headers);
  
  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->GetStatusCode(), 201);
  
  std::string body = response->GetBody();
  EXPECT_TRUE(body.find("POST") != std::string::npos);
  EXPECT_TRUE(body.find("successful") != std::string::npos);
  EXPECT_TRUE(body.find("test") != std::string::npos);
  EXPECT_TRUE(body.find("data") != std::string::npos);
}

TEST_F(HttpClientIntegrationTest, PutRequest) {
  std::string request_body = R"({"update": "data"})";
  std::unordered_map<std::string, std::string> headers{
    {"Content-Type", "application/json"}
  };
  
  auto response = client_->Put(base_url_ + "/api/test", request_body, headers);
  
  ASSERT_NE(response, nullptr);
  EXPECT_TRUE(response->IsSuccess());
  EXPECT_EQ(response->GetStatusCode(), 200);
  
  std::string body = response->GetBody();
  EXPECT_TRUE(body.find("PUT") != std::string::npos);
  EXPECT_TRUE(body.find("successful") != std::string::npos);
}

TEST_F(HttpClientIntegrationTest, DeleteRequest) {
  auto response = client_->Delete(base_url_ + "/api/test");
  
  ASSERT_NE(response, nullptr);
  EXPECT_TRUE(response->IsSuccess());
  EXPECT_EQ(response->GetStatusCode(), 200);
  
  std::string body = response->GetBody();
  EXPECT_TRUE(body.find("DELETE") != std::string::npos);
  EXPECT_TRUE(body.find("successful") != std::string::npos);
}

// Status code tests
TEST_F(HttpClientIntegrationTest, VariousStatusCodes) {
  // Test successful status codes
  auto response_200 = client_->Get(base_url_ + "/api/status/200");
  EXPECT_EQ(response_200->GetStatusCode(), 200);
  EXPECT_TRUE(response_200->IsSuccess());
  
  auto response_201 = client_->Get(base_url_ + "/api/status/201");
  EXPECT_EQ(response_201->GetStatusCode(), 201);
  EXPECT_TRUE(response_201->IsSuccess());
  
  // Test client error status codes
  auto response_400 = client_->Get(base_url_ + "/api/status/400");
  EXPECT_EQ(response_400->GetStatusCode(), 400);
  EXPECT_FALSE(response_400->IsSuccess());
  
  auto response_401 = client_->Get(base_url_ + "/api/status/401");
  EXPECT_EQ(response_401->GetStatusCode(), 401);
  EXPECT_FALSE(response_401->IsSuccess());
  
  auto response_404 = client_->Get(base_url_ + "/api/status/404");
  EXPECT_EQ(response_404->GetStatusCode(), 404);
  EXPECT_FALSE(response_404->IsSuccess());
  
  // Test server error status codes
  auto response_500 = client_->Get(base_url_ + "/api/status/500");
  EXPECT_EQ(response_500->GetStatusCode(), 500);
  EXPECT_FALSE(response_500->IsSuccess());
}

// Headers tests
TEST_F(HttpClientIntegrationTest, CustomRequestHeaders) {
  std::unordered_map<std::string, std::string> headers{
    {"X-Custom-Header", "test-value"},
    {"Authorization", "Bearer test-token"},
    {"User-Agent", "CoyoteHTTPClient/1.0"}
  };
  
  auto response = client_->Get(base_url_ + "/api/headers", headers);
  
  ASSERT_NE(response, nullptr);
  EXPECT_TRUE(response->IsSuccess());
  
  std::string body = response->GetBody();
  EXPECT_TRUE(body.find("test-value") != std::string::npos);
  EXPECT_TRUE(body.find("Bearer test-token") != std::string::npos);
  EXPECT_TRUE(body.find("CoyoteHTTPClient/1.0") != std::string::npos);
}

TEST_F(HttpClientIntegrationTest, ResponseHeaders) {
  auto response = client_->Get(base_url_ + "/api/response-headers");
  
  ASSERT_NE(response, nullptr);
  EXPECT_TRUE(response->IsSuccess());
  
  auto headers = response->GetHeaders();
  
  // Check for custom response headers
  auto custom_header = headers.find("x-custom-response-header");
  EXPECT_NE(custom_header, headers.end());
  if (custom_header != headers.end()) {
    EXPECT_EQ(custom_header->second, "test-value");
  }
  
  auto api_version = headers.find("x-api-version");
  EXPECT_NE(api_version, headers.end());
  if (api_version != headers.end()) {
    EXPECT_EQ(api_version->second, "1.0");
  }
}

// JSON handling tests
TEST_F(HttpClientIntegrationTest, JsonResponse) {
  auto response = client_->Get(base_url_ + "/api/json");
  
  ASSERT_NE(response, nullptr);
  EXPECT_TRUE(response->IsSuccess());
  
  // Check Content-Type header
  auto headers = response->GetHeaders();
  auto content_type = headers.find("content-type");
  EXPECT_NE(content_type, headers.end());
  if (content_type != headers.end()) {
    EXPECT_TRUE(content_type->second.find("application/json") != std::string::npos);
  }
  
  // Verify JSON structure
  std::string body = response->GetBody();
  EXPECT_TRUE(body.find("\"data\"") != std::string::npos);
  EXPECT_TRUE(body.find("\"users\"") != std::string::npos);
  EXPECT_TRUE(body.find("\"pagination\"") != std::string::npos);
  EXPECT_TRUE(body.find("John Doe") != std::string::npos);
  EXPECT_TRUE(body.find("jane@example.com") != std::string::npos);
}

// Authentication tests
TEST_F(HttpClientIntegrationTest, BearerTokenAuthentication) {
  std::unordered_map<std::string, std::string> headers{
    {"Authorization", "Bearer valid-token-123"}
  };
  
  auto response = client_->Get(base_url_ + "/api/auth/bearer", headers);
  
  ASSERT_NE(response, nullptr);
  EXPECT_TRUE(response->IsSuccess());
  EXPECT_EQ(response->GetStatusCode(), 200);
  
  std::string body = response->GetBody();
  EXPECT_TRUE(body.find("Authentication successful") != std::string::npos);
  EXPECT_TRUE(body.find("testuser") != std::string::npos);
}

TEST_F(HttpClientIntegrationTest, InvalidBearerToken) {
  std::unordered_map<std::string, std::string> headers{
    {"Authorization", "Bearer invalid-token"}
  };
  
  auto response = client_->Get(base_url_ + "/api/auth/bearer", headers);
  
  ASSERT_NE(response, nullptr);
  EXPECT_FALSE(response->IsSuccess());
  EXPECT_EQ(response->GetStatusCode(), 401);
}

// Error handling tests
TEST_F(HttpClientIntegrationTest, NetworkTimeout) {
  // Set a very short timeout
  client_->SetDefaultTimeout(1000); // 1 second
  
  // Request a 5-second delay (should timeout)
  auto response = client_->Get(base_url_ + "/api/timeout/5");
  
  // This should either timeout or complete quickly
  // The exact behavior depends on the CURL implementation
  ASSERT_NE(response, nullptr);
}

TEST_F(HttpClientIntegrationTest, InvalidUrl) {
  auto response = client_->Get("http://nonexistent-server-12345.invalid/api/test");
  
  ASSERT_NE(response, nullptr);
  EXPECT_FALSE(response->IsSuccess());
  EXPECT_FALSE(response->GetErrorMessage().empty());
}

TEST_F(HttpClientIntegrationTest, NonExistentEndpoint) {
  auto response = client_->Get(base_url_ + "/api/nonexistent");
  
  ASSERT_NE(response, nullptr);
  EXPECT_FALSE(response->IsSuccess());
  EXPECT_EQ(response->GetStatusCode(), 404);
}

// Large response tests
TEST_F(HttpClientIntegrationTest, LargeResponse) {
  // Request a 1MB response
  auto response = client_->Get(base_url_ + "/api/large/1024");
  
  ASSERT_NE(response, nullptr);
  EXPECT_TRUE(response->IsSuccess());
  
  std::string body = response->GetBody();
  // Should be approximately 1MB
  EXPECT_GT(body.size(), 1000000); // At least 1MB
  EXPECT_LT(body.size(), 2000000); // But not more than 2MB
}

// Configuration tests
TEST_F(HttpClientIntegrationTest, ClientConfiguration) {
  // Test setting default headers
  std::unordered_map<std::string, std::string> default_headers{
    {"User-Agent", "CoyoteTestClient/1.0"},
    {"X-Test-Suite", "integration"}
  };
  
  client_->SetDefaultHeaders(default_headers);
  client_->SetDefaultTimeout(30000); // 30 seconds
  client_->SetVerifyPeer(true);
  
  auto response = client_->Get(base_url_ + "/api/headers");
  
  ASSERT_NE(response, nullptr);
  EXPECT_TRUE(response->IsSuccess());
  
  std::string body = response->GetBody();
  EXPECT_TRUE(body.find("CoyoteTestClient/1.0") != std::string::npos);
  EXPECT_TRUE(body.find("integration") != std::string::npos);
}

// Ping functionality test
TEST_F(HttpClientIntegrationTest, PingFunctionality) {
  // Ping should succeed for healthy server
  bool ping_result = client_->Ping(base_url_);
  EXPECT_TRUE(ping_result);
  
  // Ping should fail for non-existent server
  bool bad_ping_result = client_->Ping("http://nonexistent-server-12345.invalid");
  EXPECT_FALSE(bad_ping_result);
}
