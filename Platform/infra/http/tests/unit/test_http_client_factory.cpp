// Unit tests for HTTP Client Factory
#include <gtest/gtest.h>
#include "../../factory/cpp/http_client_factory.h"
#include "../../modes/mock/cpp/http_client_mock.h"
#include <cstdlib>

using namespace coyote::infra;

class HttpClientFactoryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Clear environment variables before each test
    #ifdef _WIN32
    _putenv_s("COYOTE_RUNTIME_MODE", "");
    _putenv_s("MODE", "");
    #else
    unsetenv("COYOTE_RUNTIME_MODE");
    unsetenv("MODE");
    #endif
  }

  void SetEnvironmentVariable(const std::string& name, const std::string& value) {
    #ifdef _WIN32
    _putenv_s(name.c_str(), value.c_str());
    #else
    setenv(name.c_str(), value.c_str(), 1);
    #endif
  }
};

TEST_F(HttpClientFactoryTest, CreateMockClientExplicitly) {
  SetEnvironmentVariable("COYOTE_RUNTIME_MODE", "mock");
  
  auto client = HttpClientFactory::CreateHttpClient();
  ASSERT_NE(client, nullptr);
  
  // Test that it behaves like a mock client
  auto response = client->Get("http://example.com");
  EXPECT_TRUE(response->IsSuccess());
  EXPECT_EQ(response->GetStatusCode(), 200);
}

TEST_F(HttpClientFactoryTest, CreateTestClient) {
  SetEnvironmentVariable("COYOTE_RUNTIME_MODE", "testing");
  
  auto client = HttpClientFactory::CreateHttpClient();
  ASSERT_NE(client, nullptr);
  
  // Testing mode should also return mock client
  auto response = client->Get("http://example.com");
  EXPECT_TRUE(response->IsSuccess());
}

TEST_F(HttpClientFactoryTest, CreateDebugClient) {
  SetEnvironmentVariable("COYOTE_RUNTIME_MODE", "debug");
  
  auto client = HttpClientFactory::CreateHttpClient();
  ASSERT_NE(client, nullptr);
  
  // Debug mode should return mock client
  auto response = client->Get("http://example.com");
  EXPECT_TRUE(response->IsSuccess());
}

TEST_F(HttpClientFactoryTest, CreateSimulationClient) {
  SetEnvironmentVariable("COYOTE_RUNTIME_MODE", "simulation");
  
  auto client = HttpClientFactory::CreateHttpClient();
  ASSERT_NE(client, nullptr);
  
  // Simulation mode should return mock client
  auto response = client->Get("http://example.com");
  EXPECT_TRUE(response->IsSuccess());
}

TEST_F(HttpClientFactoryTest, AlternateModeVariable) {
  SetEnvironmentVariable("MODE", "mock");
  
  auto client = HttpClientFactory::CreateHttpClient();
  ASSERT_NE(client, nullptr);
  
  // Should work with MODE variable too
  auto response = client->Get("http://example.com");
  EXPECT_TRUE(response->IsSuccess());
}

TEST_F(HttpClientFactoryTest, CoyoteRuntimeModeHasPriority) {
  SetEnvironmentVariable("COYOTE_RUNTIME_MODE", "mock");
  SetEnvironmentVariable("MODE", "production");
  
  auto client = HttpClientFactory::CreateHttpClient();
  ASSERT_NE(client, nullptr);
  
  // COYOTE_RUNTIME_MODE should take precedence
  auto response = client->Get("http://example.com");
  EXPECT_TRUE(response->IsSuccess());
}

#ifdef CURL_NOT_AVAILABLE
TEST_F(HttpClientFactoryTest, ProductionModeWithoutCurlThrows) {
  SetEnvironmentVariable("COYOTE_RUNTIME_MODE", "production");
  
  EXPECT_THROW(HttpClientFactory::CreateHttpClient(), std::runtime_error);
}

TEST_F(HttpClientFactoryTest, RecordingModeWithoutCurlThrows) {
  SetEnvironmentVariable("COYOTE_RUNTIME_MODE", "recording");
  
  EXPECT_THROW(HttpClientFactory::CreateHttpClient(), std::runtime_error);
}

TEST_F(HttpClientFactoryTest, ReplayModeWithoutCurlThrows) {
  SetEnvironmentVariable("COYOTE_RUNTIME_MODE", "replay");
  
  EXPECT_THROW(HttpClientFactory::CreateHttpClient(), std::runtime_error);
}
#endif

TEST_F(HttpClientFactoryTest, DefaultModeWhenNoEnvironmentSet) {
  // Don't set any environment variables
  
  auto client = HttpClientFactory::CreateHttpClient();
  ASSERT_NE(client, nullptr);
  
  // Should default to mock client when no mode is set
  auto response = client->Get("http://example.com");
  EXPECT_TRUE(response->IsSuccess());
}

TEST_F(HttpClientFactoryTest, CaseInsensitiveModeDetection) {
  SetEnvironmentVariable("COYOTE_RUNTIME_MODE", "MOCK");
  
  auto client = HttpClientFactory::CreateHttpClient();
  ASSERT_NE(client, nullptr);
  
  // Should handle uppercase mode
  auto response = client->Get("http://example.com");
  EXPECT_TRUE(response->IsSuccess());
}

TEST_F(HttpClientFactoryTest, UnknownModeDefaultsToMock) {
  SetEnvironmentVariable("COYOTE_RUNTIME_MODE", "unknown_mode");
  
  auto client = HttpClientFactory::CreateHttpClient();
  ASSERT_NE(client, nullptr);
  
  // Unknown mode should default to mock
  auto response = client->Get("http://example.com");
  EXPECT_TRUE(response->IsSuccess());
}

TEST_F(HttpClientFactoryTest, MultipleClientCreation) {
  SetEnvironmentVariable("COYOTE_RUNTIME_MODE", "mock");
  
  auto client1 = HttpClientFactory::CreateHttpClient();
  auto client2 = HttpClientFactory::CreateHttpClient();
  
  ASSERT_NE(client1, nullptr);
  ASSERT_NE(client2, nullptr);
  EXPECT_NE(client1.get(), client2.get()); // Should be different instances
  
  // Both should work independently
  auto response1 = client1->Get("http://example.com");
  auto response2 = client2->Get("http://example.com");
  
  EXPECT_TRUE(response1->IsSuccess());
  EXPECT_TRUE(response2->IsSuccess());
}
