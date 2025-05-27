// Unit tests for HTTP Client Mock
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../../modes/mock/cpp/http_client_mock.h"
#include "../../factory/cpp/http_client_factory.h"
#include <chrono>
#include <thread>
#include <memory>

using namespace coyote::infra;
using namespace coyote::infra::mocks;

// Test fixture for HTTP Client Mock tests
class HttpClientMockTest : public ::testing::Test {
protected:
    void SetUp() override {
        client_ = std::make_unique<HttpClientMock>();
    }

    void TearDown() override {
        // Clean up any resources
    }

    std::unique_ptr<HttpClientMock> client_;
};

// Basic functionality tests
TEST(HttpClientMock, DefaultResponseIsSuccessful) {
  auto client = std::make_unique<HttpClientMock>();
  auto response = client->Get("http://example.com");
  
  ASSERT_NE(response.get(), nullptr);
  ASSERT_TRUE(response->IsSuccess());
  ASSERT_EQ(response->GetStatusCode(), 200);
  EXPECT_FALSE(response->GetBody().empty());
}

TEST_F(HttpClientMockTest, AllHttpMethodsSupported) {
  auto get_response = client_->Get("http://example.com");
  auto post_response = client_->Post("http://example.com", "test body");
  auto put_response = client_->Put("http://example.com", "test body");
  auto delete_response = client_->Delete("http://example.com");
  
  EXPECT_TRUE(get_response->IsSuccess());
  EXPECT_TRUE(post_response->IsSuccess());
  EXPECT_TRUE(put_response->IsSuccess());
  EXPECT_TRUE(delete_response->IsSuccess());
}

TEST_F(HttpClientMockTest, CustomHeadersInRequest) {
  std::unordered_map<std::string, std::string> headers{
    {"Authorization", "Bearer token123"},
    {"Content-Type", "application/json"}
  };
  
  auto response = client_->Get("http://example.com", headers);
  EXPECT_TRUE(response->IsSuccess());
}

// Response queue tests
TEST_F(HttpClientMockTest, QueuedResponsesReturnedInOrder) {
  // Queue multiple responses
  client_->AddSuccessResponse("First response");
  client_->AddSuccessResponse("Second response");
  client_->AddErrorResponse(404, "Not found");
  
  EXPECT_EQ(client_->GetQueuedResponseCount(), 3);
  
  auto response1 = client_->Get("http://example.com");
  EXPECT_EQ(response1->GetStatusCode(), 200);
  EXPECT_EQ(response1->GetBody(), "First response");
  EXPECT_EQ(client_->GetQueuedResponseCount(), 2);
  
  auto response2 = client_->Get("http://example.com");
  EXPECT_EQ(response2->GetStatusCode(), 200);
  EXPECT_EQ(response2->GetBody(), "Second response");
  EXPECT_EQ(client_->GetQueuedResponseCount(), 1);
  
  auto response3 = client_->Get("http://example.com");
  EXPECT_EQ(response3->GetStatusCode(), 404);
  EXPECT_EQ(response3->GetBody(), "Not found");
  EXPECT_EQ(client_->GetQueuedResponseCount(), 0);
  
  // Should return default response when queue is empty
  auto response4 = client_->Get("http://example.com");
  EXPECT_EQ(response4->GetStatusCode(), 200);
}

TEST_F(HttpClientMockTest, JsonResponsesHaveCorrectContentType) {
  client_->AddJsonResponse(200, R"({"success": true})");
  
  auto response = client_->Get("http://example.com");
  EXPECT_EQ(response->GetStatusCode(), 200);
  EXPECT_EQ(response->GetBody(), R"({"success": true})");
  
  auto headers = response->GetHeaders();
  auto it = headers.find("Content-Type");
  ASSERT_NE(it, headers.end());
  EXPECT_EQ(it->second, "application/json");
}

// Request recording tests
TEST_F(HttpClientMockTest, RequestRecordingWhenEnabled) {
  client_->EnableRequestRecording(true);
  EXPECT_TRUE(client_->IsRecordingRequests());
  
  client_->Get("http://example.com/path1");
  client_->Post("http://example.com/path2", "test body");
  
  const auto& requests = client_->GetRecordedRequests();
  EXPECT_EQ(requests.size(), 2);
  
  EXPECT_EQ(requests[0]->GetUrl(), "http://example.com/path1");
  EXPECT_EQ(requests[0]->GetMethod(), HttpMethod::kGet);
  
  EXPECT_EQ(requests[1]->GetUrl(), "http://example.com/path2");
  EXPECT_EQ(requests[1]->GetMethod(), HttpMethod::kPost);
  EXPECT_EQ(requests[1]->GetBody(), "test body");
}

TEST_F(HttpClientMockTest, RequestRecordingWhenDisabled) {
  client_->EnableRequestRecording(false);
  EXPECT_FALSE(client_->IsRecordingRequests());
  
  client_->Get("http://example.com");
  
  const auto& requests = client_->GetRecordedRequests();
  EXPECT_EQ(requests.size(), 0);
}

TEST_F(HttpClientMockTest, ClearRecordedRequests) {
  client_->EnableRequestRecording(true);
  
  client_->Get("http://example.com");
  EXPECT_EQ(client_->GetRecordedRequests().size(), 1);
  
  client_->ClearRecordedRequests();
  EXPECT_EQ(client_->GetRecordedRequests().size(), 0);
}

// Error simulation tests
TEST_F(HttpClientMockTest, NetworkErrorSimulation) {
  client_->SimulateNetworkError(true, "Custom network error");
  EXPECT_TRUE(client_->IsSimulatingNetworkError());
  
  auto response = client_->Get("http://example.com");
  EXPECT_EQ(response->GetStatusCode(), 0);
  EXPECT_EQ(response->GetErrorMessage(), "Custom network error");
  EXPECT_FALSE(response->IsSuccess());
}

TEST_F(HttpClientMockTest, LatencySimulation) {
  auto start_time = std::chrono::steady_clock::now();
  
  client_->SetLatencySimulation(std::chrono::milliseconds(100));
  auto response = client_->Get("http://example.com");
  
  auto end_time = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
  
  EXPECT_GE(duration.count(), 100);
  EXPECT_TRUE(response->IsSuccess());
}

TEST_F(HttpClientMockTest, FailureRateSimulation) {
  // Set 100% failure rate
  client_->SetFailureRate(1.0);
  
  // Test multiple requests - all should fail
  int failure_count = 0;
  for (int i = 0; i < 10; ++i) {
    auto response = client_->Get("http://example.com");
    if (!response->IsSuccess()) {
      failure_count++;
    }
  }
  
  EXPECT_GT(failure_count, 8); // Allow some variance in random generation
}

// Convenience method tests
TEST_F(HttpClientMockTest, ConvenienceResponseMethods) {
  client_->AddNotFoundResponse();
  auto not_found = client_->Get("http://example.com");
  EXPECT_EQ(not_found->GetStatusCode(), 404);
  
  client_->AddServerErrorResponse();
  auto server_error = client_->Get("http://example.com");
  EXPECT_EQ(server_error->GetStatusCode(), 500);
  
  client_->AddUnauthorizedResponse();
  auto unauthorized = client_->Get("http://example.com");
  EXPECT_EQ(unauthorized->GetStatusCode(), 401);
}

// Configuration tests
TEST_F(HttpClientMockTest, ConfigurationMethods) {
  client_->SetDefaultTimeout(5000);
  client_->SetDefaultHeaders({{"User-Agent", "Test Client"}});
  client_->SetClientCertificate("/path/to/cert", "/path/to/key");
  client_->SetCACertificate("/path/to/ca");
  client_->SetVerifyPeer(false);
  
  // These should not throw exceptions
  auto response = client_->Get("http://example.com");
  EXPECT_TRUE(response->IsSuccess());
}

TEST_F(HttpClientMockTest, PingMethod) {
  // Default response should make ping succeed
  EXPECT_TRUE(client_->Ping("http://example.com"));
  
  // Add error response and ping should fail
  client_->AddErrorResponse(500, "Server error");
  EXPECT_FALSE(client_->Ping("http://example.com"));
}

// Custom response tests
TEST_F(HttpClientMockTest, CustomDefaultResponse) {
  auto custom_response = std::make_unique<MockHttpResponse>(
    201, 
    "Custom created", 
    std::unordered_map<std::string, std::string>{{"Location", "/new/resource"}}
  );
  
  client_->SetDefaultResponse(std::move(custom_response));
  
  auto response = client_->Get("http://example.com");
  EXPECT_EQ(response->GetStatusCode(), 201);
  EXPECT_EQ(response->GetBody(), "Custom created");
  
  auto headers = response->GetHeaders();
  auto location_it = headers.find("Location");
  ASSERT_NE(location_it, headers.end());
  EXPECT_EQ(location_it->second, "/new/resource");
}

TEST_F(HttpClientMockTest, ClearResponses) {
  client_->AddSuccessResponse("Test 1");
  client_->AddSuccessResponse("Test 2");
  EXPECT_EQ(client_->GetQueuedResponseCount(), 2);
  
  client_->ClearResponses();
  EXPECT_EQ(client_->GetQueuedResponseCount(), 0);
  
  // Should return default response
  auto response = client_->Get("http://example.com");
  EXPECT_EQ(response->GetStatusCode(), 200);
}

// Thread safety tests
TEST_F(HttpClientMockTest, ThreadSafetyBasic) {
  client_->EnableRequestRecording(true);
  
  std::vector<std::thread> threads;
  const int num_threads = 4;
  const int requests_per_thread = 10;
  
  for (int t = 0; t < num_threads; ++t) {
    threads.emplace_back([this, t, requests_per_thread]() {
      for (int i = 0; i < requests_per_thread; ++i) {
        std::string url = "http://example.com/thread" + std::to_string(t) + "/request" + std::to_string(i);
        auto response = client_->Get(url);
        EXPECT_TRUE(response->IsSuccess());
      }
    });
  }
  
  for (auto& thread : threads) {
    thread.join();
  }
  
  const auto& requests = client_->GetRecordedRequests();
  EXPECT_EQ(requests.size(), num_threads * requests_per_thread);
}

// Factory integration test
TEST_F(HttpClientMockTest, FactoryCreatesCorrectType) {
  // Set environment to mock mode
  #ifdef _WIN32
  _putenv_s("COYOTE_RUNTIME_MODE", "mock");
  #else
  setenv("COYOTE_RUNTIME_MODE", "mock", 1);
  #endif
  
  auto factory_client = HttpClientFactory::CreateHttpClient();
  ASSERT_NE(factory_client, nullptr);
  
  // Try to use it - should work like mock client
  auto response = factory_client->Get("http://example.com");
  EXPECT_TRUE(response->IsSuccess());
  EXPECT_EQ(response->GetStatusCode(), 200);
}
