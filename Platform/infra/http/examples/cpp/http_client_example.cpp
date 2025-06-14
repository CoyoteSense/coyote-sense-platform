#include "../factory/cpp/http_client_factory.h"
#include "../modes/mock/cpp/http_client_mock.h"
#include <iostream>
#include <cassert>

using namespace coyote::infra;

void TestRealHttpClient() {
  std::cout << "Testing Real HTTP Client..." << std::endl;
  
  try {
    // Create real HTTP client
    auto client = HttpClientFactory::CreateClient(RuntimeMode::kProduction);
    
    // Configure client
    client->SetDefaultTimeout(5000);
    client->SetDefaultHeaders({
      {"User-Agent", "CoyoteSense/1.0"},
      {"Accept", "application/json"}
    });
    
    // Test GET request to a test endpoint
    try {
      auto response = client->Get("https://httpbin.org/get");
      std::cout << "GET Status: " << response->GetStatusCode() << std::endl;
      std::cout << "GET Response (first 100 chars): " 
                << response->GetBody().substr(0, 100) << "..." << std::endl;
    } catch (const std::exception& e) {
      std::cout << "GET Request failed: " << e.what() << std::endl;
    }
    
    // Test POST request
    try {
      auto response = client->Post("https://httpbin.org/post", 
                                  R"({"test": "data"})",
                                  {{"Content-Type", "application/json"}});
      std::cout << "POST Status: " << response->GetStatusCode() << std::endl;
    } catch (const std::exception& e) {
      std::cout << "POST Request failed: " << e.what() << std::endl;
    }
    
    std::cout << "Real HTTP Client tests completed!" << std::endl;
    
  } catch (const std::exception& e) {
    std::cout << "Real HTTP Client not available: " << e.what() << std::endl;
    std::cout << "This is expected on builds without libcurl." << std::endl;
  }
}

void TestMockHttpClient() {
  std::cout << "\nTesting Mock HTTP Client..." << std::endl;
  
  // Create mock HTTP client
  auto mock_client = std::make_unique<mocks::HttpClientMock>();
  
  // Set up mock responses
  mocks::RequestMatcher get_matcher;
  get_matcher.url_pattern = ".*test.*";
  get_matcher.method = HttpMethod::kGet;
    auto mock_response = std::make_unique<mocks::MockHttpResponse>(
    200, 
    R"({"mock": true, "data": "test response"})",
    std::unordered_map<std::string, std::string>{
      {"content-type", "application/json"},
      {"x-mock", "true"}
    }
  );
  
  mock_client->AddResponse(std::move(mock_response));
  
  // Test the mock
  auto response = mock_client->Get("https://api.test.com/data");
  
  assert(response->GetStatusCode() == 200);
  assert(response->IsSuccess());
  assert(response->GetBody().find("mock") != std::string::npos);
  
  std::cout << "Mock Status: " << response->GetStatusCode() << std::endl;
  std::cout << "Mock Response: " << response->GetBody() << std::endl;
  
  // Test request recording
  mock_client->EnableRequestRecording(true);
  auto response2 = mock_client->Get("https://api.test.com/data2");
  
  const auto& history = mock_client->GetRecordedRequests();
  assert(history.size() == 1);
  
  std::cout << "Mock HTTP Client tests passed!" << std::endl;
}

void TestFactoryModeSelection() {
  std::cout << "\nTesting Factory Mode Selection..." << std::endl;
  
  try {
    // Test different modes
    auto prod_client = HttpClientFactory::CreateClient(RuntimeMode::kProduction);
    auto test_client = HttpClientFactory::CreateClient(RuntimeMode::kTesting);
    
    // In real usage, these would be different types, but for demo we just check they're not null
    assert(prod_client != nullptr);
    assert(test_client != nullptr);
    
    std::cout << "Factory mode selection tests passed!" << std::endl;
    
  } catch (const std::exception& e) {
    std::cout << "Factory mode selection failed: " << e.what() << std::endl;
    std::cout << "This may be expected on builds without libcurl." << std::endl;
  }
}

int main() {
  std::cout << "=== Coyote HTTP Client Example ===" << std::endl;
  
  try {
    // Test mock client (always works)
    TestMockHttpClient();
    
    // Test factory
    TestFactoryModeSelection();
    
    // Test real client (might fail if no internet)
    TestRealHttpClient();
    
    std::cout << "\n=== All tests completed ===" << std::endl;
    
  } catch (const std::exception& e) {
    std::cerr << "Example failed: " << e.what() << std::endl;
    return 1;
  }
  
  return 0;
}
