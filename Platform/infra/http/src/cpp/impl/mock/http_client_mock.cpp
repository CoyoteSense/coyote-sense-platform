#include "http_client_mock.h"
#include <regex>
#include <thread>

namespace coyote {
namespace infra {
namespace mocks {

// RequestMatcher implementation
bool RequestMatcher::Matches(const HttpRequest& request) const {
  const auto& mock_request = static_cast<const MockHttpRequest&>(request);
  
  // Check method
  if (method != mock_request.GetMethod()) {
    return false;
  }
  
  // Check URL pattern
  if (!url_pattern.empty()) {
    std::regex pattern(url_pattern);
    if (!std::regex_match(mock_request.GetUrl(), pattern)) {
      return false;
    }
  }
  
  // Check required headers
  for (const auto& [key, value] : required_headers) {
    const auto& request_headers = mock_request.GetHeaders();
    auto it = request_headers.find(key);
    if (it == request_headers.end() || it->second != value) {
      return false;
    }
  }
  
  // Check body pattern
  if (!body_pattern.empty()) {
    std::regex pattern(body_pattern);
    if (!std::regex_match(mock_request.GetBody(), pattern)) {
      return false;
    }
  }
  
  return true;
}

// HttpClientMock implementation
HttpClientMock::HttpClientMock() {
  // Set default successful response
  default_response_ = std::make_unique<MockHttpResponse>(200, "OK");
}

std::unique_ptr<HttpResponse> HttpClientMock::Execute(const HttpRequest& request) {
  std::lock_guard<std::mutex> lock(request_mutex_);
  
  // Record the request if enabled
  if (record_requests_) {
    RecordRequest(request);
  }
  
  // Simulate latency if configured
  if (simulated_latency_.count() > 0) {
    std::this_thread::sleep_for(simulated_latency_);
  }
  
  // Simulate network error
  if (simulate_network_error_) {
    return std::make_unique<MockHttpResponse>(0, "", std::unordered_map<std::string, std::string>{}, network_error_message_);
  }
  
  // Check if we should simulate failure
  if (ShouldSimulateFailure()) {
    return std::make_unique<MockHttpResponse>(0, "", std::unordered_map<std::string, std::string>{}, "Simulated network failure");
  }
  
  // Get response from queue if available
  if (!response_queue_.empty()) {
    auto response = std::move(response_queue_.front());
    response_queue_.pop();
    return std::make_unique<MockHttpResponse>(
      response->GetStatusCode(),
      response->GetBody(),
      response->GetHeaders(),
      response->GetErrorMessage()
    );
  }
  
  // Return default response
  return std::make_unique<MockHttpResponse>(
    default_response_->GetStatusCode(),
    default_response_->GetBody(),
    default_response_->GetHeaders(),
    default_response_->GetErrorMessage()
  );
}

std::unique_ptr<HttpResponse> HttpClientMock::Get(
    const std::string& url, 
    const std::unordered_map<std::string, std::string>& headers) {
  MockHttpRequest request;
  request.SetUrl(url);
  request.SetMethod(HttpMethod::kGet);
  request.SetHeaders(headers);
  return Execute(request);
}

std::unique_ptr<HttpResponse> HttpClientMock::Post(
    const std::string& url, 
    const std::string& body,
    const std::unordered_map<std::string, std::string>& headers) {
  MockHttpRequest request;
  request.SetUrl(url);
  request.SetMethod(HttpMethod::kPost);
  request.SetBody(body);
  request.SetHeaders(headers);
  return Execute(request);
}

std::unique_ptr<HttpResponse> HttpClientMock::Put(
    const std::string& url, 
    const std::string& body,
    const std::unordered_map<std::string, std::string>& headers) {
  MockHttpRequest request;
  request.SetUrl(url);
  request.SetMethod(HttpMethod::kPut);
  request.SetBody(body);
  request.SetHeaders(headers);
  return Execute(request);
}

std::unique_ptr<HttpResponse> HttpClientMock::Delete(
    const std::string& url,
    const std::unordered_map<std::string, std::string>& headers) {
  MockHttpRequest request;
  request.SetUrl(url);
  request.SetMethod(HttpMethod::kDelete);
  request.SetHeaders(headers);
  return Execute(request);
}

void HttpClientMock::SetDefaultTimeout(long timeout_ms) {
  default_timeout_ = timeout_ms;
}

void HttpClientMock::SetDefaultHeaders(
    const std::unordered_map<std::string, std::string>& headers) {
  default_headers_ = headers;
}

void HttpClientMock::SetClientCertificate(
    const std::string& cert_path, 
    const std::string& key_path) {
  default_client_cert_path_ = cert_path;
  default_client_key_path_ = key_path;
}

void HttpClientMock::SetCACertificate(const std::string& ca_path) {
  default_ca_cert_path_ = ca_path;
}

void HttpClientMock::SetVerifyPeer(bool verify) {
  default_verify_peer_ = verify;
}

bool HttpClientMock::Ping(const std::string& url) {
  auto response = Get(url + "/health");
  return response && response->IsSuccess();
}

// Mock-specific methods
void HttpClientMock::AddResponse(std::unique_ptr<MockHttpResponse> response) {
  std::lock_guard<std::mutex> lock(request_mutex_);
  response_queue_.push(std::move(response));
}

void HttpClientMock::AddResponses(std::vector<std::unique_ptr<MockHttpResponse>> responses) {
  std::lock_guard<std::mutex> lock(request_mutex_);
  for (auto& response : responses) {
    response_queue_.push(std::move(response));
  }
}

void HttpClientMock::SetDefaultResponse(std::unique_ptr<MockHttpResponse> response) {
  std::lock_guard<std::mutex> lock(request_mutex_);
  default_response_ = std::move(response);
}

void HttpClientMock::ClearResponses() {
  std::lock_guard<std::mutex> lock(request_mutex_);
  std::queue<std::unique_ptr<MockHttpResponse>> empty;
  response_queue_.swap(empty);
}

// Request recording
void HttpClientMock::EnableRequestRecording(bool enable) {
  record_requests_ = enable;
}

const std::vector<std::unique_ptr<MockHttpRequest>>& HttpClientMock::GetRecordedRequests() const {
  return recorded_requests_;
}

void HttpClientMock::ClearRecordedRequests() {
  std::lock_guard<std::mutex> lock(request_mutex_);
  recorded_requests_.clear();
}

// Error simulation
void HttpClientMock::SimulateNetworkError(bool simulate, const std::string& error_message) {
  simulate_network_error_ = simulate;
  network_error_message_ = error_message;
}

void HttpClientMock::SetLatencySimulation(std::chrono::milliseconds latency) {
  simulated_latency_ = latency;
}

void HttpClientMock::SetFailureRate(double rate) {
  failure_rate_ = rate;
}

// Convenience methods
void HttpClientMock::AddJsonResponse(int status_code, const std::string& json_body) {
  auto response = std::make_unique<MockHttpResponse>(status_code, json_body);
  response->SetHeader("Content-Type", "application/json");
  AddResponse(std::move(response));
}

void HttpClientMock::AddSuccessResponse(const std::string& body) {
  AddResponse(std::make_unique<MockHttpResponse>(200, body));
}

void HttpClientMock::AddErrorResponse(int status_code, const std::string& error_body) {
  AddResponse(std::make_unique<MockHttpResponse>(status_code, error_body));
}

void HttpClientMock::AddNotFoundResponse() {
  AddResponse(std::make_unique<MockHttpResponse>(404, "Not Found"));
}

void HttpClientMock::AddServerErrorResponse() {
  AddResponse(std::make_unique<MockHttpResponse>(500, "Internal Server Error"));
}

void HttpClientMock::AddUnauthorizedResponse() {
  AddResponse(std::make_unique<MockHttpResponse>(401, "Unauthorized"));
}

// State inspection
size_t HttpClientMock::GetQueuedResponseCount() const {
  std::lock_guard<std::mutex> lock(request_mutex_);
  return response_queue_.size();
}

// Private helper methods
std::unique_ptr<MockHttpResponse> HttpClientMock::CreateMockResponse(
    int status_code, 
    const std::string& body, 
    const std::unordered_map<std::string, std::string>& headers) {
  return std::make_unique<MockHttpResponse>(status_code, body, headers);
}

void HttpClientMock::RecordRequest(const HttpRequest& request) {
  auto recorded_request = std::make_unique<MockHttpRequest>();
  const auto& mock_request = static_cast<const MockHttpRequest&>(request);
  
  recorded_request->SetUrl(mock_request.GetUrl());
  recorded_request->SetMethod(mock_request.GetMethod());
  recorded_request->SetHeaders(mock_request.GetHeaders());
  recorded_request->SetBody(mock_request.GetBody());
  recorded_request->SetTimeout(mock_request.GetTimeout());
  
  recorded_requests_.push_back(std::move(recorded_request));
}

bool HttpClientMock::ShouldSimulateFailure() const {
  return failure_rate_ > 0.0 && static_cast<double>(rand()) / RAND_MAX < failure_rate_;
}

}  // namespace mocks
}  // namespace infra
}  // namespace coyote