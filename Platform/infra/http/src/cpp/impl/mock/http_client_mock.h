#pragma once

#include "http_client.h"
#include <queue>
#include <mutex>
#include <unordered_map>
#include <chrono>
#include <functional>

namespace coyote {
namespace infra {
namespace mocks {

// Mock HTTP Response implementation
class MockHttpResponse : public HttpResponse {
 public:
  MockHttpResponse(int status_code, const std::string& body, 
                  const std::unordered_map<std::string, std::string>& headers = {},
                  const std::string& error_message = "")
      : status_code_(status_code), headers_(headers), body_(body), error_message_(error_message) {}

  int GetStatusCode() const override { return status_code_; }
  const std::unordered_map<std::string, std::string>& GetHeaders() const override { return headers_; }
  const std::string& GetBody() const override { return body_; }
  bool IsSuccess() const override { return status_code_ >= 200 && status_code_ < 300; }
  const std::string& GetErrorMessage() const override { return error_message_; }

  void SetStatusCode(int code) { status_code_ = code; }
  void SetBody(const std::string& body) { body_ = body; }
  void SetHeader(const std::string& name, const std::string& value) { headers_[name] = value; }
  void SetErrorMessage(const std::string& error) { error_message_ = error; }

 private:
  int status_code_;
  std::unordered_map<std::string, std::string> headers_;
  std::string body_;
  std::string error_message_;
};

// Mock HTTP Request implementation
class MockHttpRequest : public HttpRequest {
 public:
  MockHttpRequest() = default;
  
  void SetUrl(const std::string& url) override { url_ = url; }
  void SetMethod(HttpMethod method) override { method_ = method; }
  void SetBody(const std::string& body) override { body_ = body; }
  void SetHeader(const std::string& key, const std::string& value) override { headers_[key] = value; }
  void SetHeaders(const std::unordered_map<std::string, std::string>& headers) override { headers_ = headers; }
  void SetTimeout(long timeout_ms) override { timeout_ms_ = timeout_ms; }
  void SetClientCert(const std::string& cert_path, const std::string& key_path) override {
    client_cert_path_ = cert_path;
    client_key_path_ = key_path;
  }
  void SetCACert(const std::string& ca_path) override { ca_path_ = ca_path; }
  void SetVerifyPeer(bool verify) override { verify_peer_ = verify; }
  void SetFollowRedirects(bool follow) override { follow_redirects_ = follow; }
    // Getters for internal use
  const std::string& GetUrl() const { return url_; }
  HttpMethod GetMethod() const { return method_; }
  const std::string& GetBody() const { return body_; }
  const std::unordered_map<std::string, std::string>& GetHeaders() const { return headers_; }
  long GetTimeout() const { return timeout_ms_; }
  const std::string& GetClientCertPath() const { return client_cert_path_; }
  const std::string& GetClientKeyPath() const { return client_key_path_; }
  const std::string& GetCACertPath() const { return ca_path_; }
  bool GetVerifyPeer() const { return verify_peer_; }
  bool GetFollowRedirects() const { return follow_redirects_; }

 private:
  std::string url_;
  HttpMethod method_ = HttpMethod::kGet;
  std::unordered_map<std::string, std::string> headers_;
  std::string body_;
  long timeout_ms_ = 10000;
  std::string client_cert_path_;
  std::string client_key_path_;
  std::string ca_path_;
  bool verify_peer_ = true;
  bool follow_redirects_ = true;
};

// Request matcher for setting up mock responses
struct RequestMatcher {
  std::string url_pattern;
  HttpMethod method = HttpMethod::kGet;
  std::unordered_map<std::string, std::string> required_headers;
  std::string body_pattern;
  
  bool Matches(const HttpRequest& request) const;
};

// Mock HTTP Client implementation
class HttpClientMock : public HttpClient {
 public:
  HttpClientMock();
  ~HttpClientMock() override = default;

  // HttpClient implementation
  std::unique_ptr<HttpResponse> Execute(const HttpRequest& request) override;
  std::unique_ptr<HttpResponse> Get(const std::string& url, const std::unordered_map<std::string, std::string>& headers = {}) override;
  std::unique_ptr<HttpResponse> Post(const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers = {}) override;
  std::unique_ptr<HttpResponse> Put(const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers = {}) override;
  std::unique_ptr<HttpResponse> Delete(const std::string& url, const std::unordered_map<std::string, std::string>& headers = {}) override;
  
  // Configuration methods
  void SetDefaultTimeout(long timeout_ms) override;
  void SetDefaultHeaders(const std::unordered_map<std::string, std::string>& headers) override;
  void SetClientCertificate(const std::string& cert_path, const std::string& key_path) override;
  void SetCACertificate(const std::string& ca_path) override;
  void SetVerifyPeer(bool verify) override;
  
  // Connection health
  bool Ping(const std::string& url) override;

  // Mock-specific methods for testing
  void AddResponse(std::unique_ptr<MockHttpResponse> response);
  void AddResponses(std::vector<std::unique_ptr<MockHttpResponse>> responses);
  void SetDefaultResponse(std::unique_ptr<MockHttpResponse> response);
  void ClearResponses();
  
  // Request recording
  void EnableRequestRecording(bool enable = true);
  const std::vector<std::unique_ptr<MockHttpRequest>>& GetRecordedRequests() const;
  void ClearRecordedRequests();
  
  // Error simulation
  void SimulateNetworkError(bool simulate = true, const std::string& error_message = "Mock network error");
  void SetLatencySimulation(std::chrono::milliseconds latency);
  void SetFailureRate(double rate);
  
  // Convenience methods for common responses
  void AddJsonResponse(int status_code, const std::string& json_body);
  void AddSuccessResponse(const std::string& body = "OK");
  void AddErrorResponse(int status_code, const std::string& error_body = "Error");
  void AddNotFoundResponse();
  void AddServerErrorResponse();
  void AddUnauthorizedResponse();
  
  // State inspection
  size_t GetQueuedResponseCount() const;
  bool IsRecordingRequests() const { return record_requests_; }
  bool IsSimulatingNetworkError() const { return simulate_network_error_; }

 private:
  mutable std::mutex request_mutex_;
  
  // Queue of pre-configured responses
  std::queue<std::unique_ptr<MockHttpResponse>> response_queue_;
  
  // Default response for when queue is empty
  std::unique_ptr<MockHttpResponse> default_response_;
  
  // Configuration
  std::unordered_map<std::string, std::string> default_headers_;
  long default_timeout_ = 10000;
  std::string default_client_cert_path_;
  std::string default_client_key_path_;
  std::string default_ca_cert_path_;
  bool default_verify_peer_ = true;
  
  // Recording functionality
  std::vector<std::unique_ptr<MockHttpRequest>> recorded_requests_;
  bool record_requests_ = false;
  
  // Failure simulation
  bool simulate_network_error_ = false;
  std::string network_error_message_ = "Mock network error";
  std::chrono::milliseconds simulated_latency_{0};
  double failure_rate_ = 0.0;
  
  // Helper methods
  std::unique_ptr<MockHttpResponse> CreateMockResponse(int status_code, const std::string& body, 
                                                       const std::unordered_map<std::string, std::string>& headers = {});
  void RecordRequest(const HttpRequest& request);
  bool ShouldSimulateFailure() const;
};

}  // namespace mocks
}  // namespace infra
}  // namespace coyote