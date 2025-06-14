#pragma once

#include "http_client.h"

#ifndef CURL_NOT_AVAILABLE
#include <curl/curl.h>
#endif

#include <memory>
#include <string>
#include <unordered_map>

namespace coyote {
namespace infra {

// HTTP response implementation
class HttpResponseReal : public HttpResponse {
 public:
  HttpResponseReal(int status_code, const std::string& body, 
                   const std::unordered_map<std::string, std::string>& headers, 
                   const std::string& error_message = "");
  
  int GetStatusCode() const override { return status_code_; }
  const std::string& GetBody() const override { return body_; }
  const std::unordered_map<std::string, std::string>& GetHeaders() const override { return headers_; }
  bool IsSuccess() const override { return status_code_ >= 200 && status_code_ < 300; }
  const std::string& GetErrorMessage() const override { return error_message_; }

 private:
  int status_code_;
  std::string body_;
  std::unordered_map<std::string, std::string> headers_;
  std::string error_message_;
};

// HTTP request implementation
class HttpRequestReal : public HttpRequest {
 public:
  HttpRequestReal() = default;
  
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
  std::string body_;
  std::unordered_map<std::string, std::string> headers_;
  long timeout_ms_ = 10000;
  std::string client_cert_path_;
  std::string client_key_path_;
  std::string ca_path_;
  bool verify_peer_ = true;
  bool follow_redirects_ = true;
};

// CURL-based HTTP client implementation
class HttpClientReal : public HttpClient {
 public:
  HttpClientReal();
  ~HttpClientReal() override;
  
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
 private:
#ifndef CURL_NOT_AVAILABLE
  CURL* curl_;
#endif
  long default_timeout_;
  std::unordered_map<std::string, std::string> default_headers_;
  std::string default_client_cert_path_;
  std::string default_client_key_path_;
  std::string default_ca_cert_path_;
  bool default_verify_peer_;
  
  // Helper methods
#ifndef CURL_NOT_AVAILABLE
  void SetupCurlForRequest(CURL* curl, const HttpRequestReal& request);
#endif
  std::string GetHttpMethodString(HttpMethod method);
#ifndef CURL_NOT_AVAILABLE
  static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp);
  static size_t HeaderCallback(char* buffer, size_t size, size_t nitems, std::unordered_map<std::string, std::string>* userp);
#endif
};

}  // namespace infra
}  // namespace coyote