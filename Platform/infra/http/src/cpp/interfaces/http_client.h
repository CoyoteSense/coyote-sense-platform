#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace coyote {
namespace infra {

// HTTP method enumeration
enum class HttpMethod {
  kGet,
  kPost,
  kPut,
  kDelete,
  kPatch,
  kHead,
  kOptions
};

// HTTP response interface
class HttpResponse {
 public:
  virtual ~HttpResponse() = default;
  virtual int GetStatusCode() const = 0;
  virtual const std::string& GetBody() const = 0;
  virtual const std::unordered_map<std::string, std::string>& GetHeaders() const = 0;
  virtual bool IsSuccess() const = 0;
  virtual const std::string& GetErrorMessage() const = 0;
};

// HTTP request interface
class HttpRequest {
 public:
  virtual ~HttpRequest() = default;
  virtual void SetUrl(const std::string& url) = 0;
  virtual void SetMethod(HttpMethod method) = 0;
  virtual void SetBody(const std::string& body) = 0;
  virtual void SetHeader(const std::string& key, const std::string& value) = 0;
  virtual void SetHeaders(const std::unordered_map<std::string, std::string>& headers) = 0;
  virtual void SetTimeout(long timeout_ms) = 0;
  virtual void SetClientCert(const std::string& cert_path, const std::string& key_path) = 0;
  virtual void SetCACert(const std::string& ca_path) = 0;
  virtual void SetVerifyPeer(bool verify) = 0;
  virtual void SetFollowRedirects(bool follow) = 0;
};

// HTTP client interface
class HttpClient {
 public:
  virtual ~HttpClient() = default;
  
  // Synchronous request methods
  virtual std::unique_ptr<HttpResponse> Execute(const HttpRequest& request) = 0;
  virtual std::unique_ptr<HttpResponse> Get(const std::string& url, const std::unordered_map<std::string, std::string>& headers = {}) = 0;
  virtual std::unique_ptr<HttpResponse> Post(const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers = {}) = 0;
  virtual std::unique_ptr<HttpResponse> Put(const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers = {}) = 0;
  virtual std::unique_ptr<HttpResponse> Delete(const std::string& url, const std::unordered_map<std::string, std::string>& headers = {}) = 0;
  
  // Configuration methods
  virtual void SetDefaultTimeout(long timeout_ms) = 0;
  virtual void SetDefaultHeaders(const std::unordered_map<std::string, std::string>& headers) = 0;
  virtual void SetClientCertificate(const std::string& cert_path, const std::string& key_path) = 0;
  virtual void SetCACertificate(const std::string& ca_path) = 0;
  virtual void SetVerifyPeer(bool verify) = 0;
  
  // Connection health
  virtual bool Ping(const std::string& url) = 0;
};

}  // namespace infra
}  // namespace coyote