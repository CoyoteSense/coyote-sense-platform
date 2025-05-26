#include "http_client_real.h"
#include <iostream>
#include <sstream>
#include <algorithm>

#ifndef CURL_NOT_AVAILABLE

namespace coyote {
namespace infra {

// HttpResponseReal implementation
HttpResponseReal::HttpResponseReal(int status_code, const std::string& body, 
                                   const std::unordered_map<std::string, std::string>& headers, 
                                   const std::string& error_message)
    : status_code_(status_code), body_(body), headers_(headers), error_message_(error_message) {
}

// HttpClientReal implementation
HttpClientReal::HttpClientReal() 
    : default_timeout_(10000), default_verify_peer_(true) {
  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl_ = curl_easy_init();
  
  if (!curl_) {
    throw std::runtime_error("Failed to initialize CURL");
  }
}

HttpClientReal::~HttpClientReal() {
  if (curl_) {
    curl_easy_cleanup(curl_);
  }
  curl_global_cleanup();
}

std::unique_ptr<HttpResponse> HttpClientReal::Execute(const HttpRequest& request) {
  const auto& http_request = static_cast<const HttpRequestReal&>(request);
  
  std::string response_body;
  std::unordered_map<std::string, std::string> response_headers;
  long response_code = 0;
  
  // Setup CURL for this request
  SetupCurlForRequest(curl_, http_request);
  
  // Set callbacks for response data
  curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, WriteCallback);
  curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response_body);
  curl_easy_setopt(curl_, CURLOPT_HEADERFUNCTION, HeaderCallback);
  curl_easy_setopt(curl_, CURLOPT_HEADERDATA, &response_headers);
  
  // Execute the request
  CURLcode res = curl_easy_perform(curl_);
    std::string error_message;
  if (res != CURLE_OK) {
    error_message = curl_easy_strerror(res);
    std::cerr << "CURL error: " << error_message << std::endl;
    return std::make_unique<HttpResponseReal>(0, "", response_headers, error_message);
  }
  
  // Get response code
  curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &response_code);
  
  return std::make_unique<HttpResponseReal>(static_cast<int>(response_code), response_body, response_headers);
}

std::unique_ptr<HttpResponse> HttpClientReal::Get(const std::string& url, const std::unordered_map<std::string, std::string>& headers) {
  HttpRequestReal request;
  request.SetUrl(url);
  request.SetMethod(HttpMethod::kGet);
  request.SetHeaders(headers);
  return Execute(request);
}

std::unique_ptr<HttpResponse> HttpClientReal::Post(const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers) {
  HttpRequestReal request;
  request.SetUrl(url);
  request.SetMethod(HttpMethod::kPost);
  request.SetBody(body);
  request.SetHeaders(headers);
  return Execute(request);
}

std::unique_ptr<HttpResponse> HttpClientReal::Put(const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers) {
  HttpRequestReal request;
  request.SetUrl(url);
  request.SetMethod(HttpMethod::kPut);
  request.SetBody(body);
  request.SetHeaders(headers);
  return Execute(request);
}

std::unique_ptr<HttpResponse> HttpClientReal::Delete(const std::string& url, const std::unordered_map<std::string, std::string>& headers) {
  HttpRequestReal request;
  request.SetUrl(url);
  request.SetMethod(HttpMethod::kDelete);
  request.SetHeaders(headers);
  return Execute(request);
}

void HttpClientReal::SetDefaultTimeout(long timeout_ms) {
  default_timeout_ = timeout_ms;
}

void HttpClientReal::SetDefaultHeaders(const std::unordered_map<std::string, std::string>& headers) {
  default_headers_ = headers;
}

void HttpClientReal::SetClientCertificate(const std::string& cert_path, const std::string& key_path) {
  default_client_cert_path_ = cert_path;
  default_client_key_path_ = key_path;
}

void HttpClientReal::SetCACertificate(const std::string& ca_path) {
  default_ca_cert_path_ = ca_path;
}

void HttpClientReal::SetVerifyPeer(bool verify) {
  default_verify_peer_ = verify;
}

bool HttpClientReal::Ping(const std::string& url) {
  try {
    auto response = Get(url + "/health");
    return response && response->IsSuccess();
  } catch (...) {
    return false;
  }
}

void HttpClientReal::SetupCurlForRequest(CURL* curl, const HttpRequestReal& request) {
    // Reset curl handle
    curl_easy_reset(curl);
    
    // Set URL
    curl_easy_setopt(curl, CURLOPT_URL, request.GetUrl().c_str());
    
    // Set HTTP method
    switch (request.GetMethod()) {
        case HttpMethod::kGet:
            curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
            break;
        case HttpMethod::kPost:
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            if (!request.GetBody().empty()) {
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.GetBody().c_str());
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, request.GetBody().size());
            }
            break;
        case HttpMethod::kPut:
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
            if (!request.GetBody().empty()) {
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.GetBody().c_str());                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, request.GetBody().size());
            }
            break;
        case HttpMethod::kDelete:
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
            break;
        case HttpMethod::kPatch:
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
            if (!request.GetBody().empty()) {
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.GetBody().c_str());
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, request.GetBody().size());
            }
            break;
        case HttpMethod::kHead:
            curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
            break;
        case HttpMethod::kOptions:
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "OPTIONS");
            break;
    }
      // Set timeout
  long timeout = request.GetTimeout() > 0 ? request.GetTimeout() : default_timeout_;
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout);
  
  // Set headers
  struct curl_slist* headers = nullptr;
  
  // Add default headers first
  for (const auto& [key, value] : default_headers_) {
    std::string header = key + ": " + value;
    headers = curl_slist_append(headers, header.c_str());
  }
  
  // Add request-specific headers (will override defaults)
  for (const auto& [key, value] : request.GetHeaders()) {
    std::string header = key + ": " + value;
    headers = curl_slist_append(headers, header.c_str());
  }
  
  if (headers) {
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  }
  
  // SSL/TLS configuration
  std::string ca_cert_path = !request.GetCACertPath().empty() ? request.GetCACertPath() : default_ca_cert_path_;
  std::string client_cert_path = !request.GetClientCertPath().empty() ? request.GetClientCertPath() : default_client_cert_path_;
  std::string client_key_path = !request.GetClientKeyPath().empty() ? request.GetClientKeyPath() : default_client_key_path_;
  
  if (!ca_cert_path.empty()) {
    curl_easy_setopt(curl, CURLOPT_CAINFO, ca_cert_path.c_str());
  }
  
  if (!client_cert_path.empty()) {
    curl_easy_setopt(curl, CURLOPT_SSLCERT, client_cert_path.c_str());
  }
  
  if (!client_key_path.empty()) {
    curl_easy_setopt(curl, CURLOPT_SSLKEY, client_key_path.c_str());
  }
    // Set peer verification
  bool verify_peer = request.GetVerifyPeer();
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify_peer ? 1L : 0L);
  
  // Set follow redirects
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, request.GetFollowRedirects() ? 1L : 0L);
  
  // Enable verbose output for debugging (can be controlled by environment variable)
  if (getenv("CURL_VERBOSE")) {
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  }
}

std::string HttpClientReal::GetHttpMethodString(HttpMethod method) {
  switch (method) {
    case HttpMethod::kGet: return "GET";
    case HttpMethod::kPost: return "POST";
    case HttpMethod::kPut: return "PUT";
    case HttpMethod::kDelete: return "DELETE";
    case HttpMethod::kPatch: return "PATCH";
    case HttpMethod::kHead: return "HEAD";
    case HttpMethod::kOptions: return "OPTIONS";
    default: return "GET";
  }
}

size_t HttpClientReal::WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
  size_t total_size = size * nmemb;
  userp->append(static_cast<char*>(contents), total_size);
  return total_size;
}

size_t HttpClientReal::HeaderCallback(char* buffer, size_t size, size_t nitems, std::unordered_map<std::string, std::string>* userp) {
  size_t total_size = size * nitems;
  std::string header(buffer, total_size);
  
  // Parse header line
  size_t colon_pos = header.find(':');
  if (colon_pos != std::string::npos && colon_pos > 0) {
    std::string key = header.substr(0, colon_pos);
    std::string value = header.substr(colon_pos + 1);
    
    // Trim whitespace
    key.erase(0, key.find_first_not_of(" \t"));
    key.erase(key.find_last_not_of(" \t\r\n") + 1);
    value.erase(0, value.find_first_not_of(" \t"));
    value.erase(value.find_last_not_of(" \t\r\n") + 1);
    
    // Convert key to lowercase for consistent access
    std::transform(key.begin(), key.end(), key.begin(), ::tolower);
    
    (*userp)[key] = value;
  }
    return total_size;
}

}  // namespace infra
}  // namespace coyote

#else  // CURL_NOT_AVAILABLE

// Stub implementation when CURL is not available
namespace coyote {
namespace infra {

HttpResponseReal::HttpResponseReal(int status_code, const std::string& body, 
                                   const std::unordered_map<std::string, std::string>& headers, 
                                   const std::string& error_message)
    : status_code_(status_code), body_(body), headers_(headers), error_message_(error_message) {
}

HttpClientReal::HttpClientReal() : default_timeout_(10000), default_verify_peer_(true) {
  throw std::runtime_error("HttpClientReal: libcurl not available in this build");
}

HttpClientReal::~HttpClientReal() = default;

std::unique_ptr<HttpResponse> HttpClientReal::Execute(const HttpRequest& request) {
  throw std::runtime_error("HttpClientReal: libcurl not available in this build");
}

std::unique_ptr<HttpResponse> HttpClientReal::Get(const std::string& url, const std::unordered_map<std::string, std::string>& headers) {
  throw std::runtime_error("HttpClientReal: libcurl not available in this build");
}

std::unique_ptr<HttpResponse> HttpClientReal::Post(const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers) {
  throw std::runtime_error("HttpClientReal: libcurl not available in this build");
}

std::unique_ptr<HttpResponse> HttpClientReal::Put(const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers) {
  throw std::runtime_error("HttpClientReal: libcurl not available in this build");
}

std::unique_ptr<HttpResponse> HttpClientReal::Delete(const std::string& url, const std::unordered_map<std::string, std::string>& headers) {
  throw std::runtime_error("HttpClientReal: libcurl not available in this build");
}

void HttpClientReal::SetDefaultTimeout(long timeout_ms) {}
void HttpClientReal::SetDefaultHeaders(const std::unordered_map<std::string, std::string>& headers) {}
void HttpClientReal::SetClientCertificate(const std::string& cert_path, const std::string& key_path) {}
void HttpClientReal::SetCACertificate(const std::string& ca_path) {}
void HttpClientReal::SetVerifyPeer(bool verify) {}
bool HttpClientReal::Ping(const std::string& url) { return false; }

}  // namespace infra
}  // namespace coyote

#endif  // CURL_NOT_AVAILABLE
