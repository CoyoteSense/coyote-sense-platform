#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <memory>

namespace coyote {
namespace infra {

// HTTP method enumeration
enum class HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS
};

// HTTP response structure
struct IHttpResponse {
    virtual ~IHttpResponse() = default;
    virtual int getStatusCode() const = 0;
    virtual const std::string& getBody() const = 0;
    virtual const std::unordered_map<std::string, std::string>& getHeaders() const = 0;
    virtual bool isSuccess() const = 0;
    virtual const std::string& getErrorMessage() const = 0;
};

// HTTP request structure
struct IHttpRequest {
    virtual ~IHttpRequest() = default;
    virtual void setUrl(const std::string& url) = 0;
    virtual void setMethod(HttpMethod method) = 0;
    virtual void setBody(const std::string& body) = 0;
    virtual void setHeader(const std::string& key, const std::string& value) = 0;
    virtual void setHeaders(const std::unordered_map<std::string, std::string>& headers) = 0;
    virtual void setTimeout(long timeoutMs) = 0;
    virtual void setClientCert(const std::string& certPath, const std::string& keyPath) = 0;
    virtual void setCACert(const std::string& caPath) = 0;
    virtual void setVerifyPeer(bool verify) = 0;
    virtual void setFollowRedirects(bool follow) = 0;
};

// HTTP client interface
class IHttpClient {
public:
    virtual ~IHttpClient() = default;
    
    // Synchronous request methods
    virtual std::unique_ptr<IHttpResponse> execute(const IHttpRequest& request) = 0;
    virtual std::unique_ptr<IHttpResponse> get(const std::string& url, const std::unordered_map<std::string, std::string>& headers = {}) = 0;
    virtual std::unique_ptr<IHttpResponse> post(const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers = {}) = 0;
    virtual std::unique_ptr<IHttpResponse> put(const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers = {}) = 0;
    virtual std::unique_ptr<IHttpResponse> del(const std::string& url, const std::unordered_map<std::string, std::string>& headers = {}) = 0;
    
    // Configuration methods
    virtual void setDefaultTimeout(long timeoutMs) = 0;
    virtual void setDefaultHeaders(const std::unordered_map<std::string, std::string>& headers) = 0;
    virtual void setClientCertificate(const std::string& certPath, const std::string& keyPath) = 0;
    virtual void setCACertificate(const std::string& caPath) = 0;
    virtual void setVerifyPeer(bool verify) = 0;
    
    // Connection health
    virtual bool ping(const std::string& url) = 0;
};

// Factory for creating HTTP clients
class IHttpClientFactory {
public:
    virtual ~IHttpClientFactory() = default;
    virtual std::unique_ptr<IHttpClient> createClient() = 0;
};

} // namespace infra
} // namespace coyote
