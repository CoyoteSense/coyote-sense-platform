#pragma once

#include "IHttpClient.h"
#include <curl/curl.h>
#include <memory>
#include <string>
#include <unordered_map>

namespace coyote {
namespace infra {

// HTTP response implementation
class HttpResponse : public IHttpResponse {
public:
    HttpResponse(int statusCode, const std::string& body, const std::unordered_map<std::string, std::string>& headers, const std::string& errorMessage = "");
    
    int getStatusCode() const override { return m_statusCode; }
    const std::string& getBody() const override { return m_body; }
    const std::unordered_map<std::string, std::string>& getHeaders() const override { return m_headers; }
    bool isSuccess() const override { return m_statusCode >= 200 && m_statusCode < 300; }
    const std::string& getErrorMessage() const override { return m_errorMessage; }

private:
    int m_statusCode;
    std::string m_body;
    std::unordered_map<std::string, std::string> m_headers;
    std::string m_errorMessage;
};

// HTTP request implementation
class HttpRequest : public IHttpRequest {
public:
    HttpRequest() = default;
    
    void setUrl(const std::string& url) override { m_url = url; }
    void setMethod(HttpMethod method) override { m_method = method; }
    void setBody(const std::string& body) override { m_body = body; }
    void setHeader(const std::string& key, const std::string& value) override { m_headers[key] = value; }
    void setHeaders(const std::unordered_map<std::string, std::string>& headers) override { m_headers = headers; }
    void setTimeout(long timeoutMs) override { m_timeoutMs = timeoutMs; }
    void setClientCert(const std::string& certPath, const std::string& keyPath) override { 
        m_clientCertPath = certPath; 
        m_clientKeyPath = keyPath; 
    }
    void setCACert(const std::string& caPath) override { m_caPath = caPath; }
    void setVerifyPeer(bool verify) override { m_verifyPeer = verify; }
    void setFollowRedirects(bool follow) override { m_followRedirects = follow; }
    
    // Getters for internal use
    const std::string& getUrl() const { return m_url; }
    HttpMethod getMethod() const { return m_method; }
    const std::string& getBody() const { return m_body; }
    const std::unordered_map<std::string, std::string>& getHeaders() const { return m_headers; }
    long getTimeout() const { return m_timeoutMs; }
    const std::string& getClientCertPath() const { return m_clientCertPath; }
    const std::string& getClientKeyPath() const { return m_clientKeyPath; }
    const std::string& getCACertPath() const { return m_caPath; }
    bool getVerifyPeer() const { return m_verifyPeer; }
    bool getFollowRedirects() const { return m_followRedirects; }

private:
    std::string m_url;
    HttpMethod m_method = HttpMethod::GET;
    std::string m_body;
    std::unordered_map<std::string, std::string> m_headers;
    long m_timeoutMs = 10000;
    std::string m_clientCertPath;
    std::string m_clientKeyPath;
    std::string m_caPath;
    bool m_verifyPeer = true;
    bool m_followRedirects = true;
};

// CURL-based HTTP client implementation
class CurlHttpClient : public IHttpClient {
public:
    CurlHttpClient();
    ~CurlHttpClient() override;
    
    // IHttpClient implementation
    std::unique_ptr<IHttpResponse> execute(const IHttpRequest& request) override;
    std::unique_ptr<IHttpResponse> get(const std::string& url, const std::unordered_map<std::string, std::string>& headers = {}) override;
    std::unique_ptr<IHttpResponse> post(const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers = {}) override;
    std::unique_ptr<IHttpResponse> put(const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers = {}) override;
    std::unique_ptr<IHttpResponse> del(const std::string& url, const std::unordered_map<std::string, std::string>& headers = {}) override;
    
    // Configuration methods
    void setDefaultTimeout(long timeoutMs) override;
    void setDefaultHeaders(const std::unordered_map<std::string, std::string>& headers) override;
    void setClientCertificate(const std::string& certPath, const std::string& keyPath) override;
    void setCACertificate(const std::string& caPath) override;
    void setVerifyPeer(bool verify) override;
    
    // Connection health
    bool ping(const std::string& url) override;

private:
    CURL* m_curl;
    long m_defaultTimeout;
    std::unordered_map<std::string, std::string> m_defaultHeaders;
    std::string m_defaultClientCertPath;
    std::string m_defaultClientKeyPath;
    std::string m_defaultCACertPath;
    bool m_defaultVerifyPeer;
    
    // Helper methods
    void setupCurlForRequest(CURL* curl, const HttpRequest& request);
    std::string getHttpMethodString(HttpMethod method);
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, std::string* userp);
    static size_t headerCallback(char* buffer, size_t size, size_t nitems, std::unordered_map<std::string, std::string>* userp);
};

// Factory implementation for HTTP clients
class HttpClientFactory : public IHttpClientFactory {
public:
    std::unique_ptr<IHttpClient> createClient() override {
        return std::make_unique<CurlHttpClient>();
    }
};

} // namespace infra
} // namespace coyote
