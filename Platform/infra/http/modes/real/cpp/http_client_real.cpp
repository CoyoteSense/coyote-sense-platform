#include "HttpClient.h"
#include <iostream>
#include <sstream>
#include <algorithm>

namespace coyote {
namespace infra {

// HttpResponse implementation
HttpResponse::HttpResponse(int statusCode, const std::string& body, const std::unordered_map<std::string, std::string>& headers, const std::string& errorMessage)
    : m_statusCode(statusCode), m_body(body), m_headers(headers), m_errorMessage(errorMessage) {
}

// CurlHttpClient implementation
CurlHttpClient::CurlHttpClient() 
    : m_defaultTimeout(10000), m_defaultVerifyPeer(true) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    m_curl = curl_easy_init();
    
    if (!m_curl) {
        throw std::runtime_error("Failed to initialize CURL");
    }
}

CurlHttpClient::~CurlHttpClient() {
    if (m_curl) {
        curl_easy_cleanup(m_curl);
    }
    curl_global_cleanup();
}

std::unique_ptr<IHttpResponse> CurlHttpClient::execute(const IHttpRequest& request) {
    const auto& httpRequest = static_cast<const HttpRequest&>(request);
    
    std::string responseBody;
    std::unordered_map<std::string, std::string> responseHeaders;
    long responseCode = 0;
    
    // Setup CURL for this request
    setupCurlForRequest(m_curl, httpRequest);
    
    // Set callbacks for response data
    curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &responseBody);
    curl_easy_setopt(m_curl, CURLOPT_HEADERFUNCTION, headerCallback);
    curl_easy_setopt(m_curl, CURLOPT_HEADERDATA, &responseHeaders);
    
    // Execute the request
    CURLcode res = curl_easy_perform(m_curl);
    
    std::string errorMessage;
    if (res != CURLE_OK) {
        errorMessage = curl_easy_strerror(res);
        std::cerr << "CURL error: " << errorMessage << std::endl;
        return std::make_unique<HttpResponse>(0, "", responseHeaders, errorMessage);
    }
    
    // Get response code
    curl_easy_getinfo(m_curl, CURLINFO_RESPONSE_CODE, &responseCode);
    
    return std::make_unique<HttpResponse>(static_cast<int>(responseCode), responseBody, responseHeaders);
}

std::unique_ptr<IHttpResponse> CurlHttpClient::get(const std::string& url, const std::unordered_map<std::string, std::string>& headers) {
    HttpRequest request;
    request.setUrl(url);
    request.setMethod(HttpMethod::GET);
    request.setHeaders(headers);
    return execute(request);
}

std::unique_ptr<IHttpResponse> CurlHttpClient::post(const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers) {
    HttpRequest request;
    request.setUrl(url);
    request.setMethod(HttpMethod::POST);
    request.setBody(body);
    request.setHeaders(headers);
    return execute(request);
}

std::unique_ptr<IHttpResponse> CurlHttpClient::put(const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers) {
    HttpRequest request;
    request.setUrl(url);
    request.setMethod(HttpMethod::PUT);
    request.setBody(body);
    request.setHeaders(headers);
    return execute(request);
}

std::unique_ptr<IHttpResponse> CurlHttpClient::del(const std::string& url, const std::unordered_map<std::string, std::string>& headers) {
    HttpRequest request;
    request.setUrl(url);
    request.setMethod(HttpMethod::DELETE);
    request.setHeaders(headers);
    return execute(request);
}

void CurlHttpClient::setDefaultTimeout(long timeoutMs) {
    m_defaultTimeout = timeoutMs;
}

void CurlHttpClient::setDefaultHeaders(const std::unordered_map<std::string, std::string>& headers) {
    m_defaultHeaders = headers;
}

void CurlHttpClient::setClientCertificate(const std::string& certPath, const std::string& keyPath) {
    m_defaultClientCertPath = certPath;
    m_defaultClientKeyPath = keyPath;
}

void CurlHttpClient::setCACertificate(const std::string& caPath) {
    m_defaultCACertPath = caPath;
}

void CurlHttpClient::setVerifyPeer(bool verify) {
    m_defaultVerifyPeer = verify;
}

bool CurlHttpClient::ping(const std::string& url) {
    try {
        auto response = get(url + "/health");
        return response && response->isSuccess();
    } catch (...) {
        return false;
    }
}

void CurlHttpClient::setupCurlForRequest(CURL* curl, const HttpRequest& request) {
    // Reset curl handle
    curl_easy_reset(curl);
    
    // Set URL
    curl_easy_setopt(curl, CURLOPT_URL, request.getUrl().c_str());
    
    // Set HTTP method
    switch (request.getMethod()) {
        case HttpMethod::GET:
            curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
            break;
        case HttpMethod::POST:
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            if (!request.getBody().empty()) {
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.getBody().c_str());
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, request.getBody().size());
            }
            break;
        case HttpMethod::PUT:
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
            if (!request.getBody().empty()) {
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.getBody().c_str());
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, request.getBody().size());
            }
            break;
        case HttpMethod::DELETE:
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
            break;
        case HttpMethod::PATCH:
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
            if (!request.getBody().empty()) {
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.getBody().c_str());
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, request.getBody().size());
            }
            break;
        case HttpMethod::HEAD:
            curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
            break;
        case HttpMethod::OPTIONS:
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "OPTIONS");
            break;
    }
    
    // Set timeout
    long timeout = request.getTimeout() > 0 ? request.getTimeout() : m_defaultTimeout;
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout);
    
    // Set headers
    struct curl_slist* headers = nullptr;
    
    // Add default headers first
    for (const auto& [key, value] : m_defaultHeaders) {
        std::string header = key + ": " + value;
        headers = curl_slist_append(headers, header.c_str());
    }
    
    // Add request-specific headers (will override defaults)
    for (const auto& [key, value] : request.getHeaders()) {
        std::string header = key + ": " + value;
        headers = curl_slist_append(headers, header.c_str());
    }
    
    if (headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }
    
    // SSL/TLS configuration
    std::string caCertPath = !request.getCACertPath().empty() ? request.getCACertPath() : m_defaultCACertPath;
    std::string clientCertPath = !request.getClientCertPath().empty() ? request.getClientCertPath() : m_defaultClientCertPath;
    std::string clientKeyPath = !request.getClientKeyPath().empty() ? request.getClientKeyPath() : m_defaultClientKeyPath;
    
    if (!caCertPath.empty()) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, caCertPath.c_str());
    }
    
    if (!clientCertPath.empty()) {
        curl_easy_setopt(curl, CURLOPT_SSLCERT, clientCertPath.c_str());
    }
    
    if (!clientKeyPath.empty()) {
        curl_easy_setopt(curl, CURLOPT_SSLKEY, clientKeyPath.c_str());
    }
    
    // Set peer verification
    bool verifyPeer = request.getVerifyPeer();
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verifyPeer ? 1L : 0L);
    
    // Set follow redirects
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, request.getFollowRedirects() ? 1L : 0L);
    
    // Enable verbose output for debugging (can be controlled by environment variable)
    if (getenv("CURL_VERBOSE")) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    }
}

std::string CurlHttpClient::getHttpMethodString(HttpMethod method) {
    switch (method) {
        case HttpMethod::GET: return "GET";
        case HttpMethod::POST: return "POST";
        case HttpMethod::PUT: return "PUT";
        case HttpMethod::DELETE: return "DELETE";
        case HttpMethod::PATCH: return "PATCH";
        case HttpMethod::HEAD: return "HEAD";
        case HttpMethod::OPTIONS: return "OPTIONS";
        default: return "GET";
    }
}

size_t CurlHttpClient::writeCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    size_t totalSize = size * nmemb;
    userp->append(static_cast<char*>(contents), totalSize);
    return totalSize;
}

size_t CurlHttpClient::headerCallback(char* buffer, size_t size, size_t nitems, std::unordered_map<std::string, std::string>* userp) {
    size_t totalSize = size * nitems;
    std::string header(buffer, totalSize);
    
    // Parse header line
    size_t colonPos = header.find(':');
    if (colonPos != std::string::npos && colonPos > 0) {
        std::string key = header.substr(0, colonPos);
        std::string value = header.substr(colonPos + 1);
        
        // Trim whitespace
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t\r\n") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t\r\n") + 1);
        
        // Convert key to lowercase for consistent access
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        
        (*userp)[key] = value;
    }
    
    return totalSize;
}

} // namespace infra
} // namespace coyote
