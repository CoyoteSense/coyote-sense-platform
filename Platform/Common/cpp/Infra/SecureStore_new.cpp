#include "SecureStore.h"
#include <iostream>
#include <sstream>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <chrono>
#include <cstring>
#include <thread>

namespace coyote {
namespace infra {

// CurlHttpClient implementation
CurlHttpClient::CurlHttpClient() : m_curl(nullptr) {
    // Initialize CURL globally (should be done once per application)
    static bool curlInitialized = false;
    if (!curlInitialized) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curlInitialized = true;
    }
    
    m_curl = curl_easy_init();
    if (!m_curl) {
        throw std::runtime_error("Failed to initialize CURL");
    }
}

CurlHttpClient::~CurlHttpClient() {
    if (m_curl) {
        curl_easy_cleanup(m_curl);
    }
}

size_t CurlHttpClient::writeCallback(void* contents, size_t size, size_t nmemb, std::string* response) {
    size_t totalSize = size * nmemb;
    response->append(static_cast<char*>(contents), totalSize);
    return totalSize;
}

size_t CurlHttpClient::headerCallback(char* buffer, size_t size, size_t nitems, 
                                      std::unordered_map<std::string, std::string>* headers) {
    size_t totalSize = size * nitems;
    std::string header(buffer, totalSize);
    
    // Parse header
    auto colonPos = header.find(':');
    if (colonPos != std::string::npos) {
        std::string key = header.substr(0, colonPos);
        std::string value = header.substr(colonPos + 1);
        
        // Trim whitespace
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \r\n\t") + 1);
        
        (*headers)[key] = value;
    }
    
    return totalSize;
}

HttpResponse CurlHttpClient::execute(const HttpRequest& request) {
    HttpResponse response;
    auto startTime = std::chrono::steady_clock::now();
    
    if (!m_curl) {
        response.error_message = "CURL not initialized";
        return response;
    }
    
    // Reset CURL handle
    curl_easy_reset(m_curl);
    
    // Set URL
    curl_easy_setopt(m_curl, CURLOPT_URL, request.url.c_str());
    
    // Set method
    if (request.method == "POST") {
        curl_easy_setopt(m_curl, CURLOPT_POST, 1L);
        curl_easy_setopt(m_curl, CURLOPT_POSTFIELDS, request.body.c_str());
        curl_easy_setopt(m_curl, CURLOPT_POSTFIELDSIZE, request.body.length());
    } else if (request.method == "PUT") {
        curl_easy_setopt(m_curl, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_easy_setopt(m_curl, CURLOPT_POSTFIELDS, request.body.c_str());
        curl_easy_setopt(m_curl, CURLOPT_POSTFIELDSIZE, request.body.length());
    } else if (request.method == "DELETE") {
        curl_easy_setopt(m_curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    }
    
    // Set headers
    struct curl_slist* headers = nullptr;
    
    // Add default headers
    for (const auto& header : m_defaultHeaders) {
        std::string headerStr = header.first + ": " + header.second;
        headers = curl_slist_append(headers, headerStr.c_str());
    }
    
    // Add request-specific headers
    for (const auto& header : request.headers) {
        std::string headerStr = header.first + ": " + header.second;
        headers = curl_slist_append(headers, headerStr.c_str());
    }
    
    if (headers) {
        curl_easy_setopt(m_curl, CURLOPT_HTTPHEADER, headers);
    }
    
    // Set SSL options
    if (!request.verify_ssl) {
        curl_easy_setopt(m_curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(m_curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    
    if (!request.ca_cert_path.empty()) {
        curl_easy_setopt(m_curl, CURLOPT_CAINFO, request.ca_cert_path.c_str());
    }
    
    if (!request.client_cert_path.empty()) {
        curl_easy_setopt(m_curl, CURLOPT_SSLCERT, request.client_cert_path.c_str());
    }
    
    if (!request.client_key_path.empty()) {
        curl_easy_setopt(m_curl, CURLOPT_SSLKEY, request.client_key_path.c_str());
    }
    
    // Set timeout
    curl_easy_setopt(m_curl, CURLOPT_TIMEOUT, static_cast<long>(request.timeout_seconds));
    
    // Set User-Agent
    if (!m_userAgent.empty()) {
        curl_easy_setopt(m_curl, CURLOPT_USERAGENT, m_userAgent.c_str());
    }
    
    // Set callbacks
    curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &response.body);
    curl_easy_setopt(m_curl, CURLOPT_HEADERFUNCTION, headerCallback);
    curl_easy_setopt(m_curl, CURLOPT_HEADERDATA, &response.headers);
    
    // Perform request
    CURLcode res = curl_easy_perform(m_curl);
    
    auto endTime = std::chrono::steady_clock::now();
    response.duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    
    if (res != CURLE_OK) {
        response.error_message = curl_easy_strerror(res);
        response.success = false;
    } else {
        long statusCode;
        curl_easy_getinfo(m_curl, CURLINFO_RESPONSE_CODE, &statusCode);
        response.status_code = static_cast<int>(statusCode);
        response.success = (statusCode >= 200 && statusCode < 300);
    }
    
    // Cleanup headers
    if (headers) {
        curl_slist_free_all(headers);
    }
    
    return response;
}

void CurlHttpClient::setUserAgent(const std::string& userAgent) {
    m_userAgent = userAgent;
}

void CurlHttpClient::setDefaultHeaders(const std::unordered_map<std::string, std::string>& headers) {
    m_defaultHeaders = headers;
}

// KeyVaultClient implementation
KeyVaultClient::KeyVaultClient(const std::string& vaultUrl, const std::string& unitId, 
                               std::shared_ptr<IHttpClient> httpClient)
    : m_vaultUrl(vaultUrl), m_unitId(unitId) {
    
    if (httpClient) {
        m_httpClient = httpClient;
    } else {
        m_httpClient = std::make_shared<CurlHttpClient>();
    }
    
    // Set default headers for KeyVault
    m_httpClient->setDefaultHeaders({
        {"Content-Type", "application/json"},
        {"Accept", "application/json"},
        {"X-Vault-Request", "true"}
    });
    
    m_httpClient->setUserAgent("CoyoteSense-BaseUnit/1.0");
    m_lastRequestTime = std::chrono::steady_clock::now();
}

KeyVaultClient::~KeyVaultClient() {
    clearSensitiveData();
}

bool KeyVaultClient::authenticate(const std::string& unitId, const std::string& credentials) {
    try {
        nlohmann::json authPayload;
        authPayload["role"] = unitId;
        authPayload["secret_id"] = credentials;

        auto response = makeHttpRequestWithRetry("POST", "/v1/auth/approle/login", authPayload.dump());
        if (!response.success) {
            std::cerr << "Authentication failed: " << response.error_message << std::endl;
            return false;
        }

        auto jsonResponse = nlohmann::json::parse(response.body);
        if (jsonResponse.contains("auth") && jsonResponse["auth"].contains("client_token")) {
            m_authToken = jsonResponse["auth"]["client_token"];
            
            // Update default headers with auth token
            auto headers = m_httpClient->setDefaultHeaders({
                {"Content-Type", "application/json"},
                {"Accept", "application/json"},
                {"X-Vault-Request", "true"},
                {"X-Vault-Token", m_authToken}
            });
            
            std::cout << "Successfully authenticated with KeyVault" << std::endl;
            return true;
        }
        
        std::cerr << "Invalid authentication response format" << std::endl;
        return false;
        
    } catch (const std::exception& e) {
        std::cerr << "Authentication error: " << e.what() << std::endl;
        return false;
    }
}

std::string KeyVaultClient::getAuthToken() const {
    return m_authToken;
}

bool KeyVaultClient::refreshToken() {
    if (m_authToken.empty()) {
        return false;
    }
    
    auto response = makeHttpRequestWithRetry("POST", "/v1/auth/token/renew-self", "{}");
    if (!response.success) {
        std::cerr << "Token refresh failed: " << response.error_message << std::endl;
        return false;
    }
    
    try {
        auto jsonResponse = nlohmann::json::parse(response.body);
        if (jsonResponse.contains("auth") && jsonResponse["auth"].contains("client_token")) {
            m_authToken = jsonResponse["auth"]["client_token"];
            
            // Update headers with new token
            m_httpClient->setDefaultHeaders({
                {"Content-Type", "application/json"},
                {"Accept", "application/json"},
                {"X-Vault-Request", "true"},
                {"X-Vault-Token", m_authToken}
            });
            
            return true;
        }
    } catch (const std::exception& e) {
        std::cerr << "Token refresh parse error: " << e.what() << std::endl;
    }
    
    return false;
}

std::string KeyVaultClient::getSecret(const std::string& path) {
    std::string endpoint = "/v1/secret/data/" + path;
    auto response = makeHttpRequestWithRetry("GET", endpoint);
    
    if (!response.success) {
        std::cerr << "Failed to get secret: " << response.error_message << std::endl;
        return "";
    }
    
    return parseSecretFromResponse(response.body);
}

bool KeyVaultClient::setSecret(const std::string& path, const std::string& value) {
    nlohmann::json payload;
    payload["data"]["value"] = value;
    
    std::string endpoint = "/v1/secret/data/" + path;
    auto response = makeHttpRequestWithRetry("POST", endpoint, payload.dump());
    
    if (!response.success) {
        std::cerr << "Failed to set secret: " << response.error_message << std::endl;
        return false;
    }
    
    return true;
}

bool KeyVaultClient::deleteSecret(const std::string& path) {
    std::string endpoint = "/v1/secret/data/" + path;
    auto response = makeHttpRequestWithRetry("DELETE", endpoint);
    
    if (!response.success) {
        std::cerr << "Failed to delete secret: " << response.error_message << std::endl;
        return false;
    }
    
    return true;
}

std::unordered_map<std::string, std::string> KeyVaultClient::getSecrets(const std::vector<std::string>& paths) {
    std::unordered_map<std::string, std::string> results;
    
    for (const auto& path : paths) {
        std::string secret = getSecret(path);
        if (!secret.empty()) {
            results[path] = secret;
        }
    }
    
    return results;
}

bool KeyVaultClient::isConnected() const {
    return !m_authToken.empty();
}

void KeyVaultClient::disconnect() {
    clearSensitiveData();
}

bool KeyVaultClient::ping() {
    auto response = makeHttpRequest("GET", "/v1/sys/health");
    return response.success && response.status_code == 200;
}

std::unordered_map<std::string, std::string> KeyVaultClient::getMetrics() {
    std::lock_guard<std::mutex> lock(m_metricsMutex);
    
    auto now = std::chrono::steady_clock::now();
    auto timeSinceLastRequest = std::chrono::duration_cast<std::chrono::seconds>(now - m_lastRequestTime);
    
    return {
        {"total_requests", std::to_string(m_requestCount.load())},
        {"successful_requests", std::to_string(m_successCount.load())},
        {"failed_requests", std::to_string(m_errorCount.load())},
        {"success_rate", std::to_string(m_requestCount > 0 ? 
            (double(m_successCount) / double(m_requestCount)) * 100.0 : 0.0)},
        {"seconds_since_last_request", std::to_string(timeSinceLastRequest.count())}
    };
}

void KeyVaultClient::setCertificatePaths(const std::string& caPath, const std::string& clientCertPath, 
                                         const std::string& clientKeyPath) {
    m_caPath = caPath;
    m_clientCertPath = clientCertPath;
    m_clientKeyPath = clientKeyPath;
    m_useMutualTLS = !clientCertPath.empty() && !clientKeyPath.empty();
}

void KeyVaultClient::setRetryPolicy(int maxRetries, std::chrono::milliseconds retryDelay) {
    m_maxRetries = maxRetries;
    m_retryDelay = retryDelay;
}

HttpResponse KeyVaultClient::makeHttpRequest(const std::string& method, const std::string& endpoint, 
                                           const std::string& payload) {
    HttpRequest request;
    request.url = m_vaultUrl + endpoint;
    request.method = method;
    request.body = payload;
    request.verify_ssl = true;
    
    if (!m_caPath.empty()) {
        request.ca_cert_path = m_caPath;
    }
    
    if (m_useMutualTLS) {
        request.client_cert_path = m_clientCertPath;
        request.client_key_path = m_clientKeyPath;
    }
    
    updateMetrics(false); // Will be updated to true if successful
    auto response = m_httpClient->execute(request);
    updateMetrics(response.success);
    
    return response;
}

HttpResponse KeyVaultClient::makeHttpRequestWithRetry(const std::string& method, const std::string& endpoint, 
                                                    const std::string& payload) {
    HttpResponse lastResponse;
    
    for (int attempt = 0; attempt <= m_maxRetries; ++attempt) {
        lastResponse = makeHttpRequest(method, endpoint, payload);
        
        if (lastResponse.success) {
            return lastResponse;
        }
        
        // If this isn't the last attempt, wait before retrying
        if (attempt < m_maxRetries) {
            std::this_thread::sleep_for(m_retryDelay);
        }
    }
    
    return lastResponse; // Return the last failed response
}

bool KeyVaultClient::validateTLSConnection() {
    if (!m_useMutualTLS) {
        return true; // No mutual TLS required
    }
    
    // Perform a simple health check to validate TLS
    return ping();
}

void KeyVaultClient::clearSensitiveData() {
    // Clear sensitive data from memory
    if (!m_authToken.empty()) {
        std::fill(m_authToken.begin(), m_authToken.end(), '\0');
        m_authToken.clear();
    }
}

void KeyVaultClient::updateMetrics(bool success) {
    std::lock_guard<std::mutex> lock(m_metricsMutex);
    m_requestCount++;
    m_lastRequestTime = std::chrono::steady_clock::now();
    
    if (success) {
        m_successCount++;
    } else {
        m_errorCount++;
    }
}

std::string KeyVaultClient::parseSecretFromResponse(const std::string& response) {
    try {
        auto jsonResponse = nlohmann::json::parse(response);
        
        if (jsonResponse.contains("data") && 
            jsonResponse["data"].contains("data") && 
            jsonResponse["data"]["data"].contains("value")) {
            return jsonResponse["data"]["data"]["value"];
        }
        
        std::cerr << "Secret not found in response or unexpected format" << std::endl;
        return "";
        
    } catch (const std::exception& e) {
        std::cerr << "Failed to parse secret response: " << e.what() << std::endl;
        return "";
    }
}

} // namespace infra
} // namespace coyote
