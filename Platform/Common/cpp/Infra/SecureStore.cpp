#include "SecureStore.h"
#include <iostream>
#include <sstream>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <chrono>
#include <cstring>

namespace coyote {
namespace infra {

// Helper for CURL response
struct CurlResponse {
    std::string data;
    long responseCode = 0;
};

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, CurlResponse* response) {
    size_t totalSize = size * nmemb;
    response->data.append(static_cast<char*>(contents), totalSize);
    return totalSize;
}

KeyVaultClient::KeyVaultClient(const std::string& vaultUrl, const std::string& unitId)
    : m_vaultUrl(vaultUrl), m_unitId(unitId), m_useMutualTLS(false) {
    
    // Initialize CURL globally (should be done once per application)
    static bool curlInitialized = false;
    if (!curlInitialized) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curlInitialized = true;
    }
}

KeyVaultClient::~KeyVaultClient() {
    clearSensitiveData();
}

bool KeyVaultClient::authenticate(const std::string& unitId, const std::string& credentials) {
    try {
        nlohmann::json authPayload;
        authPayload["role"] = unitId;
        authPayload["secret_id"] = credentials;

        std::string response = makeHttpRequest("POST", "/v1/auth", authPayload.dump());
        if (response.empty()) {
            return false;
        }

        auto jsonResponse = nlohmann::json::parse(response);
        if (jsonResponse.contains("auth") && jsonResponse["auth"].contains("client_token")) {
            m_authToken = jsonResponse["auth"]["client_token"];
            std::cout << "Successfully authenticated with KeyVault" << std::endl;
            return true;
        }

        std::cerr << "Authentication failed: no token in response" << std::endl;
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

    try {
        std::string response = makeHttpRequest("POST", "/v1/auth/token/renew-self", "{}");
        if (response.empty()) {
            return false;
        }

        auto jsonResponse = nlohmann::json::parse(response);
        if (jsonResponse.contains("auth") && jsonResponse["auth"].contains("client_token")) {
            // Clear old token from memory
            std::memset(m_authToken.data(), 0, m_authToken.size());
            m_authToken = jsonResponse["auth"]["client_token"];
            return true;
        }

        return false;

    } catch (const std::exception& e) {
        std::cerr << "Token refresh error: " << e.what() << std::endl;
        return false;
    }
}

std::string KeyVaultClient::getSecret(const std::string& path) {
    if (m_authToken.empty()) {
        std::cerr << "Not authenticated with KeyVault" << std::endl;
        return "";
    }

    try {
        std::string endpoint = "/v1/secret/" + path;
        std::string response = makeHttpRequest("GET", endpoint);
        
        if (response.empty()) {
            return "";
        }

        auto jsonResponse = nlohmann::json::parse(response);
        if (jsonResponse.contains("data") && jsonResponse["data"].contains("value")) {
            return jsonResponse["data"]["value"];
        }

        std::cerr << "Secret not found or invalid format: " << path << std::endl;
        return "";

    } catch (const std::exception& e) {
        std::cerr << "Error retrieving secret '" << path << "': " << e.what() << std::endl;
        return "";
    }
}

bool KeyVaultClient::setSecret(const std::string& path, const std::string& value) {
    if (m_authToken.empty()) {
        std::cerr << "Not authenticated with KeyVault" << std::endl;
        return false;
    }

    try {
        nlohmann::json payload;
        payload["data"]["value"] = value;

        std::string endpoint = "/v1/secret/" + path;
        std::string response = makeHttpRequest("POST", endpoint, payload.dump());
        
        return !response.empty();

    } catch (const std::exception& e) {
        std::cerr << "Error setting secret '" << path << "': " << e.what() << std::endl;
        return false;
    }
}

bool KeyVaultClient::deleteSecret(const std::string& path) {
    if (m_authToken.empty()) {
        std::cerr << "Not authenticated with KeyVault" << std::endl;
        return false;
    }

    try {
        std::string endpoint = "/v1/secret/" + path;
        std::string response = makeHttpRequest("DELETE", endpoint);
        
        return !response.empty();

    } catch (const std::exception& e) {
        std::cerr << "Error deleting secret '" << path << "': " << e.what() << std::endl;
        return false;
    }
}

bool KeyVaultClient::isConnected() const {
    return !m_authToken.empty();
}

void KeyVaultClient::disconnect() {
    clearSensitiveData();
}

std::string KeyVaultClient::makeHttpRequest(const std::string& method, const std::string& endpoint, 
                                           const std::string& payload) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Failed to initialize CURL" << std::endl;
        return "";
    }

    CurlResponse response;
    std::string url = m_vaultUrl + endpoint;
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    // Set HTTP method
    if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if (!payload.empty()) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
        }
    } else if (method == "DELETE") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    }

    // Set headers
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    if (!m_authToken.empty()) {
        std::string authHeader = "Authorization: Bearer " + m_authToken;
        headers = curl_slist_append(headers, authHeader.c_str());
    }
    
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Mutual TLS configuration
    if (m_useMutualTLS) {
        if (!m_caPath.empty()) {
            curl_easy_setopt(curl, CURLOPT_CAINFO, m_caPath.c_str());
        }
        if (!m_clientCertPath.empty()) {
            curl_easy_setopt(curl, CURLOPT_SSLCERT, m_clientCertPath.c_str());
        }
        if (!m_clientKeyPath.empty()) {
            curl_easy_setopt(curl, CURLOPT_SSLKEY, m_clientKeyPath.c_str());
        }
    }

    // Perform the request
    CURLcode res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.responseCode);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        std::cerr << "CURL error: " << curl_easy_strerror(res) << std::endl;
        return "";
    }

    if (response.responseCode < 200 || response.responseCode >= 300) {
        std::cerr << "HTTP error: " << response.responseCode << std::endl;
        return "";
    }

    return response.data;
}

void KeyVaultClient::clearSensitiveData() {
    if (!m_authToken.empty()) {
        std::memset(m_authToken.data(), 0, m_authToken.size());
        m_authToken.clear();
    }
}

} // namespace infra
} // namespace coyote
