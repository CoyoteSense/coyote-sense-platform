#pragma once

#include <string>
#include <unordered_map>
#include <memory>

namespace coyote {
namespace infra {

class ISecureStore {
public:
    virtual ~ISecureStore() = default;
    
    // Authentication
    virtual bool authenticate(const std::string& unitId, const std::string& credentials) = 0;
    virtual std::string getAuthToken() const = 0;
    virtual bool refreshToken() = 0;
    
    // Secret retrieval
    virtual std::string getSecret(const std::string& path) = 0;
    virtual bool setSecret(const std::string& path, const std::string& value) = 0;
    virtual bool deleteSecret(const std::string& path) = 0;
    
    // Connection management
    virtual bool isConnected() const = 0;
    virtual void disconnect() = 0;
};

class KeyVaultClient : public ISecureStore {
public:
    KeyVaultClient(const std::string& vaultUrl, const std::string& unitId);
    ~KeyVaultClient() override;

    // ISecureStore implementation
    bool authenticate(const std::string& unitId, const std::string& credentials) override;
    std::string getAuthToken() const override;
    bool refreshToken() override;
    
    std::string getSecret(const std::string& path) override;
    bool setSecret(const std::string& path, const std::string& value) override;
    bool deleteSecret(const std::string& path) override;
    
    bool isConnected() const override;
    void disconnect() override;

private:
    std::string m_vaultUrl;
    std::string m_unitId;
    std::string m_authToken;
    std::string m_caPath;
    std::string m_clientCertPath;
    std::string m_clientKeyPath;
    bool m_useMutualTLS;
    
    std::string makeHttpRequest(const std::string& method, const std::string& endpoint, 
                               const std::string& payload = "");
    bool validateTLSConnection();
    void clearSensitiveData();
};

} // namespace infra
} // namespace coyote
