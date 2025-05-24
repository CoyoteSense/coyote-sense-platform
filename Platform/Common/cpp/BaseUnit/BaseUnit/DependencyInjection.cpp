#include "DependencyInjection.h"
#include "../../Infra/ConfigReader.h"
#include "../../Infra/RedisClient.h"
#include "../../Infra/SecureStore.h"
#include "../../Infra/HttpClient.h"
#include "../../Infra/MockRedisClient.h"
#include "../../Infra/MockSecureStore.h"
#include "../../Infra/MockHttpClient.h"
#include "../../Infra/MockConfigReader.h"

namespace coyote {
namespace baseunit {

std::unique_ptr<BaseUnit> DependencyContainer::createProduction(const std::string& configPath) {
    // Create configuration reader using factory
    auto configReader = infra::ConfigReaderFactory::create(configPath);
    auto config = std::make_unique<infra::CoyoteConfig>(std::move(configReader));
    
    // Create infrastructure components using factories
    const auto& redisConfig = config->getRedisConfig();
    auto redisClient = infra::RedisClientFactory::create(redisConfig);
    
    const auto& keyVaultConfig = config->getKeyVaultConfig();
    auto secureStore = infra::SecureStoreFactory::create(keyVaultConfig);
    
    auto httpClient = infra::HttpClientFactory::create();
    
    return std::make_unique<BaseUnit>(
        std::move(config),
        std::move(redisClient),
        std::move(secureStore),
        std::move(httpClient)
    );
}

std::unique_ptr<BaseUnit> DependencyContainer::createForTesting(
    const std::string& unitId,
    const std::string& unitType) {
    
    auto config = createTestConfig(unitId, unitType);
    auto redisClient = createMockRedisClient();
    auto secureStore = createMockSecureStore();
    auto httpClient = createMockHttpClient();
    
    return std::make_unique<BaseUnit>(
        std::move(config),
        std::move(redisClient),
        std::move(secureStore),
        std::move(httpClient)
    );
}

std::unique_ptr<BaseUnit> DependencyContainer::createCustom(
    std::unique_ptr<infra::ICoyoteConfig> config,
    std::shared_ptr<infra::IRedisClient> redisClient,
    std::shared_ptr<infra::ISecureStore> secureStore,
    std::shared_ptr<infra::IHttpClient> httpClient) {
    
    return std::make_unique<BaseUnit>(
        std::move(config),
        std::move(redisClient),
        std::move(secureStore),
        std::move(httpClient)
    );
}

std::unique_ptr<infra::ICoyoteConfig> DependencyContainer::createTestConfig(
    const std::string& unitId,
    const std::string& unitType) {
    
    auto mockReader = std::make_unique<infra::MockConfigReader>();
    
    // Set up test configuration values
    nlohmann::json testConfig = {
        {"unit", {
            {"unitId", unitId},
            {"unitType", unitType},
            {"environment", "test"}
        }},
        {"redis", {
            {"host", "localhost"},
            {"port", 6379},
            {"database", 0}
        }},
        {"keyVault", {
            {"url", "https://test-vault.vault.azure.net/"},
            {"unitRole", "test-role"},
            {"tenantId", "test-tenant"},
            {"clientId", "test-client"}
        }}
    };
    
    mockReader->setConfigValues(testConfig);
    
    return std::make_unique<infra::CoyoteConfig>(std::move(mockReader));
}

std::shared_ptr<infra::IRedisClient> DependencyContainer::createMockRedisClient() {
    return std::make_shared<infra::MockRedisClient>();
}

std::shared_ptr<infra::ISecureStore> DependencyContainer::createMockSecureStore() {
    auto mockStore = std::make_shared<infra::MockSecureStore>();
    
    // Pre-populate with some test secrets
    mockStore->addSecret("test-connection", "connected");
    mockStore->addSecret("api-key", "test-api-key-12345");
    mockStore->addSecret("database-password", "test-db-password");
    
    return mockStore;
}

std::shared_ptr<infra::IHttpClient> DependencyContainer::createMockHttpClient() {
    return std::make_shared<infra::MockHttpClient>();
}

// BaseUnitBuilder implementation
BaseUnitBuilder& BaseUnitBuilder::withConfig(std::unique_ptr<infra::ICoyoteConfig> config) {
    m_config = std::move(config);
    return *this;
}

BaseUnitBuilder& BaseUnitBuilder::withRedisClient(std::shared_ptr<infra::IRedisClient> redisClient) {
    m_redisClient = std::move(redisClient);
    return *this;
}

BaseUnitBuilder& BaseUnitBuilder::withSecureStore(std::shared_ptr<infra::ISecureStore> secureStore) {
    m_secureStore = std::move(secureStore);
    return *this;
}

BaseUnitBuilder& BaseUnitBuilder::withHttpClient(std::shared_ptr<infra::IHttpClient> httpClient) {
    m_httpClient = std::move(httpClient);
    return *this;
}

BaseUnitBuilder& BaseUnitBuilder::withMockRedisClient() {
    m_redisClient = DependencyContainer::createMockRedisClient();
    return *this;
}

BaseUnitBuilder& BaseUnitBuilder::withMockSecureStore() {
    m_secureStore = DependencyContainer::createMockSecureStore();
    return *this;
}

BaseUnitBuilder& BaseUnitBuilder::withMockHttpClient() {
    m_httpClient = DependencyContainer::createMockHttpClient();
    return *this;
}

BaseUnitBuilder& BaseUnitBuilder::withRealComponents(const std::string& configPath) {
    // Create configuration reader using factory
    auto configReader = infra::ConfigReaderFactory::create(configPath);
    m_config = std::make_unique<infra::CoyoteConfig>(std::move(configReader));
    
    // Create infrastructure components using factories
    const auto& redisConfig = m_config->getRedisConfig();
    m_redisClient = infra::RedisClientFactory::create(redisConfig);
    
    const auto& keyVaultConfig = m_config->getKeyVaultConfig();
    m_secureStore = infra::SecureStoreFactory::create(keyVaultConfig);
    
    m_httpClient = infra::HttpClientFactory::create();
    
    return *this;
}

std::unique_ptr<BaseUnit> BaseUnitBuilder::build() {
    if (!m_config || !m_redisClient || !m_secureStore || !m_httpClient) {
        throw std::runtime_error("Missing required components for BaseUnit construction");
    }
    
    return std::make_unique<BaseUnit>(
        std::move(m_config),
        std::move(m_redisClient),
        std::move(m_secureStore),
        std::move(m_httpClient)
    );
}

} // namespace baseunit
} // namespace coyote
