#pragma once

#include <memory>
#include <string>
#include "BaseUnit.h"
#include "../../Infra/IRedisClient.h"
#include "../../Infra/ISecureStore.h"
#include "../../Infra/IConfigReader.h"
#include "../../Infra/IHttpClient.h"

namespace coyote {
namespace baseunit {

/**
 * @brief Dependency injection container for creating BaseUnit instances
 * 
 * This class provides factory methods to create BaseUnit instances with
 * different implementations (real vs mock) for testing and production use.
 */
class DependencyContainer {
public:
    /**
     * @brief Create a BaseUnit with real implementations
     * @param configPath Path to the configuration file
     * @return Unique pointer to BaseUnit instance
     */
    static std::unique_ptr<BaseUnit> createProduction(const std::string& configPath);
    
    /**
     * @brief Create a BaseUnit with mock implementations for testing
     * @param unitId Unit identifier for the test instance
     * @param unitType Unit type for the test instance
     * @return Unique pointer to BaseUnit instance
     */
    static std::unique_ptr<BaseUnit> createForTesting(
        const std::string& unitId = "test-unit",
        const std::string& unitType = "test-type");
    
    /**
     * @brief Create a BaseUnit with custom implementations
     * @param config Configuration instance
     * @param redisClient Redis client implementation
     * @param secureStore Secure store implementation
     * @param httpClient HTTP client implementation
     * @return Unique pointer to BaseUnit instance
     */
    static std::unique_ptr<BaseUnit> createCustom(
        std::unique_ptr<infra::ICoyoteConfig> config,
        std::shared_ptr<infra::IRedisClient> redisClient,
        std::shared_ptr<infra::ISecureStore> secureStore,
        std::shared_ptr<infra::IHttpClient> httpClient);

private:
    // Helper methods for creating components
    static std::unique_ptr<infra::ICoyoteConfig> createTestConfig(
        const std::string& unitId,
        const std::string& unitType);
    
    static std::shared_ptr<infra::IRedisClient> createMockRedisClient();
    static std::shared_ptr<infra::ISecureStore> createMockSecureStore();
    static std::shared_ptr<infra::IHttpClient> createMockHttpClient();
};

/**
 * @brief Builder pattern for creating BaseUnit instances with specific configurations
 */
class BaseUnitBuilder {
public:
    BaseUnitBuilder() = default;
    
    BaseUnitBuilder& withConfig(std::unique_ptr<infra::ICoyoteConfig> config);
    BaseUnitBuilder& withRedisClient(std::shared_ptr<infra::IRedisClient> redisClient);
    BaseUnitBuilder& withSecureStore(std::shared_ptr<infra::ISecureStore> secureStore);
    BaseUnitBuilder& withHttpClient(std::shared_ptr<infra::IHttpClient> httpClient);
    
    // Use mock implementations
    BaseUnitBuilder& withMockRedisClient();
    BaseUnitBuilder& withMockSecureStore();
    BaseUnitBuilder& withMockHttpClient();
    
    // Use real implementations with config
    BaseUnitBuilder& withRealComponents(const std::string& configPath);
    
    std::unique_ptr<BaseUnit> build();

private:
    std::unique_ptr<infra::ICoyoteConfig> m_config;
    std::shared_ptr<infra::IRedisClient> m_redisClient;
    std::shared_ptr<infra::ISecureStore> m_secureStore;
    std::shared_ptr<infra::IHttpClient> m_httpClient;
};

} // namespace baseunit
} // namespace coyote
