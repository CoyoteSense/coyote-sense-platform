#include "BaseUnit.h"
#include "DependencyInjection.h"
#include "../../Infra/MockRedisClient.h"
#include "../../Infra/MockSecureStore.h"
#include "../../Infra/MockHttpClient.h"
#include "../../Infra/MockConfigReader.h"
#include <iostream>
#include <cassert>
#include <memory>

using namespace coyote::baseunit;
using namespace coyote::infra;

/**
 * @brief Test unit for demonstrating dependency injection and testing capabilities
 */
class TestTradingUnit : public BaseUnit {
public:
    using BaseUnit::BaseUnit; // Inherit constructors
    
protected:
    bool onInitialize() override {
        std::cout << "TestTradingUnit::onInitialize() called" << std::endl;
        
        // Test Redis connectivity
        auto redisClient = getRedisClient();
        if (redisClient && redisClient->isConnected()) {
            std::cout << "Redis client is connected" << std::endl;
        }
        
        // Test secure store
        auto secureStore = getSecureStore();
        if (secureStore) {
            try {
                auto secret = secureStore->getSecret("api-key");
                std::cout << "Retrieved secret: " << secret << std::endl;
            } catch (const std::exception& e) {
                std::cout << "Failed to retrieve secret: " << e.what() << std::endl;
            }
        }
        
        // Test HTTP client
        auto httpClient = getHttpClient();
        if (httpClient) {
            std::cout << "HTTP client available" << std::endl;
        }
        
        return true;
    }
    
    bool onStart() override {
        std::cout << "TestTradingUnit::onStart() called" << std::endl;
        
        // Publish a test message
        publishMessage("test-channel", "Hello from TestTradingUnit!");
        
        return true;
    }
    
    void onStop() override {
        std::cout << "TestTradingUnit::onStop() called" << std::endl;
    }
    
    void onMessage(const std::string& channel, const std::string& message) override {
        std::cout << "Received message on " << channel << ": " << message << std::endl;
    }
};

/**
 * @brief Demonstrate production usage with real implementations
 */
void demonstrateProductionUsage() {
    std::cout << "\n=== Production Usage Demo ===" << std::endl;
    
    try {
        // Create BaseUnit with real implementations (would read from config.json)
        auto unit = DependencyContainer::createProduction("config.json");
        
        // Cast to TestTradingUnit for demonstration
        // In real code, you'd create your specific unit type
        std::cout << "Created production BaseUnit: " << unit->getUnitId() << std::endl;
        std::cout << "Unit type: " << unit->getUnitType() << std::endl;
        
        // Initialize and start would happen here
        // unit->initialize();
        // unit->start();
        
    } catch (const std::exception& e) {
        std::cout << "Production demo failed (expected if config.json not available): " << e.what() << std::endl;
    }
}

/**
 * @brief Demonstrate testing usage with mock implementations
 */
void demonstrateTestingUsage() {
    std::cout << "\n=== Testing Usage Demo ===" << std::endl;
    
    // Create BaseUnit with mock implementations for testing
    auto unit = DependencyContainer::createForTesting("test-unit-123", "test-trading-unit");
    
    std::cout << "Created test BaseUnit: " << unit->getUnitId() << std::endl;
    std::cout << "Unit type: " << unit->getUnitType() << std::endl;
    
    // Test initialization with mocks
    if (unit->initialize()) {
        std::cout << "Unit initialized successfully with mocks" << std::endl;
        
        // Test basic functionality
        unit->publishMessage("test-channel", "Test message from mock unit");
        
        auto secret = unit->getSecret("api-key");
        std::cout << "Retrieved test secret: " << secret << std::endl;
        
        unit->logInfo("This is a test log message");
        unit->updateMetrics("test-metric", 42.0);
        
        if (unit->start()) {
            std::cout << "Unit started successfully" << std::endl;
            
            // Simulate some runtime
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            
            unit->stop();
            std::cout << "Unit stopped successfully" << std::endl;
        }
    }
}

/**
 * @brief Demonstrate builder pattern usage
 */
void demonstrateBuilderPattern() {
    std::cout << "\n=== Builder Pattern Demo ===" << std::endl;
    
    try {
        // Create a custom configuration
        auto mockReader = std::make_unique<MockConfigReader>();
        nlohmann::json customConfig = {
            {"unit", {
                {"unitId", "builder-unit-456"},
                {"unitType", "custom-builder-unit"},
                {"environment", "development"}
            }},
            {"redis", {
                {"host", "custom-redis-host"},
                {"port", 6380},
                {"database", 1}
            }}
        };
        mockReader->setConfigValues(customConfig);
        auto config = std::make_unique<CoyoteConfig>(std::move(mockReader));
        
        // Use builder pattern to create unit with mixed real/mock components
        auto unit = BaseUnitBuilder()
            .withConfig(std::move(config))
            .withMockRedisClient()
            .withMockSecureStore()
            .withMockHttpClient()
            .build();
        
        std::cout << "Created custom BaseUnit: " << unit->getUnitId() << std::endl;
        
        // Test with custom configuration
        if (unit->initialize()) {
            std::cout << "Custom unit initialized successfully" << std::endl;
            
            const auto& redisConfig = unit->getConfig().getRedisConfig();
            std::cout << "Redis host from custom config: " << redisConfig.host << std::endl;
            std::cout << "Redis port from custom config: " << redisConfig.port << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cout << "Builder pattern demo failed: " << e.what() << std::endl;
    }
}

/**
 * @brief Demonstrate mock behavior configuration
 */
void demonstrateMockConfiguration() {
    std::cout << "\n=== Mock Configuration Demo ===" << std::endl;
    
    // Create mock components with specific behaviors
    auto mockRedis = std::make_shared<MockRedisClient>();
    auto mockStore = std::make_shared<MockSecureStore>();
    auto mockHttp = std::make_shared<MockHttpClient>();
    
    // Configure mock behaviors
    mockStore->addSecret("test-key", "test-value");
    mockStore->addSecret("connection-string", "mock://test-db:1234");
    
    // Set up mock HTTP responses
    auto mockResponse = std::make_shared<MockHttpResponse>();
    mockResponse->setStatusCode(200);
    mockResponse->setBody(R"({"status": "success", "data": "mock-data"})");
    mockResponse->addHeader("Content-Type", "application/json");
    mockHttp->queueResponse(mockResponse);
    
    // Create test configuration
    auto mockReader = std::make_unique<MockConfigReader>();
    nlohmann::json testConfig = {
        {"unit", {
            {"unitId", "mock-demo-unit"},
            {"unitType", "mock-demo-type"}
        }}
    };
    mockReader->setConfigValues(testConfig);
    auto config = std::make_unique<CoyoteConfig>(std::move(mockReader));
    
    // Create unit with configured mocks
    auto unit = DependencyContainer::createCustom(
        std::move(config),
        mockRedis,
        mockStore,
        mockHttp
    );
    
    if (unit->initialize()) {
        std::cout << "Mock demo unit initialized" << std::endl;
        
        // Test mock behaviors
        auto secret = unit->getSecret("test-key");
        std::cout << "Retrieved configured secret: " << secret << std::endl;
        
        auto httpClient = unit->getHttpClient();
        auto request = httpClient->createRequest();
        request->setUrl("https://api.example.com/test");
        request->setMethod(HttpMethod::GET);
        
        auto response = httpClient->send(request);
        std::cout << "HTTP response status: " << response->getStatusCode() << std::endl;
        std::cout << "HTTP response body: " << response->getBody() << std::endl;
        
        // Check Redis operations
        auto redisClient = unit->getRedisClient();
        redisClient->set("test-key", "test-value");
        auto value = redisClient->get("test-key");
        std::cout << "Redis get result: " << value << std::endl;
    }
}

int main() {
    std::cout << "=== BaseUnit Dependency Injection Demonstration ===" << std::endl;
    
    try {
        demonstrateTestingUsage();
        demonstrateBuilderPattern();
        demonstrateMockConfiguration();
        demonstrateProductionUsage(); // This might fail if config not available
        
        std::cout << "\n=== All demos completed successfully ===" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Demo failed with exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
