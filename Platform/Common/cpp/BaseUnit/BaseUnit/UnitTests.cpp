#include "TestFramework.h"
#include "BaseUnit.h"
#include "DependencyInjection.h"
#include "../../Infra/MockRedisClient.h"
#include "../../Infra/MockSecureStore.h"
#include "../../Infra/MockHttpClient.h"
#include "../../Infra/MockConfigReader.h"

using namespace coyote::baseunit;
using namespace coyote::infra;

// Test BaseUnit class that doesn't require external resources
class TestableBaseUnit : public BaseUnit {
public:
    using BaseUnit::BaseUnit;
    
    bool initializeCalled = false;
    bool startCalled = false;
    bool stopCalled = false;
    std::vector<std::string> receivedMessages;
    
protected:
    bool onInitialize() override {
        initializeCalled = true;
        return true;
    }
    
    bool onStart() override {
        startCalled = true;
        return true;
    }
    
    void onStop() override {
        stopCalled = true;
    }
    
    void onMessage(const std::string& channel, const std::string& message) override {
        receivedMessages.push_back(channel + ":" + message);
    }
};

TEST(TestDependencyContainerCreateForTesting) {
    auto unit = DependencyContainer::createForTesting("test-unit-123", "test-type");
    
    ASSERT_NOT_NULL(unit);
    ASSERT_EQ("test-unit-123", unit->getUnitId());
    ASSERT_EQ("test-type", unit->getUnitType());
    
    // Verify components are available
    ASSERT_NOT_NULL(unit->getRedisClient());
    ASSERT_NOT_NULL(unit->getSecureStore());
    ASSERT_NOT_NULL(unit->getHttpClient());
}

TEST(TestDependencyContainerCreateCustom) {
    // Create mock components
    auto mockRedis = std::make_shared<MockRedisClient>();
    auto mockStore = std::make_shared<MockSecureStore>();
    auto mockHttp = std::make_shared<MockHttpClient>();
    
    // Create test configuration
    auto mockReader = std::make_unique<MockConfigReader>();
    nlohmann::json testConfig = {
        {"unit", {
            {"unitId", "custom-unit"},
            {"unitType", "custom-type"}
        }}
    };
    mockReader->setConfigValues(testConfig);
    auto config = std::make_unique<CoyoteConfig>(std::move(mockReader));
    
    auto unit = DependencyContainer::createCustom(
        std::move(config),
        mockRedis,
        mockStore,
        mockHttp
    );
    
    ASSERT_NOT_NULL(unit);
    ASSERT_EQ("custom-unit", unit->getUnitId());
    ASSERT_EQ("custom-type", unit->getUnitType());
    
    // Verify the same instances are used
    ASSERT_TRUE(unit->getRedisClient().get() == mockRedis.get());
    ASSERT_TRUE(unit->getSecureStore().get() == mockStore.get());
    ASSERT_TRUE(unit->getHttpClient().get() == mockHttp.get());
}

TEST(TestBaseUnitBuilderPattern) {
    auto unit = BaseUnitBuilder()
        .withMockRedisClient()
        .withMockSecureStore()
        .withMockHttpClient()
        .build();
    
    ASSERT_NOT_NULL(unit);
    ASSERT_NOT_NULL(unit->getRedisClient());
    ASSERT_NOT_NULL(unit->getSecureStore());
    ASSERT_NOT_NULL(unit->getHttpClient());
}

TEST(TestBaseUnitBuilderThrowsOnMissingComponents) {
    bool exceptionThrown = false;
    try {
        auto unit = BaseUnitBuilder()
            .withMockRedisClient()
            // Missing secure store and HTTP client
            .build();
    } catch (const std::runtime_error& e) {
        exceptionThrown = true;
        ASSERT_TRUE(std::string(e.what()).find("Missing required components") != std::string::npos);
    }
    
    ASSERT_TRUE(exceptionThrown);
}

TEST(TestMockRedisClientFunctionality) {
    auto mockRedis = std::make_shared<MockRedisClient>();
    
    // Test basic operations
    ASSERT_TRUE(mockRedis->set("key1", "value1"));
    ASSERT_EQ("value1", mockRedis->get("key1"));
    
    // Test non-existent key
    ASSERT_EQ("", mockRedis->get("non-existent"));
    
    // Test publish/subscribe
    bool callbackCalled = false;
    std::string receivedMessage;
    
    mockRedis->subscribe("test-channel", [&](const std::string& channel, const std::string& message) {
        callbackCalled = true;
        receivedMessage = message;
    });
    
    ASSERT_TRUE(mockRedis->publish("test-channel", "test-message"));
    ASSERT_TRUE(callbackCalled);
    ASSERT_EQ("test-message", receivedMessage);
}

TEST(TestMockSecureStoreFunctionality) {
    auto mockStore = std::make_shared<MockSecureStore>();
    
    // Add a secret
    mockStore->addSecret("test-key", "test-value");
    
    // Retrieve the secret
    auto secret = mockStore->getSecret("test-key");
    ASSERT_EQ("test-value", secret);
    
    // Test non-existent secret throws exception
    bool exceptionThrown = false;
    try {
        mockStore->getSecret("non-existent");
    } catch (const std::runtime_error& e) {
        exceptionThrown = true;
    }
    ASSERT_TRUE(exceptionThrown);
    
    // Test metrics
    auto metrics = mockStore->getMetrics();
    ASSERT_NOT_NULL(metrics);
    ASSERT_TRUE(metrics->getTotalRequests() > 0);
}

TEST(TestMockHttpClientFunctionality) {
    auto mockHttp = std::make_shared<MockHttpClient>();
    
    // Create a mock response
    auto mockResponse = std::make_shared<MockHttpResponse>();
    mockResponse->setStatusCode(200);
    mockResponse->setBody(R"({"status": "success"})");
    mockResponse->addHeader("Content-Type", "application/json");
    
    mockHttp->queueResponse(mockResponse);
    
    // Create and send request
    auto request = mockHttp->createRequest();
    request->setUrl("https://api.example.com/test");
    request->setMethod(HttpMethod::GET);
    
    auto response = mockHttp->send(request);
    
    ASSERT_NOT_NULL(response);
    ASSERT_EQ(200, response->getStatusCode());
    ASSERT_EQ(R"({"status": "success"})", response->getBody());
    ASSERT_EQ("application/json", response->getHeader("Content-Type"));
    
    // Verify request was recorded
    auto requests = mockHttp->getRecordedRequests();
    ASSERT_TRUE(requests.size() == 1);
    ASSERT_EQ("https://api.example.com/test", requests[0]->getUrl());
}

TEST(TestMockConfigReaderFunctionality) {
    auto mockReader = std::make_unique<MockConfigReader>();
    
    nlohmann::json testConfig = {
        {"unit", {
            {"unitId", "test-config-unit"},
            {"unitType", "config-test"}
        }},
        {"redis", {
            {"host", "test-redis"},
            {"port", 6379}
        }},
        {"keyVault", {
            {"url", "https://test-vault.vault.azure.net/"},
            {"unitRole", "test-role"}
        }}
    };
    
    mockReader->setConfigValues(testConfig);
    
    auto config = std::make_unique<CoyoteConfig>(std::move(mockReader));
    
    const auto& unitConfig = config->getUnitConfig();
    ASSERT_EQ("test-config-unit", unitConfig.unitId);
    ASSERT_EQ("config-test", unitConfig.unitType);
    
    const auto& redisConfig = config->getRedisConfig();
    ASSERT_EQ("test-redis", redisConfig.host);
    ASSERT_EQ(6379, redisConfig.port);
    
    const auto& vaultConfig = config->getKeyVaultConfig();
    ASSERT_EQ("https://test-vault.vault.azure.net/", vaultConfig.url);
    ASSERT_EQ("test-role", vaultConfig.unitRole);
}

TEST(TestBaseUnitInitializationWithMocks) {
    auto unit = DependencyContainer::createForTesting("init-test-unit", "init-test-type");
    
    // Initialize should succeed with mocks
    ASSERT_TRUE(unit->initialize());
    ASSERT_EQ(UnitState::INITIALIZING, unit->getState());
}

TEST(TestBaseUnitSecretRetrieval) {
    auto unit = DependencyContainer::createForTesting("secret-test-unit", "secret-test-type");
    
    // Initialize the unit
    ASSERT_TRUE(unit->initialize());
    
    // Try to get a secret (should work with mock store that has pre-populated secrets)
    auto secret = unit->getSecret("api-key");
    ASSERT_EQ("test-api-key-12345", secret);
}

TEST(TestBaseUnitMessaging) {
    auto unit = DependencyContainer::createForTesting("messaging-test-unit", "messaging-test-type");
    
    ASSERT_TRUE(unit->initialize());
    
    // Test publishing (should not throw with mock Redis)
    ASSERT_TRUE(unit->publishMessage("test-channel", "test-message"));
}

TEST(TestBaseUnitLifecycle) {
    // Create a testable unit
    auto mockRedis = std::make_shared<MockRedisClient>();
    auto mockStore = std::make_shared<MockSecureStore>();
    auto mockHttp = std::make_shared<MockHttpClient>();
    
    auto mockReader = std::make_unique<MockConfigReader>();
    nlohmann::json testConfig = {
        {"unit", {
            {"unitId", "lifecycle-test"},
            {"unitType", "lifecycle-type"}
        }}
    };
    mockReader->setConfigValues(testConfig);
    auto config = std::make_unique<CoyoteConfig>(std::move(mockReader));
    
    auto testableUnit = std::make_unique<TestableBaseUnit>(
        std::move(config),
        mockRedis,
        mockStore,
        mockHttp
    );
    
    // Test initialization
    ASSERT_TRUE(testableUnit->initialize());
    ASSERT_TRUE(testableUnit->initializeCalled);
    
    // Test start
    ASSERT_TRUE(testableUnit->start());
    ASSERT_TRUE(testableUnit->startCalled);
    ASSERT_EQ(UnitState::RUNNING, testableUnit->getState());
    
    // Test stop
    testableUnit->stop();
    ASSERT_TRUE(testableUnit->stopCalled);
    ASSERT_EQ(UnitState::STOPPED, testableUnit->getState());
}

int main() {
    return SimpleTestFramework::getInstance().runAllTests();
}
