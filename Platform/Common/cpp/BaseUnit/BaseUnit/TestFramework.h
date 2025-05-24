#pragma once

#include <iostream>
#include <string>
#include <functional>
#include <vector>
#include <exception>

/**
 * @brief Simple testing framework for unit tests
 */
class SimpleTestFramework {
public:
    struct TestCase {
        std::string name;
        std::function<void()> testFunction;
    };
    
    static SimpleTestFramework& getInstance() {
        static SimpleTestFramework instance;
        return instance;
    }
    
    void addTest(const std::string& name, std::function<void()> testFunction) {
        m_tests.push_back({name, testFunction});
    }
    
    int runAllTests() {
        int passed = 0;
        int failed = 0;
        
        std::cout << "Running " << m_tests.size() << " tests..." << std::endl;
        std::cout << "========================================" << std::endl;
        
        for (const auto& test : m_tests) {
            try {
                std::cout << "Running: " << test.name << "... ";
                test.testFunction();
                std::cout << "PASSED" << std::endl;
                passed++;
            } catch (const std::exception& e) {
                std::cout << "FAILED - " << e.what() << std::endl;
                failed++;
            } catch (...) {
                std::cout << "FAILED - Unknown exception" << std::endl;
                failed++;
            }
        }
        
        std::cout << "========================================" << std::endl;
        std::cout << "Tests passed: " << passed << std::endl;
        std::cout << "Tests failed: " << failed << std::endl;
        std::cout << "Total tests:  " << m_tests.size() << std::endl;
        
        return failed;
    }
    
    // Assertion helpers
    static void assertTrue(bool condition, const std::string& message = "Assertion failed") {
        if (!condition) {
            throw std::runtime_error(message);
        }
    }
    
    static void assertFalse(bool condition, const std::string& message = "Assertion failed") {
        assertTrue(!condition, message);
    }
    
    static void assertEqual(const std::string& expected, const std::string& actual, 
                           const std::string& message = "Values not equal") {
        if (expected != actual) {
            throw std::runtime_error(message + " - Expected: '" + expected + "', Actual: '" + actual + "'");
        }
    }
    
    static void assertNotEqual(const std::string& expected, const std::string& actual,
                              const std::string& message = "Values should not be equal") {
        if (expected == actual) {
            throw std::runtime_error(message + " - Both values: '" + expected + "'");
        }
    }
    
    static void assertNotNull(void* ptr, const std::string& message = "Pointer is null") {
        if (ptr == nullptr) {
            throw std::runtime_error(message);
        }
    }
    
    template<typename T>
    static void assertNotNull(std::shared_ptr<T> ptr, const std::string& message = "Shared pointer is null") {
        if (!ptr) {
            throw std::runtime_error(message);
        }
    }
    
    template<typename T>
    static void assertNotNull(std::unique_ptr<T>& ptr, const std::string& message = "Unique pointer is null") {
        if (!ptr) {
            throw std::runtime_error(message);
        }
    }

private:
    std::vector<TestCase> m_tests;
};

// Macro for easier test registration
#define TEST(testName) \
    void testName(); \
    namespace { \
        struct TestRegistrar_##testName { \
            TestRegistrar_##testName() { \
                SimpleTestFramework::getInstance().addTest(#testName, testName); \
            } \
        }; \
        static TestRegistrar_##testName testRegistrar_##testName; \
    } \
    void testName()

// Assertion macros
#define ASSERT_TRUE(condition) SimpleTestFramework::assertTrue(condition, "ASSERT_TRUE failed: " #condition)
#define ASSERT_FALSE(condition) SimpleTestFramework::assertFalse(condition, "ASSERT_FALSE failed: " #condition)
#define ASSERT_EQ(expected, actual) SimpleTestFramework::assertEqual(expected, actual, "ASSERT_EQ failed")
#define ASSERT_NE(expected, actual) SimpleTestFramework::assertNotEqual(expected, actual, "ASSERT_NE failed")
#define ASSERT_NOT_NULL(ptr) SimpleTestFramework::assertNotNull(ptr, "ASSERT_NOT_NULL failed: " #ptr)
