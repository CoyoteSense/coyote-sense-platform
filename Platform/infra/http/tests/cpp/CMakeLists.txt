# Unit tests for HTTP Client
cmake_minimum_required(VERSION 3.16)

# Include parent directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../interfaces/cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../factory/cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../modes/real/cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../modes/mock/cpp
)

# Set up GTest
find_package(GTest REQUIRED)
# Modern CMake style with target-based approach
set(GTEST_LIBRARIES GTest::gtest GTest::gtest_main GTest::gmock GTest::gmock_main)
# No need to manually include GTest directories with modern CMake

# Find threading library
find_package(Threads REQUIRED)

# Unit test sources
set(UNIT_TEST_SOURCES
    test_http_client_mock.cpp
    test_http_client_factory.cpp
)

# Create unit test executable
add_executable(http_client_unit_tests ${UNIT_TEST_SOURCES})

# Link libraries
target_link_libraries(http_client_unit_tests
    coyote_http_client
    ${GTEST_LIBRARIES}
    Threads::Threads
)

# Compiler flags
if(MSVC)
    target_compile_options(http_client_unit_tests PRIVATE 
        /W4
        /permissive-
    )
else()
    target_compile_options(http_client_unit_tests PRIVATE 
        -Wall 
        -Wextra 
        -Wpedantic
    )
endif()

# Add tests to CTest
add_test(NAME HttpClientUnitTests COMMAND http_client_unit_tests)

# Set test properties
set_tests_properties(HttpClientUnitTests PROPERTIES
    TIMEOUT 60
    LABELS "unit"
)

# Test environment variables
set_tests_properties(HttpClientUnitTests PROPERTIES
    ENVIRONMENT "COYOTE_RUNTIME_MODE=testing"
)
