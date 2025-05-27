# Unit tests for HTTP Client
cmake_minimum_required(VERSION 3.16)

# Include parent directories
include_directories(
    "${CMAKE_CURRENT_SOURCE_DIR}/../../interfaces/cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../factory/cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../modes/real/cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../modes/mock/cpp"
)

# Set up GTest
find_package(GTest CONFIG REQUIRED)
include(GoogleTest)

# Find threading library
find_package(Threads REQUIRED)

# Unit test sources
set(UNIT_TEST_SOURCES
    test_main.cpp
    test_http_client_mock.cpp
    test_http_client_factory.cpp
)

# Create unit test executable
add_executable(http_client_unit_tests ${UNIT_TEST_SOURCES})

# Add include directories to target
target_include_directories(http_client_unit_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../../interfaces/cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../factory/cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../modes/real/cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../modes/mock/cpp"
)

# Link libraries
target_link_libraries(http_client_unit_tests
    coyote_http_client
    GTest::gtest
    GTest::gtest_main
    GTest::gmock
    GTest::gmock_main
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

# Register tests with CTest
gtest_discover_tests(http_client_unit_tests)

# Set test properties
set_tests_properties(${GoogleTest_TESTS} PROPERTIES
    TIMEOUT 60
    LABELS "unit"
    ENVIRONMENT "COYOTE_RUNTIME_MODE=testing"
)
