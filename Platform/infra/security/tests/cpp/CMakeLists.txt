cmake_minimum_required(VERSION 3.20)

project(AuthClientTests 
    VERSION 1.0.0
    DESCRIPTION "Authentication Client Tests"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Google Test
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

# Create test executables
add_executable(auth_client_test
    unit/auth_client_test.cpp
)

add_executable(auth_integration_test
    integration/auth_integration_test.cpp
)

add_executable(auth_security_test
    security/auth_security_tests.cpp
)

# Include directories
target_include_directories(auth_client_test PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/cpp
)

target_include_directories(auth_integration_test PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/cpp
)

target_include_directories(auth_security_test PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/cpp
)

# Link libraries
target_link_libraries(auth_client_test
    gtest_main
    gmock_main
)

target_link_libraries(auth_integration_test
    gtest_main
    gmock_main
)

target_link_libraries(auth_security_test
    gtest_main
    gmock_main
)

# Platform-specific libraries
if(WIN32)
    target_link_libraries(auth_client_test ws2_32 crypt32)
    target_link_libraries(auth_integration_test ws2_32 crypt32)
    target_link_libraries(auth_security_test ws2_32 crypt32)
endif()

# Register tests with CTest
include(GoogleTest)
gtest_discover_tests(auth_client_test)
gtest_discover_tests(auth_integration_test)
gtest_discover_tests(auth_security_test)

# Test discovery
include(GoogleTest)
gtest_discover_tests(auth_client_test)
gtest_discover_tests(auth_integration_test)
