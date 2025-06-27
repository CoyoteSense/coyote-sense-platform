cmake_minimum_required(VERSION 3.20)

project(OAuth2AuthClientTests 
    VERSION 1.0.0
    DESCRIPTION "OAuth2 Authentication Client Tests"
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
add_executable(oauth2_auth_client_test
    simple_security_test.cpp
)

add_executable(oauth2_integration_test
    simple_security_test.cpp
)

# Link libraries
target_link_libraries(oauth2_auth_client_test
    gtest_main
    gmock_main
)

target_link_libraries(oauth2_integration_test
    gtest_main
    gmock_main
)

# Platform-specific libraries
if(WIN32)
    target_link_libraries(oauth2_auth_client_test ws2_32 crypt32)
    target_link_libraries(oauth2_integration_test ws2_32 crypt32)
endif()

# Test discovery
include(GoogleTest)
gtest_discover_tests(oauth2_auth_client_test)
gtest_discover_tests(oauth2_integration_test)
