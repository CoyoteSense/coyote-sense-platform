# CMakeLists.txt for HTTP Client Integration Tests
cmake_minimum_required(VERSION 3.16)
project(CoyoteHttpClientIntegrationTests VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(GTest QUIET)

# Find CURL
find_package(CURL QUIET)

if(NOT CURL_FOUND)
    # Try pkg-config as fallback
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(CURL libcurl)
    endif()
endif()

if(NOT CURL_FOUND AND NOT CURL_LIBRARIES)
    message(FATAL_ERROR "libcurl not found. Integration tests require libcurl.")
endif()

# Set up GTest
if(GTest_FOUND)
    # Modern GTest
    set(GTEST_LIBRARIES GTest::gtest GTest::gtest_main)
    set(GTEST_INCLUDE_DIRS "")
else()
    # Try to find GTest manually
    find_path(GTEST_INCLUDE_DIR 
        NAMES gtest/gtest.h
        PATHS
            ${CMAKE_PREFIX_PATH}/include
            $ENV{VCPKG_ROOT}/installed/x64-windows/include
            /usr/include
            /usr/local/include
    )
    
    find_library(GTEST_LIBRARY
        NAMES gtest
        PATHS
            ${CMAKE_PREFIX_PATH}/lib
            $ENV{VCPKG_ROOT}/installed/x64-windows/lib
            /usr/lib
            /usr/local/lib
    )
    
    find_library(GTEST_MAIN_LIBRARY
        NAMES gtest_main
        PATHS
            ${CMAKE_PREFIX_PATH}/lib
            $ENV{VCPKG_ROOT}/installed/x64-windows/lib
            /usr/lib
            /usr/local/lib
    )
    
    if(GTEST_INCLUDE_DIR AND GTEST_LIBRARY AND GTEST_MAIN_LIBRARY)
        set(GTEST_LIBRARIES ${GTEST_LIBRARY} ${GTEST_MAIN_LIBRARY})
        set(GTEST_INCLUDE_DIRS ${GTEST_INCLUDE_DIR})
    else()
        message(FATAL_ERROR "GTest not found. Integration tests require GTest.")
    endif()
endif()

# Find threading library
find_package(Threads REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/interfaces/cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/factory/cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/modes/real/cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/modes/mock/cpp
    ${CURL_INCLUDE_DIRS}
    ${GTEST_INCLUDE_DIRS}
)

# Add the main HTTP client library
set(HTTP_CLIENT_SOURCES
    factory/cpp/http_client_factory.cpp
    modes/real/cpp/http_client_real.cpp
    modes/mock/cpp/http_client_mock.cpp
)

add_library(coyote_http_client_for_tests STATIC ${HTTP_CLIENT_SOURCES})

target_link_libraries(coyote_http_client_for_tests 
    ${CURL_LIBRARIES}
)

# Integration test sources
set(INTEGRATION_TEST_SOURCES
    cpp/test_http_client_integration.cpp
    cpp/common/test_helpers.cpp
)

# Create integration test executable
add_executable(integration_tests ${INTEGRATION_TEST_SOURCES})

# Include test helpers directory
target_include_directories(integration_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/cpp/common
)

target_link_libraries(integration_tests
    coyote_http_client_for_tests
    ${GTEST_LIBRARIES}
    ${CURL_LIBRARIES}
    Threads::Threads
)

# Compiler flags
if(MSVC)
    target_compile_options(integration_tests PRIVATE 
        /W4
        /permissive-
        /DINTEGRATION_TESTS=1
    )
else()
    target_compile_options(integration_tests PRIVATE 
        ${CURL_CFLAGS_OTHER}
        -Wall 
        -Wextra 
        -Wpedantic
        -DINTEGRATION_TESTS=1
    )
endif()

# Enable testing
enable_testing()

# Add test
add_test(NAME HttpClientIntegrationTests COMMAND integration_tests)
