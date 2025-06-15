# CMakeLists.txt for HTTP Client Integration Tests
cmake_minimum_required(VERSION 3.16)
project(CoyoteHttpClientIntegrationTests VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set vcpkg toolchain if VCPKG_ROOT is set
if(DEFINED ENV{VCPKG_ROOT} AND EXISTS "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
    message(STATUS "Using vcpkg toolchain: ${CMAKE_TOOLCHAIN_FILE}")
elseif(WIN32 AND EXISTS "C:/vcpkg/scripts/buildsystems/vcpkg.cmake")
    # Fallback to default Windows location
    set(CMAKE_TOOLCHAIN_FILE "C:/vcpkg/scripts/buildsystems/vcpkg.cmake")
    message(STATUS "Using vcpkg toolchain (fallback): ${CMAKE_TOOLCHAIN_FILE}")
endif()

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

# On Windows with vcpkg, try manual search if packages not found
if(WIN32 AND NOT CURL_FOUND AND EXISTS "C:/vcpkg/installed/x64-windows")
    message(STATUS "Searching for CURL in vcpkg installation...")
    
    find_path(CURL_INCLUDE_DIR
        NAMES curl/curl.h
        PATHS "C:/vcpkg/installed/x64-windows/include"
        NO_DEFAULT_PATH
    )
    
    find_library(CURL_LIBRARY
        NAMES curl libcurl curl_a libcurl_a
        PATHS "C:/vcpkg/installed/x64-windows/lib"
        NO_DEFAULT_PATH
    )
    
    if(CURL_INCLUDE_DIR AND CURL_LIBRARY)
        set(CURL_LIBRARIES ${CURL_LIBRARY})
        set(CURL_INCLUDE_DIRS ${CURL_INCLUDE_DIR})
        set(CURL_FOUND TRUE)
        message(STATUS "Found CURL in vcpkg: ${CURL_LIBRARY}")
    endif()
endif()

if(NOT CURL_FOUND AND NOT CURL_LIBRARIES)
    message(FATAL_ERROR "libcurl not found. Integration tests require libcurl. Install with: vcpkg install curl")
endif()

# Set up GTest
if(GTest_FOUND)
    # Modern GTest
    set(GTEST_LIBRARIES GTest::gtest GTest::gtest_main)
    set(GTEST_INCLUDE_DIRS "")
else()
    # Try to find GTest manually, with vcpkg paths first on Windows
    set(GTEST_SEARCH_PATHS)
    if(WIN32 AND EXISTS "C:/vcpkg/installed/x64-windows")
        list(APPEND GTEST_SEARCH_PATHS "C:/vcpkg/installed/x64-windows")
    endif()
    
    list(APPEND GTEST_SEARCH_PATHS
        ${CMAKE_PREFIX_PATH}
        C:/vcpkg/installed/x64-windows
        /usr
        /usr/local
    )
    
    find_path(GTEST_INCLUDE_DIR 
        NAMES gtest/gtest.h
        PATHS ${GTEST_SEARCH_PATHS}
        PATH_SUFFIXES include
        NO_DEFAULT_PATH
    )
    
    find_library(GTEST_LIBRARY
        NAMES gtest
        PATHS ${GTEST_SEARCH_PATHS}
        PATH_SUFFIXES lib
        NO_DEFAULT_PATH
    )
    
    find_library(GTEST_MAIN_LIBRARY
        NAMES gtest_main
        PATHS ${GTEST_SEARCH_PATHS}
        PATH_SUFFIXES lib
        NO_DEFAULT_PATH
    )
    
    if(GTEST_INCLUDE_DIR AND GTEST_LIBRARY AND GTEST_MAIN_LIBRARY)
        set(GTEST_LIBRARIES ${GTEST_LIBRARY} ${GTEST_MAIN_LIBRARY})
        set(GTEST_INCLUDE_DIRS ${GTEST_INCLUDE_DIR})
        message(STATUS "Found GTest: ${GTEST_LIBRARY}")
    else()
        message(FATAL_ERROR "GTest not found. Integration tests require GTest. Install with: vcpkg install gtest")
    endif()
endif()

# Find threading library
find_package(Threads REQUIRED)

# Define compiler-specific options
if(MSVC)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)
    add_definitions(-DNOMINMAX)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Make sure the paths are correct
message(STATUS "Source directory: ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "Factory source: ${CMAKE_CURRENT_SOURCE_DIR}/../../factory/cpp/http_client_factory.cpp")
message(STATUS "Real source: ${CMAKE_CURRENT_SOURCE_DIR}/../../modes/real/cpp/http_client_real.cpp")
message(STATUS "Mock source: ${CMAKE_CURRENT_SOURCE_DIR}/../../modes/mock/cpp/http_client_mock.cpp")

# Set HTTP client sources - use absolute paths
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../src/cpp/factory/http_client_factory.cpp")
    # We're building in the regular project structure
    set(HTTP_CLIENT_SOURCES
        "${CMAKE_CURRENT_SOURCE_DIR}/../../src/cpp/factory/http_client_factory.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../src/cpp/impl/real/http_client_real.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../src/cpp/impl/mock/http_client_mock.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../src/cpp/impl/debug/http_client_debug.cpp"
    )
    set(INTERFACES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../src/cpp/interfaces")
    set(FACTORY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../src/cpp/factory")
    set(REAL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../src/cpp/impl/real")
    set(MOCK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../src/cpp/impl/mock")
    set(DEBUG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../src/cpp/impl/debug")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/factory/cpp/http_client_factory.cpp")
    # We're building in Docker where files are copied to /workspace
    set(HTTP_CLIENT_SOURCES
        "${CMAKE_CURRENT_SOURCE_DIR}/factory/cpp/http_client_factory.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/modes/real/cpp/http_client_real.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/modes/mock/cpp/http_client_mock.cpp"
    )
    set(INTERFACES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/interfaces/cpp")
    set(FACTORY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/factory/cpp")
    set(REAL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/modes/real/cpp")
    set(MOCK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/modes/mock/cpp")
else()
    message(FATAL_ERROR "Cannot find HTTP client source files!")
endif()

# Create HTTP client library with proper include directories
add_library(coyote_http_client_for_tests STATIC ${HTTP_CLIENT_SOURCES})

# Set include directories for the HTTP client library
target_include_directories(coyote_http_client_for_tests PUBLIC
    ${INTERFACES_DIR}
    ${FACTORY_DIR}
    ${REAL_DIR}
    ${MOCK_DIR}
    ${DEBUG_DIR}
)

# Add CURL include directories if available
if(CURL_INCLUDE_DIRS)
    target_include_directories(coyote_http_client_for_tests PRIVATE ${CURL_INCLUDE_DIRS})
endif()

target_link_libraries(coyote_http_client_for_tests ${CURL_LIBRARIES})

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
