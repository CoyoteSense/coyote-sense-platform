# CMakeLists.txt for Coyote HTTP Client Infrastructure
cmake_minimum_required(VERSION 3.16)
project(CoyoteHttpClient VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(CURL QUIET)

if(NOT CURL_FOUND)
    # Try to find curl manually on Windows
    if(WIN32)
        # Look for vcpkg installation
        find_path(CURL_INCLUDE_DIR 
            NAMES curl/curl.h
            PATHS
                ${CMAKE_PREFIX_PATH}/include
                $ENV{VCPKG_ROOT}/installed/x64-windows/include
                $ENV{PROGRAMFILES}/curl/include
                "C:/Program Files/curl/include"
        )
        
        find_library(CURL_LIBRARY
            NAMES curl libcurl
            PATHS
                ${CMAKE_PREFIX_PATH}/lib
                $ENV{VCPKG_ROOT}/installed/x64-windows/lib
                $ENV{PROGRAMFILES}/curl/lib
                "C:/Program Files/curl/lib"
        )
        
        if(CURL_INCLUDE_DIR AND CURL_LIBRARY)
            set(CURL_FOUND TRUE)
            set(CURL_LIBRARIES ${CURL_LIBRARY})
            set(CURL_INCLUDE_DIRS ${CURL_INCLUDE_DIR})
        endif()
    endif()
endif()

# If still not found, make it optional for development
if(NOT CURL_FOUND)
    message(WARNING "libcurl not found. Real HTTP client will not be functional.")
    set(CURL_INCLUDE_DIRS "")
    set(CURL_LIBRARIES "")
    add_definitions(-DCURL_NOT_AVAILABLE)
endif()

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/interfaces/cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/factory/cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/modes/real/cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/modes/mock/cpp
    ${CURL_INCLUDE_DIRS}
)

# Source files
set(HTTP_CLIENT_SOURCES
    factory/cpp/http_client_factory.cpp
    modes/real/cpp/http_client_real.cpp
    modes/mock/cpp/http_client_mock.cpp
)

# Headers
set(HTTP_CLIENT_HEADERS
    interfaces/cpp/http_client.h
    factory/cpp/http_client_factory.h
    modes/real/cpp/http_client_real.h
    modes/mock/cpp/http_client_mock.h
)

# Create library
add_library(coyote_http_client STATIC ${HTTP_CLIENT_SOURCES} ${HTTP_CLIENT_HEADERS})

# Link libraries
target_link_libraries(coyote_http_client 
    ${CURL_LIBRARIES}
)

# Compiler flags
if(MSVC)
    target_compile_options(coyote_http_client PRIVATE 
        /W4
        /permissive-
    )
else()
    target_compile_options(coyote_http_client PRIVATE 
        ${CURL_CFLAGS_OTHER}
        -Wall 
        -Wextra 
        -Wpedantic
    )
endif()

# Add definitions for debug mode
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(coyote_http_client PRIVATE COYOTE_DEBUG=1)
endif()

# Installation
install(TARGETS coyote_http_client
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES ${HTTP_CLIENT_HEADERS}
    DESTINATION include/coyote/http
)

# Example/Test executable (optional)
option(BUILD_HTTP_CLIENT_EXAMPLES "Build HTTP client examples" OFF)
option(BUILD_HTTP_CLIENT_TESTS "Build HTTP client tests" OFF)

if(BUILD_HTTP_CLIENT_EXAMPLES)
    add_executable(http_client_example examples/http_client_example.cpp)
    target_link_libraries(http_client_example coyote_http_client)
endif()

# Testing
if(BUILD_HTTP_CLIENT_TESTS)
    enable_testing()
    
    # Find GTest
    find_package(GTest QUIET)
    
    if(NOT GTest_FOUND)
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
            set(GTest_FOUND TRUE)
            set(GTEST_LIBRARIES ${GTEST_LIBRARY} ${GTEST_MAIN_LIBRARY})
            set(GTEST_INCLUDE_DIRS ${GTEST_INCLUDE_DIR})
        endif()
    endif()
    
    if(GTest_FOUND OR GTEST_FOUND)
        message(STATUS "Found GTest. Building unit tests.")
        
        # Unit tests
        add_subdirectory(tests/unit)
        
        # Integration tests (optional, requires Docker)
        option(BUILD_INTEGRATION_TESTS "Build integration tests (requires Docker)" OFF)
        if(BUILD_INTEGRATION_TESTS)
            add_subdirectory(tests/integration)
        endif()
    else()
        message(WARNING "GTest not found. Unit tests will not be built.")
        message(STATUS "To build tests, install GTest or set GTEST_ROOT")
    endif()
endif()
