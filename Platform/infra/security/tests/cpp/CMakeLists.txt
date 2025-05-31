cmake_minimum_required(VERSION 3.16)
project(OAuth2AuthClientTests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set default build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# Compiler-specific options
if(MSVC)
    add_compile_options(/W4 /permissive-)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(/Od /MDd)
    else()
        add_compile_options(/O2 /MD)
    endif()
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -O0)
    else()
        add_compile_options(-O2)
    endif()
endif()

# Enable coverage if requested
option(ENABLE_COVERAGE "Enable code coverage" OFF)
if(ENABLE_COVERAGE AND NOT MSVC)
    add_compile_options(--coverage)
    add_link_options(--coverage)
endif()

# Find required packages
find_package(PkgConfig)

# Google Test
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Google Mock (included with Google Test)
enable_testing()

# Find OpenSSL for JWT support
find_package(OpenSSL REQUIRED)

# Find curl for HTTP client
if(WIN32)
    # On Windows, you might need to specify curl path
    find_package(CURL REQUIRED)
else()
    # On Unix-like systems
    pkg_check_modules(CURL REQUIRED libcurl)
endif()

# Find JSON library (nlohmann/json)
FetchContent_Declare(
    json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.2
)
FetchContent_MakeAvailable(json)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/mocks
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../
)

# OAuth2 client library sources
set(OAUTH2_CLIENT_SOURCES
    ../../../cpp/oauth2_auth_client.cpp
    # Add other OAuth2 client source files as needed
)

# Test sources
set(TEST_SOURCES
    unit/oauth2_auth_client_test.cpp
    # Add other test source files as needed
)

# Integration test sources
set(INTEGRATION_TEST_SOURCES
    integration/oauth2_integration_test.cpp
    # Add other integration test source files as needed
)

# Mock sources
set(MOCK_SOURCES
    mocks/oauth2_test_mocks.h
    # Add other mock source files as needed
)

# Create unit test executable
add_executable(oauth2_auth_client_test
    ${TEST_SOURCES}
    ${OAUTH2_CLIENT_SOURCES}
)

# Create integration test executable
add_executable(oauth2_integration_test
    ${INTEGRATION_TEST_SOURCES}
    ${OAUTH2_CLIENT_SOURCES}
)

# Link libraries for unit tests
target_link_libraries(oauth2_auth_client_test
    gtest_main
    gmock_main
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

# Link libraries for integration tests
target_link_libraries(oauth2_integration_test
    gtest_main
    gmock_main
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

# Link curl for unit tests
if(WIN32)
    target_link_libraries(oauth2_auth_client_test CURL::libcurl)
    target_link_libraries(oauth2_integration_test CURL::libcurl)
else()
    target_link_libraries(oauth2_auth_client_test ${CURL_LIBRARIES})
    target_include_directories(oauth2_auth_client_test PRIVATE ${CURL_INCLUDE_DIRS})
    target_compile_options(oauth2_auth_client_test PRIVATE ${CURL_CFLAGS_OTHER})
    
    target_link_libraries(oauth2_integration_test ${CURL_LIBRARIES})
    target_include_directories(oauth2_integration_test PRIVATE ${CURL_INCLUDE_DIRS})
    target_compile_options(oauth2_integration_test PRIVATE ${CURL_CFLAGS_OTHER})
endif()

# Platform-specific libraries
if(WIN32)
    target_link_libraries(oauth2_auth_client_test ws2_32 crypt32)
    target_link_libraries(oauth2_integration_test ws2_32 crypt32)
elseif(UNIX)
    target_link_libraries(oauth2_auth_client_test pthread)
    target_link_libraries(oauth2_integration_test pthread)
endif()

# Compiler definitions
target_compile_definitions(oauth2_auth_client_test PRIVATE
    OAUTH2_CLIENT_TESTING=1
)

target_compile_definitions(oauth2_integration_test PRIVATE
    OAUTH2_CLIENT_TESTING=1
    OAUTH2_INTEGRATION_TESTING=1
)

# Add test discovery
include(GoogleTest)
gtest_discover_tests(oauth2_auth_client_test)
gtest_discover_tests(oauth2_integration_test)

# Custom targets for running tests
add_custom_target(run_unit_tests
    COMMAND oauth2_auth_client_test
    DEPENDS oauth2_auth_client_test
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

add_custom_target(run_integration_tests
    COMMAND oauth2_integration_test
    DEPENDS oauth2_integration_test
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

add_custom_target(run_all_tests
    COMMAND oauth2_auth_client_test
    COMMAND oauth2_integration_test
    DEPENDS oauth2_auth_client_test oauth2_integration_test
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Legacy target for backward compatibility
add_custom_target(run_tests
    DEPENDS run_all_tests
)

# Coverage target
if(ENABLE_COVERAGE AND NOT MSVC)
    find_program(GCOV_PATH gcov)
    find_program(LCOV_PATH lcov)
    find_program(GENHTML_PATH genhtml)
    
    if(GCOV_PATH AND LCOV_PATH AND GENHTML_PATH)
        add_custom_target(coverage
            COMMAND ${LCOV_PATH} --directory . --zerocounters
            COMMAND oauth2_auth_client_test
            COMMAND oauth2_integration_test
            COMMAND ${LCOV_PATH} --directory . --capture --output-file coverage.info
            COMMAND ${LCOV_PATH} --remove coverage.info '/usr/*' '*test*' '*mock*' '*gtest*' '*gmock*' --output-file coverage.info.cleaned
            COMMAND ${GENHTML_PATH} -o coverage coverage.info.cleaned
            COMMAND ${CMAKE_COMMAND} -E remove coverage.info coverage.info.cleaned
            DEPENDS oauth2_auth_client_test oauth2_integration_test
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating code coverage report"
        )
    endif()
endif()

# Install target (optional)
install(TARGETS oauth2_auth_client_test oauth2_integration_test
    RUNTIME DESTINATION bin
)

# CPack configuration for packaging
set(CPACK_PACKAGE_NAME "OAuth2AuthClientTests")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "OAuth2 Authentication Client Test Suite")
set(CPACK_PACKAGE_VENDOR "CoyoteSense Platform Team")

include(CPack)

# Print configuration summary
message(STATUS "OAuth2 Auth Client Tests Configuration:")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Coverage enabled: ${ENABLE_COVERAGE}")
message(STATUS "  OpenSSL version: ${OPENSSL_VERSION}")
if(WIN32)
    message(STATUS "  CURL version: ${CURL_VERSION_STRING}")
else()
    message(STATUS "  CURL version: ${CURL_VERSION}")
endif()
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")

# Additional build configuration for different platforms
if(APPLE)
    # macOS specific settings
    set_target_properties(oauth2_auth_client_test PROPERTIES
        MACOSX_RPATH ON
        INSTALL_RPATH "@loader_path/../lib"
    )
elseif(UNIX)
    # Linux specific settings
    set_target_properties(oauth2_auth_client_test PROPERTIES
        INSTALL_RPATH "$ORIGIN/../lib"
    )
endif()

# Sanitizer support for debugging
option(ENABLE_SANITIZERS "Enable sanitizers for debugging" OFF)
if(ENABLE_SANITIZERS AND NOT MSVC)
    target_compile_options(oauth2_auth_client_test PRIVATE
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
    )
    target_link_options(oauth2_auth_client_test PRIVATE
        -fsanitize=address,undefined
    )
    
    target_compile_options(oauth2_integration_test PRIVATE
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
    )
    target_link_options(oauth2_integration_test PRIVATE
        -fsanitize=address,undefined
    )
endif()

# Documentation generation
find_package(Doxygen)
if(DOXYGEN_FOUND)
    set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
    set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
    
    if(EXISTS ${DOXYGEN_IN})
        configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
        
        add_custom_target(docs
            COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating API documentation with Doxygen"
            VERBATIM
        )
    endif()
endif()
