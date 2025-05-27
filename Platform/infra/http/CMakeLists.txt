# CMakeLists.txt for Coyote HTTP Client Infrastructure
# Root CMakeLists.txt that delegates to language-specific build scripts

cmake_minimum_required(VERSION 3.16)

# vcpkg integration
if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "")
    message(STATUS "Using vcpkg toolchain: ${CMAKE_TOOLCHAIN_FILE}")
endif()

project(CoyoteHttpClient VERSION 1.0.0 LANGUAGES CXX)

# Forward options for the included CMakeLists.txt
option(BUILD_HTTP_CLIENT_EXAMPLES "Build HTTP client examples" OFF)
option(BUILD_HTTP_CLIENT_TESTS "Build HTTP client tests" OFF)
option(BUILD_INTEGRATION_TESTS "Build integration tests (requires Docker)" OFF)
set(BUILD_HTTP_CLIENT_TESTS ${BUILD_HTTP_CLIENT_TESTS} CACHE BOOL "Build HTTP client tests" FORCE)

# Include the C++ build configuration
include(build-scripts/cpp/CMakeLists.txt)

# Include tests if requested
if(BUILD_HTTP_CLIENT_TESTS)
    enable_testing()
    add_subdirectory(tests/cpp cpp_tests)
endif()
