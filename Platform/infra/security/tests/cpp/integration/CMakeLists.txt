cmake_minimum_required(VERSION 3.16)
project(CoyoteSenseCppOAuth2IntegrationTests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(GTest REQUIRED)
find_package(nlohmann_json REQUIRED)

# Find libcurl
pkg_check_modules(CURL REQUIRED libcurl)

# Include directories
include_directories(${GTEST_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/cpp/interfaces)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/cpp/impl)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../mocks)

# Add executable for OAuth2 integration tests
add_executable(real_oauth2_integration_test
    real_oauth2_integration_test.cpp
)

# Link libraries
target_link_libraries(real_oauth2_integration_test
    ${GTEST_LIBRARIES}
    ${CURL_LIBRARIES}
    nlohmann_json::nlohmann_json
    pthread
)

# Add compiler flags
target_compile_options(real_oauth2_integration_test PRIVATE ${CURL_CFLAGS})

# Enable testing
enable_testing()

# Add test to CTest
add_test(NAME RealOAuth2IntegrationTest COMMAND real_oauth2_integration_test)

# Set test properties
set_tests_properties(RealOAuth2IntegrationTest PROPERTIES
    TIMEOUT 60
    ENVIRONMENT "OAUTH2_SERVER_URL=http://localhost:8081;OAUTH2_CLIENT_ID=test-client-id;OAUTH2_CLIENT_SECRET=test-client-secret;OAUTH2_SCOPE=api.read api.write"
)

# Custom target to run integration tests
add_custom_target(run_integration_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --verbose
    DEPENDS real_oauth2_integration_test
    COMMENT "Running C++ OAuth2 integration tests"
)

# Install target
install(TARGETS real_oauth2_integration_test
    RUNTIME DESTINATION bin
)
