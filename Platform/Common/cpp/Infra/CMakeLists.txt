# CMakeList.txt : CMake project for Infrastructure components
cmake_minimum_required (VERSION 3.8)

project(CoyoteInfra)

# Set C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)

# Find hiredis
pkg_check_modules(HIREDIS REQUIRED hiredis)

# Find libcurl
find_package(CURL REQUIRED)

# Find nlohmann/json
find_package(nlohmann_json REQUIRED)

# Find yaml-cpp
find_package(yaml-cpp REQUIRED)

# Create infrastructure library
add_library(CoyoteInfra STATIC
    RedisClient.cpp
    SecureStore.cpp
    ConfigReader.cpp
    HttpClient.cpp
)

# Set include directories
target_include_directories(CoyoteInfra PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(CoyoteInfra PRIVATE ${HIREDIS_INCLUDE_DIRS})

# Link libraries
target_link_libraries(CoyoteInfra 
    ${HIREDIS_LIBRARIES}
    CURL::libcurl
    nlohmann_json::nlohmann_json
    yaml-cpp
)

# Platform-specific settings
if(WIN32)
    target_link_libraries(CoyoteInfra ws2_32 wldap32 crypt32)
endif()

# Compiler-specific options
if(MSVC)
    target_compile_definitions(CoyoteInfra PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Export the library for use by other projects
set_target_properties(CoyoteInfra PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)
