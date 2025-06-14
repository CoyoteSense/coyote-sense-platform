cmake_minimum_required(VERSION 3.20)
project(coyote_infra_log)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories
include_directories(
    include/log/interfaces
    src/impl
)

# Find all source files
file(GLOB_RECURSE SOURCES
    "src/impl/**/*.cpp"
    "factory/*.cpp"
)

# Create library
add_library(coyote_infra_log ${SOURCES})

# Set target properties
target_include_directories(coyote_infra_log 
    PUBLIC include/log/interfaces
    PRIVATE src/impl
)

# Add tests if they exist
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../tests/cpp")
    enable_testing()
    add_subdirectory(../../tests/cpp tests)
endif()
