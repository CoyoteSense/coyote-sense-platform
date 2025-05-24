# CMakeList.txt : CMake project for BaseUnit
cmake_minimum_required (VERSION 3.8)

# Add source to this project's executable.
add_executable (BaseUnit "BaseUnit.cpp" "ExampleTradingUnit.cpp" "DependencyInjection.cpp")

# Add test executables
add_executable (TestDependencyInjection "TestDependencyInjection.cpp" "DependencyInjection.cpp")
add_executable (UnitTests "UnitTests.cpp" "BaseUnit.cpp" "DependencyInjection.cpp")

# Set C++17 standard
set_property(TARGET BaseUnit PROPERTY CXX_STANDARD 17)

# Link with infrastructure library
target_link_libraries(BaseUnit CoyoteInfra)
target_link_libraries(TestDependencyInjection CoyoteInfra)
target_link_libraries(UnitTests CoyoteInfra)

# Platform-specific settings
if(WIN32)
    target_link_libraries(BaseUnit ws2_32)
    target_link_libraries(TestDependencyInjection ws2_32)
    target_link_libraries(UnitTests ws2_32)
endif()

# Compiler-specific options
if(MSVC)
    target_compile_definitions(BaseUnit PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(TestDependencyInjection PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(UnitTests PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Copy config file to build directory
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.json ${CMAKE_CURRENT_BINARY_DIR}/config.json COPYONLY)
