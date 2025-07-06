cmake_minimum_required(VERSION 3.16)
project(SecurityTests)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable testing
enable_testing()

# Add the comprehensive security test
add_executable(comprehensive_security_test comprehensive_security_test.cpp)

# Add the test to CTest
add_test(NAME ComprehensiveSecurityTest COMMAND comprehensive_security_test)

# Set test properties
set_tests_properties(ComprehensiveSecurityTest PROPERTIES
    PASS_REGULAR_EXPRESSION "All tests passed!"
)
