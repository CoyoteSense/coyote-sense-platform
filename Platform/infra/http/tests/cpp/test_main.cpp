// Main test runner for HTTP Client tests
#include <gtest/gtest.h>
#include <iostream>

int main(int argc, char **argv) {
    std::cout << "HTTP Client C++ Test Suite" << std::endl;
    std::cout << "============================" << std::endl;
    
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
