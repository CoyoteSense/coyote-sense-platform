// Main test runner for HTTP Client tests
#include "simple_test_framework.h"
#include <iostream>

int main() {
    std::cout << "HTTP Client C++ Test Suite" << std::endl;
    std::cout << "============================" << std::endl;
    
    int result = g_test_runner.run_all();
    
    if (result == 0) {
        std::cout << "\nAll tests passed!" << std::endl;
    } else {
        std::cout << "\n" << result << " test(s) failed!" << std::endl;
    }
    
    return result;
}
