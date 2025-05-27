// simple_test_framework.h
// Compatibility layer for transitioning from simple test framework to Google Test
#pragma once

#include <gtest/gtest.h>

// Map simple test framework macros to Google Test macros
#define ASSERT_NOT_NULL(x) ASSERT_NE(x, nullptr)

// Global test runner is not needed with Google Test
struct TestRunner {
    int run_all() { return 0; }
};

// Create a dummy instance for compatibility
static TestRunner g_test_runner;