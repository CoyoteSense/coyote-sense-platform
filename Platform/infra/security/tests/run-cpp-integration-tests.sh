#!/bin/bash

# Build and Run C++ OAuth2 Integration Tests (Bash)

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
TESTS_DIR="$SCRIPT_DIR"
CPP_INTEGRATION_DIR="$TESTS_DIR/cpp/integration"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

function write_success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

function write_error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

function write_info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

function write_warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

function write_banner() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  C++ OAuth2 Integration Tests${NC}"
    echo -e "${BLUE}========================================${NC}"
}

function test_oauth2_server() {
    write_info "Checking OAuth2 server availability..."
    
    if curl -s -f "http://localhost:8081/.well-known/oauth2" > /dev/null 2>&1; then
        write_success "OAuth2 server is running"
        return 0
    else
        write_warning "OAuth2 server is not running"
        write_info "Starting OAuth2 server..."
        
        local server_script="$TESTS_DIR/manage-oauth2-server.sh"
        if [ -f "$server_script" ]; then
            bash "$server_script" start
            if [ $? -eq 0 ]; then
                write_success "OAuth2 server started successfully"
                return 0
            else
                write_error "Failed to start OAuth2 server"
                return 1
            fi
        else
            write_error "OAuth2 server management script not found"
            return 1
        fi
    fi
    
    write_error "OAuth2 server is not available"
    return 1
}

function test_dependencies() {
    write_info "Checking C++ build dependencies..."
    
    # Check for CMake
    if ! command -v cmake &> /dev/null; then
        write_error "CMake not found. Please install CMake."
        return 1
    fi
    
    # Check for C++ compiler
    if ! command -v g++ &> /dev/null && ! command -v clang++ &> /dev/null; then
        write_error "C++ compiler not found. Please install GCC or Clang."
        return 1
    fi
    
    # Check for pkg-config
    if ! command -v pkg-config &> /dev/null; then
        write_error "pkg-config not found. Please install pkg-config."
        return 1
    fi
    
    write_info "Found CMake: $(cmake --version | head -n1)"
    
    if command -v g++ &> /dev/null; then
        write_info "Found G++: $(g++ --version | head -n1)"
    elif command -v clang++ &> /dev/null; then
        write_info "Found Clang++: $(clang++ --version | head -n1)"
    fi
    
    return 0
}

function build_cpp_integration_tests() {
    write_info "Building C++ integration tests..."
    
    # Create build directory
    local build_dir="$CPP_INTEGRATION_DIR/build"
    mkdir -p "$build_dir"
    
    # Change to build directory
    cd "$build_dir"
    
    # Configure with CMake
    write_info "Configuring with CMake..."
    cmake .. -DCMAKE_BUILD_TYPE=Debug
    
    if [ $? -ne 0 ]; then
        write_error "CMake configuration failed"
        return 1
    fi
    
    # Build
    write_info "Building..."
    cmake --build . --config Debug
    
    if [ $? -ne 0 ]; then
        write_error "Build failed"
        return 1
    fi
    
    write_success "C++ integration tests built successfully"
    return 0
}

function run_cpp_integration_tests() {
    write_info "Running C++ integration tests..."
    
    local build_dir="$CPP_INTEGRATION_DIR/build"
    
    if [ ! -d "$build_dir" ]; then
        write_error "Build directory not found. Please build the tests first."
        return 1
    fi
    
    cd "$build_dir"
    
    # Set environment variables for the tests
    export OAUTH2_SERVER_URL="http://localhost:8081"
    export OAUTH2_CLIENT_ID="test-client-id"
    export OAUTH2_CLIENT_SECRET="test-client-secret"
    export OAUTH2_SCOPE="api.read api.write"
    
    # Find the test executable
    local test_exe="real_oauth2_integration_test"
    if [ ! -f "$test_exe" ]; then
        write_error "Test executable not found"
        return 1
    fi
    
    write_info "Running integration tests..."
    write_info "Test executable: $test_exe"
    
    # Run the tests
    ./"$test_exe" --gtest_output=xml:test_results.xml
    
    if [ $? -eq 0 ]; then
        write_success "All C++ integration tests passed!"
        return 0
    else
        write_error "Some C++ integration tests failed"
        return 1
    fi
}

# Main execution
write_banner

# Check dependencies
if ! test_dependencies; then
    write_error "Missing required dependencies"
    exit 1
fi

# Check if OAuth2 server is available
if ! test_oauth2_server; then
    write_error "OAuth2 server is not available"
    write_info "Please start the OAuth2 server first:"
    write_info "  ./manage-oauth2-server.sh start"
    exit 1
fi

# Build the integration tests
if ! build_cpp_integration_tests; then
    write_error "Failed to build C++ integration tests"
    exit 1
fi

# Run the integration tests
if run_cpp_integration_tests; then
    write_success "All C++ integration tests completed successfully!"
    exit 0
else
    write_error "C++ integration tests failed"
    exit 1
fi
