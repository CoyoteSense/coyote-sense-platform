#!/bin/bash

# Run C# Integration Tests with Real OAuth2 Server

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$SCRIPT_DIR"
DOTNET_TEST_DIR="$TESTS_DIR/dotnet"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_banner() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  C# OAuth2 Integration Tests${NC}"
    echo -e "${BLUE}========================================${NC}"
}

check_oauth2_server() {
    print_info "Checking OAuth2 server availability..."
    
    if curl -s "http://localhost:8081/.well-known/oauth2" > /dev/null 2>&1; then
        print_success "OAuth2 server is running"
        return 0
    else
        print_warning "OAuth2 server is not running"
        print_info "Starting OAuth2 server..."
        
        # Try to start the server
        if [ -f "$TESTS_DIR/manage-oauth2-server.sh" ]; then
            chmod +x "$TESTS_DIR/manage-oauth2-server.sh"
            "$TESTS_DIR/manage-oauth2-server.sh" start
            if [ $? -eq 0 ]; then
                print_success "OAuth2 server started successfully"
                return 0
            else
                print_error "Failed to start OAuth2 server"
                return 1
            fi
        else
            print_error "OAuth2 server management script not found"
            print_info "Please start the OAuth2 server manually:"
            print_info "  ./manage-oauth2-server.sh start"
            return 1
        fi
    fi
}

run_integration_tests() {
    print_info "Running C# integration tests..."
    
    cd "$DOTNET_TEST_DIR"
    
    # Run only integration tests with real server
    local test_filter="Category=Integration&Category=RealServer"
    
    print_info "Test filter: $test_filter"
    
    if dotnet test --filter "$test_filter" --logger "console;verbosity=detailed" --no-build; then
        print_success "C# integration tests passed!"
        return 0
    else
        print_error "C# integration tests failed"
        return 1
    fi
}

main() {
    print_banner
    
    # Check if .NET is available
    if ! command -v dotnet &> /dev/null; then
        print_error ".NET SDK not found"
        exit 1
    fi
    
    # Check OAuth2 server
    if ! check_oauth2_server; then
        print_error "OAuth2 server is not available"
        print_info "Please start the OAuth2 server first:"
        print_info "  ./manage-oauth2-server.sh start"
        exit 1
    fi
    
    # Build the project first
    print_info "Building C# test project..."
    cd "$DOTNET_TEST_DIR"
    
    if dotnet build > /dev/null 2>&1; then
        print_success "C# project built successfully"
    else
        print_error "C# project build failed"
        exit 1
    fi
    
    # Run integration tests
    if run_integration_tests; then
        print_success "All integration tests passed!"
        exit 0
    else
        print_error "Integration tests failed"
        exit 1
    fi
}

main "$@"
