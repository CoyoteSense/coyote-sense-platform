#!/bin/bash

# TypeScript OAuth2 Integration Tests Runner (Bash)
#
# This script runs the TypeScript OAuth2 integration tests against a real OAuth2 server.
# It ensures the OAuth2 server is running before executing the tests.
#
# Usage:
#   ./run-typescript-integration-tests.sh [--skip-server-check] [--verbose] [--coverage]
#
# Options:
#   --skip-server-check  Skip checking if the OAuth2 server is running
#   --verbose           Enable verbose output for debugging
#   --coverage          Run tests with coverage reporting
#   --help             Show this help message

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default options
SKIP_SERVER_CHECK=false
VERBOSE=false
COVERAGE=false

# Function to print colored output
print_color() {
    local color=$1
    local message=$2
    printf "${color}${message}${NC}\n"
}

# Function to show help
show_help() {
    cat << EOF
TypeScript OAuth2 Integration Tests Runner

Usage: $0 [OPTIONS]

Options:
    --skip-server-check    Skip checking if the OAuth2 server is running
    --verbose             Enable verbose output for debugging
    --coverage            Run tests with coverage reporting
    --help               Show this help message

Examples:
    $0                           # Run integration tests with server check
    $0 --verbose --coverage      # Run tests with verbose output and coverage
    $0 --skip-server-check       # Run tests without checking server status
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-server-check)
            SKIP_SERVER_CHECK=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --coverage)
            COVERAGE=true
            shift
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            print_color $RED "❌ Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Function to test if OAuth2 server is running
test_oauth2_server() {
    if curl -s -f --max-time 5 "http://localhost:8081/health" > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Function to start OAuth2 server
start_oauth2_server() {
    print_color $BLUE "Starting OAuth2 server..."
    
    local docker_compose_file="docker-compose.oauth2.yml"
    if [[ ! -f "$docker_compose_file" ]]; then
        print_color $RED "❌ Error: $docker_compose_file not found in current directory"
        print_color $YELLOW "   Please run this script from the project root directory"
        exit 1
    fi
    
    if ! docker-compose -f "$docker_compose_file" up -d; then
        print_color $RED "❌ Failed to start OAuth2 server"
        exit 1
    fi
    
    # Wait for server to be ready
    local max_attempts=30
    local attempt=0
    
    while [[ $attempt -lt $max_attempts ]]; do
        if test_oauth2_server; then
            print_color $GREEN "✅ OAuth2 server is ready"
            return 0
        fi
        
        ((attempt++))
        echo "⏳ Waiting for OAuth2 server to start... ($attempt/$max_attempts)"
        sleep 2
    done
    
    print_color $RED "❌ OAuth2 server failed to start within expected time"
    exit 1
}

# Function to check and install Node.js dependencies
check_node_modules() {
    local package_json_path="Platform/infra/security/tests/ts/package.json"
    local node_modules_path="Platform/infra/security/tests/ts/node_modules"
    
    if [[ ! -f "$package_json_path" ]]; then
        print_color $RED "❌ Error: $package_json_path not found"
        return 1
    fi
    
    if [[ ! -d "$node_modules_path" ]]; then
        print_color $BLUE "📦 Installing TypeScript test dependencies..."
        
        if ! (cd "Platform/infra/security/tests/ts" && npm install); then
            print_color $RED "❌ Failed to install dependencies"
            return 1
        fi
    fi
    
    return 0
}

# Main execution
print_color $BLUE "🧪 TypeScript OAuth2 Integration Tests Runner"
print_color $BLUE "============================================="

# Check if we're in the correct directory
if [[ ! -f "Platform/infra/security/tests/ts/package.json" ]]; then
    print_color $RED "❌ Error: Not in project root directory"
    print_color $YELLOW "   Please run this script from the CoyoteSense platform root"
    exit 1
fi

# Check Node.js and npm
if ! command -v node &> /dev/null; then
    print_color $RED "❌ Error: Node.js not found"
    print_color $YELLOW "   Please install Node.js from https://nodejs.org/"
    exit 1
fi

if ! command -v npm &> /dev/null; then
    print_color $RED "❌ Error: npm not found"
    print_color $YELLOW "   Please install npm (usually comes with Node.js)"
    exit 1
fi

node_version=$(node --version)
npm_version=$(npm --version)
print_color $GREEN "📋 Node.js version: $node_version"
print_color $GREEN "📋 npm version: $npm_version"

# Install dependencies if needed
if ! check_node_modules; then
    exit 1
fi

# Check OAuth2 server status
if [[ "$SKIP_SERVER_CHECK" != "true" ]]; then
    print_color $BLUE "🔍 Checking OAuth2 server status..."
    
    if ! test_oauth2_server; then
        print_color $YELLOW "⚠️  OAuth2 server not running"
        print_color $BLUE "   Attempting to start OAuth2 server..."
        start_oauth2_server
    else
        print_color $GREEN "✅ OAuth2 server is already running"
    fi
fi

# Set test environment variables
export NODE_ENV="test"
export AUTH_TEST_SERVER_URL="http://localhost:8081"
export AUTH_TEST_CLIENT_ID="test-client-id"
export AUTH_TEST_CLIENT_SECRET="test-client-secret"

if [[ "$VERBOSE" == "true" ]]; then
    export AUTH_TEST_DEBUG="true"
fi

# Build Jest command
jest_args=(
    "--testPathPattern=real-oauth2-integration"
    "--verbose"
)

if [[ "$COVERAGE" == "true" ]]; then
    jest_args+=("--coverage")
fi

if [[ "$VERBOSE" == "true" ]]; then
    jest_args+=("--detectOpenHandles")
    jest_args+=("--forceExit")
fi

# Run the tests
print_color $BLUE "🚀 Running TypeScript integration tests..."
print_color $BLUE "   Test file: real-oauth2-integration.test.ts"
print_color $BLUE "   OAuth2 server: http://localhost:8081"

jest_command="npx jest ${jest_args[*]}"
print_color $BLUE "   Command: $jest_command"

if (cd "Platform/infra/security/tests/ts" && eval "$jest_command"); then
    print_color $GREEN "✅ All TypeScript integration tests passed!"
    exit 0
else
    print_color $RED "❌ Some TypeScript integration tests failed"
    exit 1
fi
