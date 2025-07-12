#!/bin/bash

# OAuth2 Test Server Management Script
# Manages the OAuth2 Mock Server for integration testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_COMPOSE_FILE="$SCRIPT_DIR/docker-compose.oauth2.yml"
OAUTH2_SERVER_URL="http://localhost:8081"

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

start_oauth2_server() {
    print_info "Starting OAuth2 Mock Server..."
    
    if ! command -v docker-compose &> /dev/null && ! command -v docker &> /dev/null; then
        print_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    # Use docker compose (new) or docker-compose (legacy)
    if command -v docker &> /dev/null && docker compose version &> /dev/null; then
        DOCKER_CMD="docker compose"
    elif command -v docker-compose &> /dev/null; then
        DOCKER_CMD="docker-compose"
    else
        print_error "Neither 'docker compose' nor 'docker-compose' is available"
        exit 1
    fi
    
    print_info "Using command: $DOCKER_CMD"
    
    # Start the OAuth2 server
    $DOCKER_CMD -f "$DOCKER_COMPOSE_FILE" up -d oauth2-mock
    
    if [ $? -eq 0 ]; then
        print_success "OAuth2 Mock Server started successfully"
        print_info "Server URL: $OAUTH2_SERVER_URL"
        print_info "Waiting for server to be ready..."
        
        # Wait for server to be ready
        local retries=30
        local count=0
        while [ $count -lt $retries ]; do
            if curl -s "$OAUTH2_SERVER_URL/.well-known/oauth2" > /dev/null 2>&1; then
                print_success "OAuth2 server is ready!"
                return 0
            fi
            echo -n "."
            sleep 1
            count=$((count + 1))
        done
        
        print_error "OAuth2 server did not become ready within 30 seconds"
        return 1
    else
        print_error "Failed to start OAuth2 Mock Server"
        return 1
    fi
}

stop_oauth2_server() {
    print_info "Stopping OAuth2 Mock Server..."
    
    # Use docker compose (new) or docker-compose (legacy)
    if command -v docker &> /dev/null && docker compose version &> /dev/null; then
        DOCKER_CMD="docker compose"
    elif command -v docker-compose &> /dev/null; then
        DOCKER_CMD="docker-compose"
    else
        print_error "Neither 'docker compose' nor 'docker-compose' is available"
        exit 1
    fi
    
    $DOCKER_CMD -f "$DOCKER_COMPOSE_FILE" down
    
    if [ $? -eq 0 ]; then
        print_success "OAuth2 Mock Server stopped successfully"
    else
        print_error "Failed to stop OAuth2 Mock Server"
        return 1
    fi
}

check_oauth2_server() {
    print_info "Checking OAuth2 Mock Server status..."
    
    if curl -s "$OAUTH2_SERVER_URL/.well-known/oauth2" > /dev/null 2>&1; then
        print_success "OAuth2 server is running and accessible"
        print_info "Server URL: $OAUTH2_SERVER_URL"
        return 0
    else
        print_error "OAuth2 server is not accessible"
        return 1
    fi
}

test_oauth2_server() {
    print_info "Testing OAuth2 Mock Server..."
    
    # Test client credentials flow
    print_info "Testing client credentials flow..."
    
    local token_response=$(curl -s -X POST "$OAUTH2_SERVER_URL/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&client_id=test-client-id&client_secret=test-client-secret&scope=api.read api.write")
    
    if [ $? -eq 0 ] && echo "$token_response" | grep -q "access_token"; then
        print_success "Client credentials flow works!"
        print_info "Token response: $token_response"
    else
        print_error "Client credentials flow failed"
        print_error "Response: $token_response"
        return 1
    fi
    
    # Test server discovery
    print_info "Testing server discovery..."
    
    local discovery_response=$(curl -s "$OAUTH2_SERVER_URL/.well-known/oauth2")
    
    if [ $? -eq 0 ] && echo "$discovery_response" | grep -q "token_endpoint"; then
        print_success "Server discovery works!"
        print_info "Discovery response: $discovery_response"
    else
        print_error "Server discovery failed"
        print_error "Response: $discovery_response"
        return 1
    fi
    
    return 0
}

usage() {
    echo "Usage: $0 [start|stop|status|test|restart]"
    echo ""
    echo "Commands:"
    echo "  start    - Start the OAuth2 Mock Server"
    echo "  stop     - Stop the OAuth2 Mock Server"
    echo "  status   - Check if the OAuth2 Mock Server is running"
    echo "  test     - Test the OAuth2 Mock Server functionality"
    echo "  restart  - Restart the OAuth2 Mock Server"
    echo ""
}

main() {
    case "${1:-}" in
        start)
            start_oauth2_server
            ;;
        stop)
            stop_oauth2_server
            ;;
        status)
            check_oauth2_server
            ;;
        test)
            test_oauth2_server
            ;;
        restart)
            stop_oauth2_server
            sleep 2
            start_oauth2_server
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
