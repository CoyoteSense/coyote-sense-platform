#!/bin/bash

# OAuth2 Test Server Management Script
# Manages Docker containers for OAuth2 integration testing

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_COMPOSE_FILE="$SCRIPT_DIR/docker-compose.oauth2.yml"

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

usage() {
    cat << EOF
Usage: $0 [COMMAND] [OPTIONS]

Manage OAuth2 test servers for integration testing.

COMMANDS:
    start [server]      Start OAuth2 server(s)
    stop [server]       Stop OAuth2 server(s)
    restart [server]    Restart OAuth2 server(s)
    status              Show status of all servers
    logs [server]       Show logs for server
    test [server]       Test server connectivity
    clean               Stop and remove all containers and volumes

SERVERS:
    mock               OAuth2 Mock Server (recommended for testing)
    keycloak          Keycloak Identity Provider
    hydra             Ory Hydra OAuth2 Server
    spring            Spring Authorization Server
    all               All servers (default)

OPTIONS:
    -h, --help        Show this help message
    -d, --detach      Run in background (detached mode)
    -v, --verbose     Enable verbose output

EXAMPLES:
    $0 start mock                Start OAuth2 Mock Server
    $0 start keycloak -d         Start Keycloak in background
    $0 test mock                 Test OAuth2 Mock Server
    $0 logs keycloak             Show Keycloak logs
    $0 status                    Show status of all servers
    $0 clean                     Clean up all containers

ENDPOINTS (when running):
    OAuth2 Mock Server:    http://localhost:8081
    Keycloak:             http://localhost:8080
    Ory Hydra:            http://localhost:4444
    Spring Auth Server:   http://localhost:9000

EOF
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        print_error "Docker Compose is not installed"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running"
        exit 1
    fi
}

get_compose_command() {
    if command -v docker-compose &> /dev/null; then
        echo "docker-compose"
    else
        echo "docker compose"
    fi
}

start_server() {
    local server="${1:-all}"
    local detach_flag=""
    
    if [ "$DETACH" = true ]; then
        detach_flag="-d"
    fi
    
    local compose_cmd=$(get_compose_command)
    
    print_info "Starting OAuth2 server: $server"
    
    case "$server" in
        "mock")
            $compose_cmd -f "$DOCKER_COMPOSE_FILE" up $detach_flag oauth2-mock
            ;;
        "keycloak")
            $compose_cmd -f "$DOCKER_COMPOSE_FILE" up $detach_flag keycloak
            ;;
        "hydra")
            $compose_cmd -f "$DOCKER_COMPOSE_FILE" up $detach_flag hydra
            ;;
        "spring")
            $compose_cmd -f "$DOCKER_COMPOSE_FILE" up $detach_flag spring-authz
            ;;
        "all")
            $compose_cmd -f "$DOCKER_COMPOSE_FILE" up $detach_flag
            ;;
        *)
            print_error "Unknown server: $server"
            usage
            exit 1
            ;;
    esac
    
    if [ "$DETACH" = true ]; then
        print_success "Started $server in background"
        print_info "Use '$0 logs $server' to view logs"
        print_info "Use '$0 status' to check status"
    fi
}

stop_server() {
    local server="${1:-all}"
    local compose_cmd=$(get_compose_command)
    
    print_info "Stopping OAuth2 server: $server"
    
    case "$server" in
        "mock")
            $compose_cmd -f "$DOCKER_COMPOSE_FILE" stop oauth2-mock
            ;;
        "keycloak")
            $compose_cmd -f "$DOCKER_COMPOSE_FILE" stop keycloak
            ;;
        "hydra")
            $compose_cmd -f "$DOCKER_COMPOSE_FILE" stop hydra
            ;;
        "spring")
            $compose_cmd -f "$DOCKER_COMPOSE_FILE" stop spring-authz
            ;;
        "all")
            $compose_cmd -f "$DOCKER_COMPOSE_FILE" stop
            ;;
        *)
            print_error "Unknown server: $server"
            usage
            exit 1
            ;;
    esac
    
    print_success "Stopped $server"
}

restart_server() {
    local server="${1:-all}"
    
    print_info "Restarting OAuth2 server: $server"
    stop_server "$server"
    sleep 2
    start_server "$server"
}

show_status() {
    local compose_cmd=$(get_compose_command)
    
    print_info "OAuth2 Test Servers Status:"
    echo ""
    
    $compose_cmd -f "$DOCKER_COMPOSE_FILE" ps
    
    echo ""
    print_info "Service URLs:"
    echo "  OAuth2 Mock Server:    http://localhost:8081"
    echo "  Keycloak:             http://localhost:8080"
    echo "  Ory Hydra:            http://localhost:4444"
    echo "  Spring Auth Server:   http://localhost:9000"
}

show_logs() {
    local server="${1:-all}"
    local compose_cmd=$(get_compose_command)
    
    case "$server" in
        "mock")
            $compose_cmd -f "$DOCKER_COMPOSE_FILE" logs -f oauth2-mock
            ;;
        "keycloak")
            $compose_cmd -f "$DOCKER_COMPOSE_FILE" logs -f keycloak
            ;;
        "hydra")
            $compose_cmd -f "$DOCKER_COMPOSE_FILE" logs -f hydra
            ;;
        "spring")
            $compose_cmd -f "$DOCKER_COMPOSE_FILE" logs -f spring-authz
            ;;
        "all")
            $compose_cmd -f "$DOCKER_COMPOSE_FILE" logs -f
            ;;
        *)
            print_error "Unknown server: $server"
            usage
            exit 1
            ;;
    esac
}

test_server() {
    local server="${1:-mock}"
    
    print_info "Testing OAuth2 server: $server"
    
    local url=""
    local well_known_endpoint=""
    
    case "$server" in
        "mock")
            url="http://localhost:8081"
            well_known_endpoint="$url/.well-known/openid_configuration"
            ;;
        "keycloak")
            url="http://localhost:8080"
            well_known_endpoint="$url/realms/coyote-test/.well-known/openid_configuration"
            ;;
        "hydra")
            url="http://localhost:4444"
            well_known_endpoint="$url/.well-known/openid_configuration"
            ;;
        "spring")
            url="http://localhost:9000"
            well_known_endpoint="$url/.well-known/openid_configuration"
            ;;
        *)
            print_error "Unknown server: $server"
            exit 1
            ;;
    esac
    
    # Test basic connectivity
    print_info "Testing connectivity to $url..."
    if curl -s -f "$url" > /dev/null 2>&1; then
        print_success "Server is responding"
    else
        print_error "Server is not responding"
        return 1
    fi
    
    # Test OpenID configuration
    print_info "Testing OpenID configuration endpoint..."
    if curl -s -f "$well_known_endpoint" > /dev/null 2>&1; then
        print_success "OpenID configuration endpoint is working"
    else
        print_warning "OpenID configuration endpoint is not available"
    fi
    
    # Test OAuth2 token endpoint for mock server
    if [ "$server" = "mock" ]; then
        print_info "Testing OAuth2 token endpoint..."
        local token_response=$(curl -s -X POST "$url/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "grant_type=client_credentials&client_id=test-client-id&client_secret=test-client-secret&scope=api.read")
        
        if echo "$token_response" | grep -q "access_token"; then
            print_success "OAuth2 token endpoint is working"
        else
            print_warning "OAuth2 token endpoint test failed"
        fi
    fi
    
    print_success "Server $server is ready for integration tests"
}

clean_all() {
    local compose_cmd=$(get_compose_command)
    
    print_info "Cleaning up all OAuth2 test containers..."
    
    $compose_cmd -f "$DOCKER_COMPOSE_FILE" down -v --remove-orphans
    
    print_success "All containers and volumes removed"
}

# Parse command line arguments
COMMAND=""
SERVER=""
DETACH=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        start|stop|restart|status|logs|test|clean)
            COMMAND="$1"
            shift
            ;;
        mock|keycloak|hydra|spring|all)
            SERVER="$1"
            shift
            ;;
        -d|--detach)
            DETACH=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            if [ -z "$COMMAND" ]; then
                COMMAND="$1"
            elif [ -z "$SERVER" ]; then
                SERVER="$1"
            else
                print_error "Unknown option: $1"
                usage
                exit 1
            fi
            shift
            ;;
    esac
done

# Set defaults
if [ -z "$COMMAND" ]; then
    COMMAND="status"
fi

if [ -z "$SERVER" ] && [ "$COMMAND" != "status" ] && [ "$COMMAND" != "clean" ]; then
    SERVER="mock"
fi

# Check Docker availability
check_docker

# Execute command
case "$COMMAND" in
    "start")
        start_server "$SERVER"
        ;;
    "stop")
        stop_server "$SERVER"
        ;;
    "restart")
        restart_server "$SERVER"
        ;;
    "status")
        show_status
        ;;
    "logs")
        show_logs "$SERVER"
        ;;
    "test")
        test_server "$SERVER"
        ;;
    "clean")
        clean_all
        ;;
    *)
        print_error "Unknown command: $COMMAND"
        usage
        exit 1
        ;;
esac
