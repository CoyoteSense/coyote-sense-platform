#!/bin/bash

# Integration test runner for C++ HTTP Client
# This script manages Docker containers and runs integration tests

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR" && pwd)"
COMPOSE_FILE="$PROJECT_ROOT/docker-compose.yml"
TEST_TIMEOUT=300  # 5 minutes

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if Docker is running
check_docker() {
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    log_info "Docker is running"
}

# Function to check if Docker Compose is available
check_docker_compose() {
    if ! command -v docker-compose >/dev/null 2>&1; then
        log_error "Docker Compose is not installed. Please install Docker Compose and try again."
        exit 1
    fi
    log_info "Docker Compose is available"
}

# Function to clean up containers
cleanup() {
    log_info "Cleaning up containers..."
    cd "$PROJECT_ROOT"
    docker-compose down --volumes --remove-orphans >/dev/null 2>&1 || true
    
    # Remove any leftover containers
    docker ps -a --filter "name=http-test-server" --filter "name=cpp-integration-tests" -q | xargs -r docker rm -f >/dev/null 2>&1 || true
    
    # Remove any leftover images if needed
    if [ "$CLEAN_IMAGES" = "true" ]; then
        docker images --filter "reference=http-test-server" --filter "reference=cpp-integration-tests" -q | xargs -r docker rmi -f >/dev/null 2>&1 || true
    fi
}

# Function to build images
build_images() {
    log_info "Building Docker images..."
    cd "$PROJECT_ROOT"
    
    # Build test server image
    log_info "Building test server image..."
    docker build -f test-server.Dockerfile -t http-test-server .
    
    # Build C++ test image
    log_info "Building C++ integration test image..."
    docker build -f cpp-tests.Dockerfile -t cpp-integration-tests ../../../..
    
    log_success "Docker images built successfully"
}

# Function to start test server
start_test_server() {
    log_info "Starting test server..."
    cd "$PROJECT_ROOT"
    
    # Start only the test server
    docker-compose up -d test-server
    
    # Wait for test server to be ready
    log_info "Waiting for test server to be ready..."
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if docker-compose exec -T test-server curl -f http://localhost:8080/health >/dev/null 2>&1; then
            log_success "Test server is ready"
            return 0
        fi
        
        log_info "Waiting for test server... attempt $attempt/$max_attempts"
        sleep 2
        attempt=$((attempt + 1))
    done
    
    log_error "Test server failed to start within timeout"
    docker-compose logs test-server
    return 1
}

# Function to run integration tests
run_tests() {
    log_info "Running C++ integration tests..."
    cd "$PROJECT_ROOT"
    
    # Set environment variables for the test container
    export TEST_SERVER_HOST=test-server
    export TEST_SERVER_HTTP_PORT=8080
    export TEST_SERVER_HTTPS_PORT=8443
    export COYOTE_RUNTIME_MODE=production
    
    # Run the tests
    local exit_code=0
    docker-compose run --rm cpp-tests || exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        log_success "All integration tests passed!"
    else
        log_error "Integration tests failed with exit code $exit_code"
        
        # Show logs for debugging
        log_info "Test server logs:"
        docker-compose logs test-server
    fi
    
    return $exit_code
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -c, --clean          Clean up containers and images before running"
    echo "  -b, --build-only     Only build images, don't run tests"
    echo "  -t, --test-only      Only run tests (assumes images are built)"
    echo "  -s, --server-only    Only start test server (for manual testing)"
    echo "  -l, --logs           Show container logs"
    echo "  -h, --help           Show this help message"
    echo
    echo "Examples:"
    echo "  $0                   # Run full test suite"
    echo "  $0 --clean           # Clean up and run full test suite"
    echo "  $0 --build-only      # Only build Docker images"
    echo "  $0 --test-only       # Run tests (assumes images are built)"
    echo "  $0 --server-only     # Start test server for manual testing"
}

# Function to show logs
show_logs() {
    log_info "Showing container logs..."
    cd "$PROJECT_ROOT"
    docker-compose logs --tail=50
}

# Parse command line arguments
CLEAN_IMAGES=false
BUILD_ONLY=false
TEST_ONLY=false
SERVER_ONLY=false
SHOW_LOGS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--clean)
            CLEAN_IMAGES=true
            shift
            ;;
        -b|--build-only)
            BUILD_ONLY=true
            shift
            ;;
        -t|--test-only)
            TEST_ONLY=true
            shift
            ;;
        -s|--server-only)
            SERVER_ONLY=true
            shift
            ;;
        -l|--logs)
            SHOW_LOGS=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Main execution
main() {
    log_info "Starting C++ HTTP Client Integration Tests"
    log_info "Project root: $PROJECT_ROOT"
    
    # Check prerequisites
    check_docker
    check_docker_compose
    
    # Set up signal handlers for cleanup
    trap cleanup EXIT
    trap 'log_error "Script interrupted"; exit 130' INT TERM
    
    # Clean up if requested
    if [ "$CLEAN_IMAGES" = "true" ]; then
        cleanup
    fi
    
    # Show logs if requested
    if [ "$SHOW_LOGS" = "true" ]; then
        show_logs
        exit 0
    fi
    
    # Build images if not test-only
    if [ "$TEST_ONLY" != "true" ]; then
        build_images
    fi
    
    # Exit if build-only
    if [ "$BUILD_ONLY" = "true" ]; then
        log_success "Build completed successfully"
        exit 0
    fi
    
    # Start test server
    start_test_server
    
    # Exit if server-only
    if [ "$SERVER_ONLY" = "true" ]; then
        log_success "Test server is running. Access it at:"
        log_info "  HTTP:  http://localhost:8080"
        log_info "  HTTPS: https://localhost:8443"
        log_info "Press Ctrl+C to stop the server"
        
        # Keep the script running
        while true; do
            sleep 60
        done
    fi
    
    # Run tests
    run_tests
    local test_exit_code=$?
    
    # Final cleanup is handled by trap
    if [ $test_exit_code -eq 0 ]; then
        log_success "Integration test suite completed successfully!"
    else
        log_error "Integration test suite failed!"
    fi
    
    exit $test_exit_code
}

# Run main function
main "$@"
