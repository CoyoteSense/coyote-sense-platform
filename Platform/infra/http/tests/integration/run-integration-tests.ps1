# PowerShell Integration Test Runner for C++ HTTP Client
# This script manages Docker containers and runs integration tests on Windows

param(
    [switch]$Clean,
    [switch]$BuildOnly,
    [switch]$TestOnly, 
    [switch]$ServerOnly,
    [switch]$Logs,
    [switch]$Help
)

# Configuration
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = $ScriptDir
$ComposeFile = Join-Path $ProjectRoot "docker-compose.yml"
$TestTimeout = 300  # 5 minutes

# Colors for output
$RED = "Red"
$GREEN = "Green"
$YELLOW = "Yellow"
$BLUE = "Blue"

# Logging functions
function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor $BLUE
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor $GREEN
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor $YELLOW
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor $RED
}

# Function to check if Docker is running
function Test-Docker {
    try {
        docker info | Out-Null
        Write-Info "Docker is running"
        return $true
    }
    catch {
        Write-Error "Docker is not running. Please start Docker and try again."
        return $false
    }
}

# Function to check if Docker Compose is available
function Test-DockerCompose {
    try {
        docker-compose --version | Out-Null
        Write-Info "Docker Compose is available"
        return $true
    }
    catch {
        Write-Error "Docker Compose is not installed. Please install Docker Compose and try again."
        return $false
    }
}

# Function to clean up containers
function Invoke-Cleanup {
    Write-Info "Cleaning up containers..."
    Set-Location $ProjectRoot
    
    try {
        docker-compose down --volumes --remove-orphans 2>$null | Out-Null
    }
    catch {
        # Ignore errors during cleanup
    }
    
    # Remove any leftover containers
    $containers = docker ps -a --filter "name=http-test-server" --filter "name=cpp-integration-tests" -q
    if ($containers) {
        docker rm -f $containers 2>$null | Out-Null
    }
    
    # Remove any leftover images if needed
    if ($Clean) {
        $images = docker images --filter "reference=http-test-server" --filter "reference=cpp-integration-tests" -q
        if ($images) {
            docker rmi -f $images 2>$null | Out-Null
        }
    }
}

# Function to build images
function Invoke-BuildImages {
    Write-Info "Building Docker images..."
    Set-Location $ProjectRoot
    
    try {
        Write-Info "Building test server image..."
        docker build -f test-server.Dockerfile -t http-test-server .
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to build test server image"
        }
        
        Write-Info "Building C++ integration test image..."
        docker build -f cpp-tests.Dockerfile -t cpp-integration-tests ../../../..
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to build C++ integration test image"
        }
        
        Write-Success "Docker images built successfully"
        return $true
    }
    catch {
        Write-Error "Failed to build Docker images: $_"
        return $false
    }
}

# Function to start test server
function Start-TestServer {
    Write-Info "Starting test server..."
    Set-Location $ProjectRoot
    
    try {
        # Start only the test server
        docker-compose up -d test-server
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to start test server"
        }
        
        # Wait for test server to be ready
        Write-Info "Waiting for test server to be ready..."
        $maxAttempts = 30
        $attempt = 1
        
        do {
            try {
                $response = docker-compose exec -T test-server curl -f http://localhost:8080/health 2>$null
                if ($LASTEXITCODE -eq 0) {
                    Write-Success "Test server is ready"
                    return $true
                }
            }
            catch {
                # Ignore curl errors
            }
            
            Write-Info "Waiting for test server... attempt $attempt/$maxAttempts"
            Start-Sleep -Seconds 2
            $attempt++
        } while ($attempt -le $maxAttempts)
        
        Write-Error "Test server failed to start within timeout"
        docker-compose logs test-server
        return $false
    }
    catch {
        Write-Error "Failed to start test server: $_"
        return $false
    }
}

# Function to run integration tests
function Invoke-Tests {
    Write-Info "Running C++ integration tests..."
    Set-Location $ProjectRoot
    
    try {
        # Set environment variables for the test container
        $env:TEST_SERVER_HOST = "test-server"
        $env:TEST_SERVER_HTTP_PORT = "8080"
        $env:TEST_SERVER_HTTPS_PORT = "8443"
        $env:COYOTE_RUNTIME_MODE = "production"
        
        # Run the tests
        docker-compose run --rm cpp-tests
        $exitCode = $LASTEXITCODE
        
        if ($exitCode -eq 0) {
            Write-Success "All integration tests passed!"
            return $true
        }
        else {
            Write-Error "Integration tests failed with exit code $exitCode"
            
            # Show logs for debugging
            Write-Info "Test server logs:"
            docker-compose logs test-server
            return $false
        }
    }
    catch {
        Write-Error "Failed to run integration tests: $_"
        return $false
    }
}

# Function to show usage
function Show-Usage {
    Write-Host "Usage: .\run-integration-tests.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Clean           Clean up containers and images before running"
    Write-Host "  -BuildOnly       Only build images, don't run tests"
    Write-Host "  -TestOnly        Only run tests (assumes images are built)"
    Write-Host "  -ServerOnly      Only start test server (for manual testing)"
    Write-Host "  -Logs            Show container logs"
    Write-Host "  -Help            Show this help message"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\run-integration-tests.ps1                   # Run full test suite"
    Write-Host "  .\run-integration-tests.ps1 -Clean            # Clean up and run full test suite"
    Write-Host "  .\run-integration-tests.ps1 -BuildOnly        # Only build Docker images"
    Write-Host "  .\run-integration-tests.ps1 -TestOnly         # Run tests (assumes images are built)"
    Write-Host "  .\run-integration-tests.ps1 -ServerOnly       # Start test server for manual testing"
}

# Function to show logs
function Show-Logs {
    Write-Info "Showing container logs..."
    Set-Location $ProjectRoot
    docker-compose logs --tail=50
}

# Main execution
function Main {
    Write-Info "Starting C++ HTTP Client Integration Tests"
    Write-Info "Project root: $ProjectRoot"
    
    # Show usage if requested
    if ($Help) {
        Show-Usage
        exit 0
    }
    
    # Check prerequisites
    if (-not (Test-Docker)) {
        exit 1
    }
    
    if (-not (Test-DockerCompose)) {
        exit 1
    }
    
    # Clean up if requested
    if ($Clean) {
        Invoke-Cleanup
    }
    
    # Show logs if requested
    if ($Logs) {
        Show-Logs
        exit 0
    }
    
    try {
        # Build images if not test-only
        if (-not $TestOnly) {
            if (-not (Invoke-BuildImages)) {
                exit 1
            }
        }
        
        # Exit if build-only
        if ($BuildOnly) {
            Write-Success "Build completed successfully"
            exit 0
        }
        
        # Start test server
        if (-not (Start-TestServer)) {
            exit 1
        }
        
        # Exit if server-only
        if ($ServerOnly) {
            Write-Success "Test server is running. Access it at:"
            Write-Info "  HTTP:  http://localhost:8080"
            Write-Info "  HTTPS: https://localhost:8443"
            Write-Info "Press Ctrl+C to stop the server"
            
            # Keep the script running
            try {
                while ($true) {
                    Start-Sleep -Seconds 60
                }
            }
            finally {
                Invoke-Cleanup
            }
        }
        
        # Run tests
        $testSuccess = Invoke-Tests
        
        if ($testSuccess) {
            Write-Success "Integration test suite completed successfully!"
            exit 0
        }
        else {
            Write-Error "Integration test suite failed!"
            exit 1
        }
    }
    finally {
        # Cleanup on exit
        Invoke-Cleanup
    }
}

# Run main function
Main
