# Parse command line arguments
param(
    [switch]$local,
    [switch]$docker
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rootDir = $scriptDir  # Use HTTP directory as root
$testServerDir = Join-Path $rootDir "tests\integration\test-server"
$httpPort = 8080
$httpsPort = 8443

# Function to check if Docker is running
function Test-DockerRunning {
    try {
        docker info 2>&1 | Out-Null
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    }
}

# If no argument is provided, run both local and Docker tests
if (-not $local -and -not $docker) {
    $local = $true
    $docker = $true
}

# Run Docker-based tests
if ($docker) {
    Write-Host "Running integration tests in Docker..." -ForegroundColor Green
    
    # Check if Docker is running
    if (-not (Test-DockerRunning)) {
        Write-Error "Docker is not running. Please start Docker and try again."
        exit 1
    }
    
    # Change to the integration tests directory
    $integrationDir = Join-Path $rootDir "tests\integration"
    Push-Location $integrationDir
    
    try {
        # Build and run the tests using Docker Compose
        Write-Host "Building Docker containers..." -ForegroundColor Cyan
        docker-compose build
        
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to build Docker containers."
            Pop-Location
            exit 1
        }
        
        Write-Host "Running tests in Docker..." -ForegroundColor Cyan
        docker-compose up --abort-on-container-exit
        
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Tests failed in Docker."
            Pop-Location
            exit 1
        }
        
        Write-Host "Tests completed successfully in Docker!" -ForegroundColor Green
    } finally {
        # Clean up Docker resources
        Write-Host "Cleaning up Docker resources..." -ForegroundColor Cyan
        docker-compose down
        Pop-Location
    }
}

# Run local tests
if ($local) {
    Write-Host "Running integration tests locally..." -ForegroundColor Green

    try {
        # Check if build directory exists, if not create it
        $buildDir = Join-Path $rootDir "build"
        if (-not (Test-Path -Path $buildDir)) {
            New-Item -ItemType Directory -Path $buildDir | Out-Null
        }
        
        Push-Location $buildDir
        
        # Run CMake to configure the project
        Write-Host "Configuring HTTP client tests with CMake..."
        cmake .. -DBUILD_HTTP_CLIENT_TESTS=ON -DBUILD_INTEGRATION_TESTS=ON
        
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to configure tests with CMake."
            exit 1
        }
        
        # Build the project
        Write-Host "Building HTTP client tests..."
        cmake --build . --config Release
        
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to build tests."
            exit 1
        }
        
        # Check if Node.js is installed
        try {
            $nodeVersion = node --version
            Write-Host "Using Node.js $nodeVersion"
        } catch {
            Write-Error "Node.js is required to run the test server. Please install Node.js and try again."
            exit 1
        }
        
        # Ensure server dependencies are installed
        $testServerRootDir = Join-Path $rootDir "tests\integration"
        
        Push-Location $testServerRootDir
        if (-not (Test-Path -Path "node_modules")) {
            Write-Host "Installing test server dependencies..."
            npm install
            if ($LASTEXITCODE -ne 0) {
                Write-Error "Failed to install test server dependencies."
                Pop-Location
                exit 1
            }
        }
        Pop-Location
        
        # Start the test server in background
        Write-Host "Starting HTTP test server on port $httpPort and HTTPS on port $httpsPort..."
        $env:HTTP_PORT = $httpPort.ToString()
        $env:HTTPS_PORT = $httpsPort.ToString()
        $serverProcess = Start-Process -FilePath "node" -ArgumentList (Join-Path $testServerDir "server.js") -PassThru -NoNewWindow
        
        # Wait a moment for the server to start
        Write-Host "Waiting for server to start..."
        Start-Sleep -Seconds 5
        
        # Set environment variables for the test
        $env:TEST_SERVER_HOST = "localhost"
        $env:TEST_SERVER_HTTP_PORT = $httpPort
        $env:TEST_SERVER_HTTPS_PORT = $httpsPort
        $env:COYOTE_RUNTIME_MODE = "production"
        
        # Verify server is responding before running tests
        try {
            $testUrl = "http://localhost:$httpPort/health"
            Write-Host "Testing server availability at $testUrl..."
            $response = Invoke-WebRequest -Uri $testUrl -UseBasicParsing
            Write-Host "Server is running: $($response.StatusCode) $($response.StatusDescription)"
        } catch {
            Write-Error "Failed to connect to test server. Error: $_"
            if ($null -ne $serverProcess) {
                Stop-Process -Id $serverProcess.Id -Force
            }
            exit 1
        }
        
        # Run the integration tests
        Write-Host "Running HTTP client integration tests..."
        $testPath = Join-Path $buildDir "integration_tests\Release\integration_tests.exe"
        if (Test-Path $testPath) {
            & $testPath
        } else {
            $testPath = Join-Path $buildDir "integration_tests\integration_tests.exe"
            if (Test-Path $testPath) {
                & $testPath
            } else {
                $testPath = Join-Path $buildDir "integration_tests"
                if (Test-Path $testPath) {
                    & $testPath
                } else {
                    Write-Error "Could not find integration tests executable."
                    exit 1
                }
            }
        }
        
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Integration tests failed with exit code $LASTEXITCODE."
            exit 1
        }
        
        Write-Host "Integration tests completed successfully!" -ForegroundColor Green
        
    } finally {
        # Clean up the server process if it's still running
        if ($null -ne $serverProcess -and -not $serverProcess.HasExited) {
            Write-Host "Stopping test server..."
            Stop-Process -Id $serverProcess.Id -Force
        }
        
        Pop-Location
    }
}

# If we get here, all requested tests have passed
Write-Host "All tests completed successfully!" -ForegroundColor Green
exit 0

try {
    # Check if build directory exists, if not create it
    $buildDir = Join-Path $rootDir "build"
    if (-not (Test-Path -Path $buildDir)) {
        New-Item -ItemType Directory -Path $buildDir | Out-Null
    }
    
    Push-Location $buildDir
    
    # Run CMake to configure the project
    Write-Host "Configuring HTTP client tests with CMake..."
    cmake .. -DBUILD_HTTP_CLIENT_TESTS=ON -DBUILD_INTEGRATION_TESTS=ON
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to configure tests with CMake."
        exit 1
    }
    
    # Build the project
    Write-Host "Building HTTP client tests..."
    cmake --build . --config Release
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to build tests."
        exit 1
    }
    
    # Check if Node.js is installed
    try {
        $nodeVersion = node --version
        Write-Host "Using Node.js $nodeVersion"
    } catch {
        Write-Error "Node.js is required to run the test server. Please install Node.js and try again."
        exit 1
    }
      # Ensure server dependencies are installed
    $testServerRootDir = Join-Path $rootDir "tests\integration"
    
    Push-Location $testServerRootDir
    if (-not (Test-Path -Path "node_modules")) {
        Write-Host "Installing test server dependencies..."
        npm install
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to install test server dependencies."
            Pop-Location
            exit 1
        }
    }
    Pop-Location
    
    # Start the test server in background
    Write-Host "Starting HTTP test server on port $httpPort and HTTPS on port $httpsPort..."
    $env:HTTP_PORT = $httpPort.ToString()
    $env:HTTPS_PORT = $httpsPort.ToString()
    $serverProcess = Start-Process -FilePath "node" -ArgumentList (Join-Path $testServerDir "server.js") -PassThru -NoNewWindow
    
    # Wait a moment for the server to start
    Write-Host "Waiting for server to start..."
    Start-Sleep -Seconds 5
    
    # Set environment variables for the test
    $env:TEST_SERVER_HOST = "localhost"
    $env:TEST_SERVER_HTTP_PORT = $httpPort
    $env:TEST_SERVER_HTTPS_PORT = $httpsPort
    $env:COYOTE_RUNTIME_MODE = "production"
    
    # Verify server is responding before running tests
    try {
        $testUrl = "http://localhost:$httpPort/health"
        Write-Host "Testing server availability at $testUrl..."
        $response = Invoke-WebRequest -Uri $testUrl -UseBasicParsing
        Write-Host "Server is running: $($response.StatusCode) $($response.StatusDescription)"
    } catch {
        Write-Error "Failed to connect to test server. Error: $_"
        if ($serverProcess -ne $null) {
            Stop-Process -Id $serverProcess.Id -Force
        }
        exit 1
    }
    
    # Run the integration tests
    Write-Host "Running HTTP client integration tests..."
    $testPath = Join-Path $buildDir "integration_tests\Release\integration_tests.exe"
    if (Test-Path $testPath) {
        & $testPath
    } else {
        $testPath = Join-Path $buildDir "integration_tests\integration_tests.exe"
        if (Test-Path $testPath) {
            & $testPath
        } else {
            $testPath = Join-Path $buildDir "integration_tests"
            if (Test-Path $testPath) {
                & $testPath
            } else {
                Write-Error "Could not find integration tests executable."
                exit 1
            }
        }
    }
      if ($LASTEXITCODE -ne 0) {
        Write-Error "Integration tests failed with exit code $LASTEXITCODE."
        exit 1
    }
    
    Write-Host "Integration tests completed successfully!" -ForegroundColor Green
    
} finally {
    # Clean up the server process if it's still running
    if ($serverProcess -ne $null -and -not $serverProcess.HasExited) {
        Write-Host "Stopping test server..."
        Stop-Process -Id $serverProcess.Id -Force
    }
    
    Pop-Location
}

# If we get here, all requested tests have passed
Write-Host "All tests completed successfully!" -ForegroundColor Green
exit 0
