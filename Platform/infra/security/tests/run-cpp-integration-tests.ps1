# Build and Run C++ OAuth2 Integration Tests (PowerShell)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$TestsDir = Join-Path $ScriptDir ".."
$CppIntegrationDir = Join-Path $TestsDir "cpp\integration"

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Banner {
    Write-Host "========================================" -ForegroundColor Blue
    Write-Host "  C++ OAuth2 Integration Tests" -ForegroundColor Blue
    Write-Host "========================================" -ForegroundColor Blue
}

function Test-OAuth2Server {
    Write-Info "Checking OAuth2 server availability..."
    
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8081/.well-known/oauth2" -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) {
            Write-Success "OAuth2 server is running"
            return $true
        }
    } catch {
        Write-Warning "OAuth2 server is not running"
        Write-Info "Starting OAuth2 server..."
        
        $serverScript = Join-Path $TestsDir "manage-oauth2-server.ps1"
        if (Test-Path $serverScript) {
            & $serverScript start
            if ($LASTEXITCODE -eq 0) {
                Write-Success "OAuth2 server started successfully"
                return $true
            } else {
                Write-Error "Failed to start OAuth2 server"
                return $false
            }
        } else {
            Write-Error "OAuth2 server management script not found"
            return $false
        }
    }
    
    Write-Error "OAuth2 server is not available"
    return $false
}

function Test-Dependencies {
    Write-Info "Checking C++ build dependencies..."
    
    # Check for CMake
    if (!(Get-Command cmake -ErrorAction SilentlyContinue)) {
        Write-Error "CMake not found. Please install CMake."
        return $false
    }
    
    # Check for C++ compiler
    if (!(Get-Command g++ -ErrorAction SilentlyContinue) -and !(Get-Command clang++ -ErrorAction SilentlyContinue) -and !(Get-Command cl -ErrorAction SilentlyContinue)) {
        Write-Error "C++ compiler not found. Please install GCC, Clang, or Visual Studio."
        return $false
    }
    
    Write-Info "Found CMake: $(cmake --version | Select-Object -First 1)"
    
    if (Get-Command g++ -ErrorAction SilentlyContinue) {
        Write-Info "Found G++: $(g++ --version | Select-Object -First 1)"
    } elseif (Get-Command clang++ -ErrorAction SilentlyContinue) {
        Write-Info "Found Clang++: $(clang++ --version | Select-Object -First 1)"
    } elseif (Get-Command cl -ErrorAction SilentlyContinue) {
        Write-Info "Found MSVC: $(cl 2>&1 | Select-Object -First 1)"
    }
    
    return $true
}

function Build-CppIntegrationTests {
    Write-Info "Building C++ integration tests..."
    
    # Create build directory
    $buildDir = Join-Path $CppIntegrationDir "build"
    if (!(Test-Path $buildDir)) {
        New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
    }
    
    # Change to build directory
    Set-Location $buildDir
    
    try {
        # Configure with CMake
        Write-Info "Configuring with CMake..."
        cmake .. -DCMAKE_BUILD_TYPE=Debug
        
        if ($LASTEXITCODE -ne 0) {
            Write-Error "CMake configuration failed"
            return $false
        }
        
        # Build
        Write-Info "Building..."
        cmake --build . --config Debug
        
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Build failed"
            return $false
        }
        
        Write-Success "C++ integration tests built successfully"
        return $true
        
    } catch {
        Write-Error "Build process failed: $_"
        return $false
    }
}

function Invoke-CppIntegrationTests {
    Write-Info "Running C++ integration tests..."
    
    $buildDir = Join-Path $CppIntegrationDir "build"
    
    if (!(Test-Path $buildDir)) {
        Write-Error "Build directory not found. Please build the tests first."
        return $false
    }
    
    Set-Location $buildDir
    
    # Set environment variables for the tests
    $env:OAUTH2_SERVER_URL = "http://localhost:8081"
    $env:OAUTH2_CLIENT_ID = "test-client-id"
    $env:OAUTH2_CLIENT_SECRET = "test-client-secret"
    $env:OAUTH2_SCOPE = "api.read api.write"
    
    # Find the test executable
    $testExe = "real_oauth2_integration_test.exe"
    if (!(Test-Path $testExe)) {
        $testExe = "real_oauth2_integration_test"
        if (!(Test-Path $testExe)) {
            Write-Error "Test executable not found"
            return $false
        }
    }
    
    Write-Info "Running integration tests..."
    Write-Info "Test executable: $testExe"
    
    # Run the tests
    & ".\$testExe" --gtest_output=xml:test_results.xml
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "All C++ integration tests passed!"
        return $true
    } else {
        Write-Error "Some C++ integration tests failed"
        return $false
    }
}

# Main execution
Write-Banner

# Check dependencies
if (!(Test-Dependencies)) {
    Write-Error "Missing required dependencies"
    exit 1
}

# Check if OAuth2 server is available
if (!(Test-OAuth2Server)) {
    Write-Error "OAuth2 server is not available"
    Write-Info "Please start the OAuth2 server first:"
    Write-Info "  .\manage-oauth2-server.ps1 start"
    exit 1
}

# Build the integration tests
if (!(Build-CppIntegrationTests)) {
    Write-Error "Failed to build C++ integration tests"
    exit 1
}

# Run the integration tests
if (Invoke-CppIntegrationTests) {
    Write-Success "All C++ integration tests completed successfully!"
    exit 0
} else {
    Write-Error "C++ integration tests failed"
    exit 1
}
