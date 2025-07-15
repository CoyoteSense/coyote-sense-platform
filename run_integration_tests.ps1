#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Run all real OAuth2 integration tests

.DESCRIPTION
    This script runs real OAuth2 integration tests across all languages in the
    CoyoteSense platform. It starts the OAuth2 server, runs integration tests,
    and cleans up automatically.

.PARAMETER Language
    Run integration tests for specific language only. Options: 'csharp', 'cpp', 'typescript', 'all' (default: 'all')

.PARAMETER KeepServer
    Keep the OAuth2 server running after tests complete (default: false)

.PARAMETER ServerOnly
    Only start the OAuth2 server without running tests (default: false)

.PARAMETER Verbose
    Show detailed output from test runs (default: false)

.EXAMPLE
    .\run_integration_tests.ps1
    Run all real OAuth2 integration tests

.EXAMPLE
    .\run_integration_tests.ps1 -Language typescript
    Run only TypeScript OAuth2 integration tests

.EXAMPLE
    .\run_integration_tests.ps1 -KeepServer
    Run tests and keep OAuth2 server running

.EXAMPLE
    .\run_integration_tests.ps1 -ServerOnly
    Only start the OAuth2 server for manual testing
#>

param(
    [ValidateSet('csharp', 'cpp', 'typescript', 'all')]
    [string]$Language = 'all',
    [switch]$KeepServer = $false,
    [switch]$ServerOnly = $false,
    [switch]$Verbose = $false
)

# Color output functions
$Red = "`e[31m"
$Green = "`e[32m"
$Yellow = "`e[33m"
$Blue = "`e[34m"
$Magenta = "`e[35m"
$Cyan = "`e[36m"
$Reset = "`e[0m"

function Write-ColorOutput {
    param([string]$Message, [string]$Color = $Reset)
    Write-Host "${Color}${Message}${Reset}"
}

function Write-Section {
    param([string]$Title)
    Write-ColorOutput "" 
    Write-ColorOutput "=" * 60 $Blue
    Write-ColorOutput " $Title" $Blue
    Write-ColorOutput "=" * 60 $Blue
}

function Test-Command {
    param([string]$Command)
    try {
        Get-Command $Command -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Start-OAuth2Server {
    Write-Section "Starting OAuth2 Server"
    
    if (-not (Test-Command "docker")) {
        Write-ColorOutput "[ERROR] Docker not found - required for OAuth2 server" $Red
        return $false
    }
    
    if (-not (Test-Path "Platform\infra\security\tests\docker-compose.oauth2.yml")) {
        Write-ColorOutput "[ERROR] OAuth2 Docker Compose file not found" $Red
        return $false
    }
    
    Write-ColorOutput "[INFO] Starting OAuth2 server with Docker Compose..." $Cyan
    try {
        docker-compose -f "Platform\infra\security\tests\docker-compose.oauth2.yml" up -d
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to start OAuth2 server"
        }
        
        # Wait for server to be ready
        Write-ColorOutput "[INFO] Waiting for OAuth2 server to be ready..." $Yellow
        $maxAttempts = 30
        $attempt = 0
        
        do {
            Start-Sleep -Seconds 2
            $attempt++
            
            try {
                $response = Invoke-WebRequest -Uri "http://localhost:8081/health" -Method GET -TimeoutSec 5 -ErrorAction Stop
                if ($response.StatusCode -eq 200) {
                    Write-ColorOutput "[SUCCESS] OAuth2 server is ready!" $Green
                    return $true
                }
            }
            catch {
                if ($Verbose) {
                    Write-ColorOutput "[INFO] Attempt $attempt/$maxAttempts - server not ready yet..." $Yellow
                }
            }
        } while ($attempt -lt $maxAttempts)
        
        Write-ColorOutput "[ERROR] OAuth2 server failed to start within timeout" $Red
        return $false
    }
    catch {
        Write-ColorOutput "[ERROR] Failed to start OAuth2 server: $_" $Red
        return $false
    }
}

function Stop-OAuth2Server {
    Write-Section "Stopping OAuth2 Server"
    
    try {
        Write-ColorOutput "[INFO] Stopping OAuth2 server..." $Cyan
        docker-compose -f "Platform\infra\security\tests\docker-compose.oauth2.yml" down
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "[SUCCESS] OAuth2 server stopped" $Green
        }
        else {
            Write-ColorOutput "[WARNING] Issues stopping OAuth2 server" $Yellow
        }
    }
    catch {
        Write-ColorOutput "[WARNING] Failed to stop OAuth2 server: $_" $Yellow
    }
}

function Test-OAuth2Server {
    Write-ColorOutput "[INFO] Testing OAuth2 server connectivity..." $Cyan
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8081/health" -Method GET -TimeoutSec 10 -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            Write-ColorOutput "[SUCCESS] OAuth2 server is accessible" $Green
            return $true
        }
        else {
            Write-ColorOutput "[ERROR] OAuth2 server returned status: $($response.StatusCode)" $Red
            return $false
        }
    }
    catch {
        Write-ColorOutput "[ERROR] OAuth2 server is not accessible: $_" $Red
        return $false
    }
}

function Run-CSharpIntegrationTests {
    Write-Section "C# OAuth2 Integration Tests"
    
    if (-not (Test-Command "dotnet")) {
        Write-ColorOutput "[SKIP] .NET SDK not found - skipping C# integration tests" $Yellow
        return $true  # Return true for skip, not false
    }
    
    $testProject = "Platform\infra\security\tests\dotnet\CoyoteSense.Security.Client.Tests.csproj"
    
    if (-not (Test-Path $testProject)) {
        Write-ColorOutput "[SKIP] C# test project not found: $testProject" $Yellow
        return $true  # Return true for skip, not false
    }
    
    Write-ColorOutput "[RUN] Running C# OAuth2 integration tests..." $Cyan
    try {
        $testArgs = @("test", $testProject, "--no-restore")
        if ($Verbose) {
            $testArgs += @("--verbosity", "normal")
        }
        # Only run real integration tests
        $testArgs += @("--filter", "Category=RealIntegration")
        
        & dotnet @testArgs
        if ($LASTEXITCODE -ne 0) {
            Write-ColorOutput "[FAIL] C# integration tests failed" $Red
            return $false
        }
        else {
            Write-ColorOutput "[PASS] C# integration tests passed" $Green
            return $true
        }
    }
    catch {
        Write-ColorOutput "[ERROR] Failed to run C# integration tests: $_" $Red
        return $false
    }
}

function Run-CppIntegrationTests {
    Write-Section "C++ OAuth2 Integration Tests"
    
    $cppTestDir = "Platform\infra\security\tests\cpp\integration"
    
    if (-not (Test-Path $cppTestDir)) {
        Write-ColorOutput "[SKIP] C++ integration test directory not found: $cppTestDir" $Yellow
        return $true  # Return true for skip, not false
    }
    
    Push-Location $cppTestDir
    try {
        # Check for build tools
        $hasMake = Test-Command "make"
        $hasCl = Test-Command "cl"
        $hasGcc = Test-Command "g++"
        
        if (-not ($hasMake -or $hasCl -or $hasGcc)) {
            Write-ColorOutput "[SKIP] No C++ build tools found (make, cl, or g++) - skipping C++ integration tests" $Yellow
            Write-ColorOutput "[INFO] Install Visual Studio Build Tools or MinGW to run C++ tests" $Yellow
            return $true  # Return true for skip, not false
        }
        
        Write-ColorOutput "[RUN] Running C++ OAuth2 integration tests..." $Cyan
        
        # Try different build approaches
        if (Test-Path "Makefile" -and $hasMake) {
            Write-ColorOutput "[INFO] Building with make..." $Cyan
            make clean 2>$null
            make
            if ($LASTEXITCODE -ne 0) {
                throw "C++ build failed with make"
            }
            
            # Run the test executable
            if (Test-Path "oauth2_integration_test.exe") {
                .\oauth2_integration_test.exe
                $testResult = $LASTEXITCODE
            }
            elseif (Test-Path "oauth2_integration_test") {
                .\oauth2_integration_test
                $testResult = $LASTEXITCODE
            }
            else {
                throw "Test executable not found after build"
            }
        }
        elseif (Test-Path "CMakeLists.txt") {
            Write-ColorOutput "[INFO] Building with CMake..." $Cyan
            if (-not (Test-Path "build")) {
                New-Item -ItemType Directory -Name "build" | Out-Null
            }
            Push-Location "build"
            try {
                cmake ..
                if ($LASTEXITCODE -ne 0) {
                    throw "CMake configuration failed"
                }
                cmake --build .
                if ($LASTEXITCODE -ne 0) {
                    throw "CMake build failed"
                }
                
                # Find and run test executable
                $testExe = Get-ChildItem -Name "*test*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($testExe) {
                    & ".\$testExe"
                    $testResult = $LASTEXITCODE
                }
                else {
                    throw "Test executable not found after build"
                }
            }
            finally {
                Pop-Location
            }
        }
        else {
            Write-ColorOutput "[SKIP] No build configuration found (Makefile or CMakeLists.txt)" $Yellow
            return $true  # Return true for skip, not false
        }
        
        if ($testResult -eq 0) {
            Write-ColorOutput "[PASS] C++ integration tests passed" $Green
            return $true
        }
        else {
            Write-ColorOutput "[FAIL] C++ integration tests failed" $Red
            return $false
        }
    }
    catch {
        Write-ColorOutput "[ERROR] Failed to run C++ integration tests: $_" $Red
        return $false
    }
    finally {
        Pop-Location
    }
}

function Run-TypeScriptIntegrationTests {
    Write-Section "TypeScript OAuth2 Integration Tests"
    
    if (-not (Test-Command "npm")) {
        Write-ColorOutput "[SKIP] Node.js/npm not found - skipping TypeScript integration tests" $Yellow
        return $true  # Return true for skip, not false
    }
    
    $testDir = "Platform\infra\security\tests\ts"
    
    if (-not ((Test-Path $testDir) -and (Test-Path "$testDir\package.json"))) {
        Write-ColorOutput "[SKIP] TypeScript test project not found: $testDir" $Yellow
        return $true  # Return true for skip, not false
    }
    
    Push-Location $testDir
    try {
        # Install dependencies if needed
        if (-not (Test-Path "node_modules")) {
            Write-ColorOutput "[INFO] Installing npm dependencies..." $Yellow
            npm install --silent
            if ($LASTEXITCODE -ne 0) {
                throw "npm install failed"
            }
        }
        
        Write-ColorOutput "[RUN] Running TypeScript OAuth2 integration tests..." $Cyan
        
        # Run integration tests specifically
        $env:NODE_ENV = "integration"
        if ($Verbose) {
            npm test -- integration/real-oauth2-integration.test.ts --verbose
        }
        else {
            npm test -- integration/real-oauth2-integration.test.ts
        }
        
        if ($LASTEXITCODE -ne 0) {
            Write-ColorOutput "[FAIL] TypeScript integration tests failed" $Red
            return $false
        }
        else {
            Write-ColorOutput "[PASS] TypeScript integration tests passed" $Green
            return $true
        }
    }
    catch {
        Write-ColorOutput "[ERROR] Failed to run TypeScript integration tests: $_" $Red
        return $false
    }
    finally {
        Pop-Location
        $env:NODE_ENV = $null
    }
}

# Main execution
Write-Section "CoyoteSense OAuth2 Integration Test Runner"
Write-ColorOutput "Running real OAuth2 integration tests" $Magenta
Write-ColorOutput "Language filter: $Language" $Cyan
if ($Verbose) { Write-ColorOutput "Verbose output: Enabled" $Cyan }
if ($KeepServer) { Write-ColorOutput "Keep server: Enabled" $Cyan }
if ($ServerOnly) { Write-ColorOutput "Server only mode: Enabled" $Cyan }

# Check if we're in the correct directory
if (-not (Test-Path "Platform\infra\security")) {
    Write-ColorOutput "[ERROR] Not in project root directory" $Red
    Write-ColorOutput "        Please run this script from the CoyoteSense platform root" $Yellow
    exit 1
}

# Start OAuth2 server
$serverStarted = Start-OAuth2Server
if (-not $serverStarted) {
    Write-ColorOutput "[ERROR] Failed to start OAuth2 server - cannot run integration tests" $Red
    exit 1
}

# Test server connectivity
if (-not (Test-OAuth2Server)) {
    if (-not $KeepServer) { Stop-OAuth2Server }
    exit 1
}

# Server-only mode
if ($ServerOnly) {
    Write-Section "Server Only Mode"
    Write-ColorOutput "[INFO] OAuth2 server is running at http://localhost:8081" $Green
    Write-ColorOutput "[INFO] Server will continue running until manually stopped" $Cyan
    Write-ColorOutput "[INFO] To stop: docker-compose -f docker-compose.oauth2.yml down" $Yellow
    exit 0
}

# Run integration tests
$overallSuccess = $true

try {
    if ($Language -eq 'all' -or $Language -eq 'csharp') {
        $overallSuccess = (Run-CSharpIntegrationTests) -and $overallSuccess
    }

    if ($Language -eq 'all' -or $Language -eq 'cpp') {
        $overallSuccess = (Run-CppIntegrationTests) -and $overallSuccess
    }

    if ($Language -eq 'all' -or $Language -eq 'typescript') {
        $overallSuccess = (Run-TypeScriptIntegrationTests) -and $overallSuccess
    }
}
finally {
    # Cleanup
    if (-not $KeepServer) {
        Stop-OAuth2Server
    }
    else {
        Write-ColorOutput "[INFO] OAuth2 server kept running as requested" $Cyan
        Write-ColorOutput "[INFO] To stop: docker-compose -f docker-compose.oauth2.yml down" $Yellow
    }
}

# Summary
Write-Section "Integration Test Summary"
if ($overallSuccess) {
    Write-ColorOutput "[SUCCESS] All integration tests passed!" $Green
    if ($KeepServer) {
        Write-ColorOutput "[INFO] OAuth2 server is still running at http://localhost:8081" $Cyan
    }
    exit 0
}
else {
    Write-ColorOutput "[FAILURE] Some integration tests failed" $Red
    Write-ColorOutput "" 
    Write-ColorOutput "Check the output above for details" $Yellow
    exit 1
}
