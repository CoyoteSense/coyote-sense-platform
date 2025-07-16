#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Run all CoyoteSense OAuth2 integration tests against real OAuth2 server

.DESCRIPTION
    This script runs all OAuth2 integration tests for all languages (C#, C++, TypeScript)
    against a real OAuth2 server. It manages the OAuth2 server lifecycle and ensures
    all integration tests pass.

.PARAMETER Language
    Specific language to test (cs, cpp, ts, all). Default: all

.PARAMETER SkipServerCheck
    Skip OAuth2 server availability check

.PARAMETER Coverage
    Generate coverage reports where supported

.PARAMETER Verbose
    Enable verbose output

.PARAMETER ServerUrl
    OAuth2 server URL (default: http://localhost:8081)

.EXAMPLE
    .\Platform\infra\security\tests\run_integration_tests.ps1
    Run all integration tests

.EXAMPLE
    .\Platform\infra\security\tests\run_integration_tests.ps1 -Language cs -Coverage
    Run only C# integration tests with coverage
#>

param(
    [ValidateSet("cs", "cpp", "ts", "all")]
    [string]$Language = "all",
    [switch]$SkipServerCheck,
    [switch]$Coverage,
    [switch]$Verbose,
    [string]$ServerUrl = "http://localhost:8081",
    [string]$ClientId = "test-client-id",
    [string]$ClientSecret = "test-client-secret"
)

$ErrorActionPreference = "Stop"

# Colors
$Green = "`e[32m"
$Red = "`e[31m"
$Yellow = "`e[33m"
$Blue = "`e[34m"
$Cyan = "`e[36m"
$Reset = "`e[0m"

function Write-ColorOutput {
    param([string]$Message, [string]$Color = $Reset)
    Write-Host "${Color}${Message}${Reset}"
}

function Write-Section {
    param([string]$Title)
    Write-ColorOutput "`n$('='*70)" $Cyan
    Write-ColorOutput "  $Title" $Cyan
    Write-ColorOutput "$('='*70)" $Cyan
}

function Test-OAuth2ServerRunning {
    try {
        Invoke-RestMethod -Uri "$ServerUrl/.well-known/oauth2" -Method GET -TimeoutSec 5 | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Start-OAuth2Server {
    Write-ColorOutput "Starting OAuth2 server..." $Blue
    
    $dockerComposeFile = "Platform\infra\security\tests\docker-compose.oauth2.yml"
    if (-not (Test-Path $dockerComposeFile)) {
        Write-ColorOutput "ERROR: $dockerComposeFile not found" $Red
        Write-ColorOutput "Please run this script from the project root directory" $Yellow
        exit 1
    }
    
    try {
        docker-compose -f $dockerComposeFile up -d
        
        # Wait for server to be ready
        $maxAttempts = 30
        $attempt = 0
        while ($attempt -lt $maxAttempts) {
            if (Test-OAuth2ServerRunning) {
                Write-ColorOutput "OAuth2 server is ready" $Green
                return
            }
            
            $attempt++
            Write-Host "Waiting for OAuth2 server to start... ($attempt/$maxAttempts)"
            Start-Sleep -Seconds 2
        }
        
        Write-ColorOutput "OAuth2 server failed to start within expected time" $Red
        exit 1
    }
    catch {
        Write-ColorOutput "Failed to start OAuth2 server: $_" $Red
        exit 1
    }
}

# Check if we're in the correct directory structure
if (-not (Test-Path "Platform\infra\security\tests")) {
    Write-ColorOutput "ERROR: Please run from project root directory" $Red
    exit 1
}

$testResults = @{
    "CSharp" = @{ "Passed" = 0; "Failed" = 0; "Skipped" = 0 }
    "Cpp" = @{ "Passed" = 0; "Failed" = 0; "Skipped" = 0 }
    "TypeScript" = @{ "Passed" = 0; "Failed" = 0; "Skipped" = 0 }
}

Write-Section "CoyoteSense OAuth2 Integration Test Suite"
Write-ColorOutput "Running real OAuth2 server integration tests for all languages" $Blue
Write-ColorOutput "OAuth2 Server: $ServerUrl" $Blue
Write-ColorOutput "Language filter: $Language" $Blue
if ($Coverage) { Write-ColorOutput "Coverage reporting: Enabled" $Green }
if ($Verbose) { Write-ColorOutput "Verbose output: Enabled" $Green }

# Check/Start OAuth2 server
if (-not $SkipServerCheck) {
    Write-Section "OAuth2 Server Management"
    
    if (-not (Test-OAuth2ServerRunning)) {
        Write-ColorOutput "OAuth2 server not running, attempting to start..." $Yellow
        Start-OAuth2Server
    } else {
        Write-ColorOutput "OAuth2 server is already running" $Green
    }
}

# Set environment variables for all tests
$env:AUTH_TEST_SERVER_URL = $ServerUrl
$env:AUTH_TEST_CLIENT_ID = $ClientId
$env:AUTH_TEST_CLIENT_SECRET = $ClientSecret
$env:NODE_ENV = "test"

# Function to run C# integration tests
function Test-CSharpIntegration {
    Write-Section "C# OAuth2 Integration Tests"
    
    $csharpTestPath = "Platform\infra\security\tests\dotnet"
    $csharpProjectFile = "$csharpTestPath\CoyoteSense.Security.Client.Tests.csproj"
    
    if (-not (Test-Path $csharpProjectFile)) {
        Write-ColorOutput "WARNING: C# test project not found: $csharpProjectFile" $Yellow
        $testResults.CSharp.Skipped = 1
        return
    }

    try {
        Write-ColorOutput "Running C# OAuth2 integration tests..." $Blue
        
        $dotnetArgs = @("test", $csharpProjectFile)
        if ($Coverage) { $dotnetArgs += "--collect:""XPlat Code Coverage""" }
        if ($Verbose) { $dotnetArgs += "--verbosity", "detailed" }
        
        # Include only real integration tests
        $dotnetArgs += "--filter", "TestCategory=RealIntegration"
        
        $dotnetCommand = "dotnet " + ($dotnetArgs -join " ")
        Write-ColorOutput "Command: $dotnetCommand" $Blue
        
        Invoke-Expression $dotnetCommand
        
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "C# integration tests PASSED" $Green
            $testResults.CSharp.Passed = 1
        } else {
            Write-ColorOutput "C# integration tests FAILED" $Red
            $testResults.CSharp.Failed = 1
        }
    }
    catch {
        Write-ColorOutput "C# integration test execution failed: $_" $Red
        $testResults.CSharp.Failed = 1
    }
}

# Function to run C++ integration tests
function Test-CppIntegration {
    Write-Section "C++ OAuth2 Integration Tests"
    
    $cppIntegrationPath = "Platform\infra\security\tests\cpp\integration"
    if (-not (Test-Path $cppIntegrationPath)) {
        Write-ColorOutput "WARNING: C++ integration test directory not found: $cppIntegrationPath" $Yellow
        $testResults.Cpp.Skipped = 1
        return
    }

    Push-Location $cppIntegrationPath
    try {
        Write-ColorOutput "Building and running C++ OAuth2 integration tests..." $Blue
        
        # Check for Windows build options
        if (Test-Path "real_oauth2_integration_test.exe") {
            # Pre-built executable exists
            Write-ColorOutput "Running pre-built C++ integration test..." $Blue
            .\real_oauth2_integration_test.exe
            if ($LASTEXITCODE -eq 0) {
                Write-ColorOutput "C++ integration tests PASSED" $Green
                $testResults.Cpp.Passed = 1
            } else {
                Write-ColorOutput "C++ integration tests FAILED" $Red
                $testResults.Cpp.Failed = 1
            }
        } elseif (Get-Command "make" -ErrorAction SilentlyContinue) {
            # Use make if available
            make clean 2>$null
            make
            
            if ($LASTEXITCODE -eq 0 -and (Test-Path "real_oauth2_integration_test.exe")) {
                .\real_oauth2_integration_test.exe
                if ($LASTEXITCODE -eq 0) {
                    Write-ColorOutput "C++ integration tests PASSED" $Green
                    $testResults.Cpp.Passed = 1
                } else {
                    Write-ColorOutput "C++ integration tests FAILED" $Red
                    $testResults.Cpp.Failed = 1
                }
            } else {
                Write-ColorOutput "C++ integration test build FAILED" $Red
                $testResults.Cpp.Failed = 1
            }
        } elseif (Get-Command "cl" -ErrorAction SilentlyContinue) {
            # Try MSVC compiler
            Write-ColorOutput "Attempting to build with MSVC..." $Blue
            cl /EHsc real_oauth2_integration_test.cpp /link winhttp.lib
            if ($LASTEXITCODE -eq 0 -and (Test-Path "real_oauth2_integration_test.exe")) {
                .\real_oauth2_integration_test.exe
                if ($LASTEXITCODE -eq 0) {
                    Write-ColorOutput "C++ integration tests PASSED" $Green
                    $testResults.Cpp.Passed = 1
                } else {
                    Write-ColorOutput "C++ integration tests FAILED" $Red
                    $testResults.Cpp.Failed = 1
                }
            } else {
                Write-ColorOutput "C++ MSVC build FAILED" $Red
                $testResults.Cpp.Failed = 1
            }
        } else {
            # Try to find and set up Visual Studio environment and use CMake with vcpkg
            Write-ColorOutput "Searching for Visual Studio installation..." $Blue
            
            $vsInstallPath = Get-ChildItem "C:\Program Files*\Microsoft Visual Studio\*\*" -Directory -ErrorAction SilentlyContinue | 
                            Where-Object { Test-Path (Join-Path $_.FullName "VC\Auxiliary\Build\vcvarsall.bat") } |
                            Select-Object -First 1
            
            if ($vsInstallPath) {
                $vcvarsall = Join-Path $vsInstallPath.FullName "VC\Auxiliary\Build\vcvarsall.bat"
                Write-ColorOutput "Found Visual Studio at: $($vsInstallPath.FullName)" $Blue
                Write-ColorOutput "Building with CMake and vcpkg..." $Blue
                
                # Create build directory
                if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
                New-Item -ItemType Directory -Path "build" | Out-Null
                
                # Create a temporary batch file to set up environment and build with CMake
                $tempBatch = "setup_and_build_cmake.bat"
                
                $batchContent = @"
@echo off
call "$vcvarsall" x64
if errorlevel 1 (
    echo Failed to set up Visual Studio environment
    exit /b 1
)
echo Visual Studio environment set up successfully

cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake"
if errorlevel 1 (
    echo CMake configuration failed
    exit /b 1
)

cmake --build . --config Release
if errorlevel 1 (
    echo Build failed
    exit /b 1
)

echo Build completed successfully
ctest -C Release --output-on-failure
"@
                
                Set-Content -Path $tempBatch -Value $batchContent -Encoding ASCII
                
                Write-ColorOutput "Running CMake build and test process..." $Blue
                $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $tempBatch -NoNewWindow -Wait -PassThru
                
                # Clean up temp file
                Remove-Item $tempBatch -ErrorAction SilentlyContinue
                
                if ($process.ExitCode -eq 0) {
                    Write-ColorOutput "C++ integration tests PASSED" $Green
                    $testResults.Cpp.Passed = 1
                } else {
                    Write-ColorOutput "C++ integration tests FAILED" $Red
                    $testResults.Cpp.Failed = 1
                }
            } else {
                Write-ColorOutput "No C++ build tools found (make, cl, Visual Studio), skipping C++ tests" $Yellow
                Write-ColorOutput "Please install Visual Studio Build Tools or make" $Yellow
                $testResults.Cpp.Skipped = 1
            }
        }
    }
    catch {
        Write-ColorOutput "C++ integration test execution failed: $_" $Red
        $testResults.Cpp.Failed = 1
    }
    finally {
        Pop-Location
    }
}

# Function to run TypeScript integration tests
function Test-TypeScriptIntegration {
    Write-Section "TypeScript OAuth2 Integration Tests"
    
    $tsTestPath = "Platform\infra\security\tests\ts"
    if (-not (Test-Path $tsTestPath)) {
        Write-ColorOutput "WARNING: TypeScript test directory not found: $tsTestPath" $Yellow
        $testResults.TypeScript.Skipped = 1
        return
    }

    Push-Location $tsTestPath
    try {
        # Check if dependencies are installed
        if (-not (Test-Path "node_modules")) {
            Write-ColorOutput "Installing TypeScript test dependencies..." $Blue
            npm install
            if ($LASTEXITCODE -ne 0) {
                Write-ColorOutput "Failed to install TypeScript dependencies" $Red
                $testResults.TypeScript.Failed = 1
                return
            }
        }

        Write-ColorOutput "Running TypeScript OAuth2 integration tests..." $Blue
        
        $jestArgs = @("--testPathPattern=real-oauth2-integration")
        if ($Coverage) { $jestArgs += "--coverage" }
        if ($Verbose) { $jestArgs += "--verbose" }
        
        $jestCommand = "npx jest " + ($jestArgs -join " ")
        Write-ColorOutput "Command: $jestCommand" $Blue
        
        Invoke-Expression $jestCommand
        
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "TypeScript integration tests PASSED" $Green
            $testResults.TypeScript.Passed = 1
        } else {
            Write-ColorOutput "TypeScript integration tests FAILED" $Red
            $testResults.TypeScript.Failed = 1
        }
    }
    catch {
        Write-ColorOutput "TypeScript integration test execution failed: $_" $Red
        $testResults.TypeScript.Failed = 1
    }
    finally {
        Pop-Location
    }
}

# Run integration tests based on language filter
switch ($Language) {
    "cs" { Test-CSharpIntegration }
    "cpp" { Test-CppIntegration }
    "ts" { Test-TypeScriptIntegration }
    "all" { 
        Test-CSharpIntegration
        Test-CppIntegration
        Test-TypeScriptIntegration
    }
}

# Results summary
Write-Section "Integration Test Results Summary"

$totalPassed = 0
$totalFailed = 0
$totalSkipped = 0

foreach ($lang in $testResults.Keys) {
    $result = $testResults[$lang]
    $status = if ($result.Failed -gt 0) { "FAILED" } elseif ($result.Passed -gt 0) { "PASSED" } else { "SKIPPED" }
    $color = if ($result.Failed -gt 0) { $Red } elseif ($result.Passed -gt 0) { $Green } else { $Yellow }
    
    Write-ColorOutput "$lang`: $status" $color
    
    $totalPassed += $result.Passed
    $totalFailed += $result.Failed
    $totalSkipped += $result.Skipped
}

Write-ColorOutput "`nOverall Integration Tests: Passed=$totalPassed, Failed=$totalFailed, Skipped=$totalSkipped" $Cyan

if ($totalFailed -gt 0) {
    Write-ColorOutput "`nSome integration tests FAILED" $Red
    exit 1
} elseif ($totalPassed -eq 0) {
    Write-ColorOutput "`nNo integration tests were run" $Yellow
    exit 0
} else {
    Write-ColorOutput "`nAll integration tests PASSED" $Green
    exit 0
}
