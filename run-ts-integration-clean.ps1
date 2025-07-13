#!/usr/bin/env pwsh

param(
    [switch]$Coverage
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Colors
$Green = "`e[32m"
$Red = "`e[31m"
$Yellow = "`e[33m"  
$Blue = "`e[34m"
$Reset = "`e[0m"

function Write-ColorOutput {
    param([string]$Message, [string]$Color = $Reset)
    Write-Host "${Color}${Message}${Reset}"
}

Write-ColorOutput "TypeScript OAuth2 Integration Tests" $Blue
Write-ColorOutput "===================================" $Blue

# Check directory
if (-not (Test-Path "Platform\infra\security\tests\ts\package.json")) {
    Write-ColorOutput "Error: Not in project root directory" $Red
    exit 1
}

# Check Node.js
try {
    $nodeVersion = node --version
    Write-ColorOutput "Node.js version: $nodeVersion" $Green
}
catch {
    Write-ColorOutput "Error: Node.js not found" $Red
    exit 1
}

# Set environment
$env:NODE_ENV = "test"
$env:AUTH_TEST_SERVER_URL = "http://localhost:8081"
$env:AUTH_TEST_CLIENT_ID = "test-client-id"
$env:AUTH_TEST_CLIENT_SECRET = "test-client-secret"

# Build command
$jestArgs = @("--testPathPattern=real-oauth2-integration", "--verbose")
if ($Coverage) { $jestArgs += "--coverage" }

Write-ColorOutput "Running TypeScript integration tests..." $Blue

Push-Location "Platform\infra\security\tests\ts"
try {
    $jestCommand = "npx jest " + ($jestArgs -join " ")
    Invoke-Expression $jestCommand
    $exitCode = $LASTEXITCODE
    
    if ($exitCode -eq 0) {
        Write-ColorOutput "All TypeScript integration tests passed!" $Green
    } else {
        Write-ColorOutput "Some TypeScript integration tests failed" $Red
    }
    
    exit $exitCode
}
catch {
    Write-ColorOutput "Failed to run tests: $_" $Red
    exit 1
}
finally {
    Pop-Location
}
