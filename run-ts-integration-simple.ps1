#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Run TypeScript OAuth2 integration tests (simplified version)

.DESCRIPTION
    This script runs the TypeScript OAuth2 integration tests against a real OAuth2 server.
    Assumes the OAuth2 server is already running at http://localhost:8081.

.PARAMETER Coverage
    Run tests with coverage reporting (default: false)

.EXAMPLE
    .\run-ts-integration-simple.ps1
    Run integration tests

.EXAMPLE
    .\run-ts-integration-simple.ps1 -Coverage
    Run tests with coverage
#>

param(
    [switch]$Coverage
)

# Colors for output
$Green = "`e[32m"
$Red = "`e[31m"
$Yellow = "`e[33m"
$Blue = "`e[34m"
$Reset = "`e[0m"

function Write-ColorOutput {
    param([string]$Message, [string]$Color = $Reset)
    Write-Host "${Color}${Message}${Reset}"
}

Write-ColorOutput "[TEST] TypeScript OAuth2 Integration Tests" $Blue
Write-ColorOutput "=====================================" $Blue

# Check if we're in the correct directory
if (-not (Test-Path "Platform\infra\security\tests\ts\package.json")) {
    Write-ColorOutput "❌ Error: Not in project root directory" $Red
    Write-ColorOutput "   Please run this script from the CoyoteSense platform root" $Yellow
    exit 1
}

# Check Node.js
try {
    $nodeVersion = node --version
    Write-ColorOutput "📋 Node.js version: $nodeVersion" $Green
}
catch {
    Write-ColorOutput "❌ Error: Node.js not found" $Red
    exit 1
}

# Set environment variables
$env:NODE_ENV = "test"
$env:AUTH_TEST_SERVER_URL = "http://localhost:8081"
$env:AUTH_TEST_CLIENT_ID = "test-client-id"
$env:AUTH_TEST_CLIENT_SECRET = "test-client-secret"

# Build Jest command
$jestArgs = @("--testPathPattern=real-oauth2-integration", "--verbose")
if ($Coverage) { $jestArgs += "--coverage" }

# Run tests
Write-ColorOutput "🚀 Running TypeScript integration tests..." $Blue
Write-ColorOutput "   OAuth2 server: http://localhost:8081" $Blue

Set-Location "Platform\infra\security\tests\ts"
try {
    $jestCommand = "npx jest " + ($jestArgs -join " ")
    Write-ColorOutput "   Command: $jestCommand" $Blue
    
    Invoke-Expression $jestCommand
    $exitCode = $LASTEXITCODE
    
    if ($exitCode -eq 0) {
        Write-ColorOutput "✅ All TypeScript integration tests passed!" $Green
    } else {
        Write-ColorOutput "❌ Some TypeScript integration tests failed" $Red
    }
    
    exit $exitCode
}
catch {
    Write-ColorOutput "❌ Failed to run tests: $_" $Red
    exit 1
}
finally {
    Set-Location ..\..\..\..\..
}
