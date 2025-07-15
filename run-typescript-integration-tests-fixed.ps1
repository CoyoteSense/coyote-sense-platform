#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Run TypeScript OAuth2 integration tests against real OAuth2 server

.DESCRIPTION
    This script runs the TypeScript OAuth2 integration tests against a real OAuth2 server.
    It ensures the OAuth2 server is running before executing the tests.

.PARAMETER SkipServerCheck
    Skip checking if the OAuth2 server is running (default: false)

.PARAMETER Verbose
    Enable verbose output for debugging (default: false)

.PARAMETER Coverage
    Run tests with coverage reporting (default: false)

.EXAMPLE
    .\run-typescript-integration-tests.ps1
    Run integration tests with server check

.EXAMPLE
    .\run-typescript-integration-tests.ps1 -Verbose -Coverage
    Run tests with verbose output and coverage reporting

.EXAMPLE
    .\run-typescript-integration-tests.ps1 -SkipServerCheck
    Run tests without checking server status
#>

param(
    [switch]$SkipServerCheck,
    [switch]$Verbose,
    [switch]$Coverage
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Colors for output
$Green = "`e[32m"
$Red = "`e[31m"
$Yellow = "`e[33m"
$Blue = "`e[34m"
$Reset = "`e[0m"

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = $Reset
    )
    Write-Host "${Color}${Message}${Reset}"
}

function Test-OAuth2ServerRunning {
    try {
        Invoke-RestMethod -Uri "http://localhost:8081/health" -Method GET -TimeoutSec 5 | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Start-OAuth2Server {
    Write-ColorOutput "Starting OAuth2 server..." $Blue
    
    $dockerComposeFile = "docker-compose.oauth2.yml"
    if (-not (Test-Path $dockerComposeFile)) {
        Write-ColorOutput "❌ Error: $dockerComposeFile not found in current directory" $Red
        Write-ColorOutput "   Please run this script from the project root directory" $Yellow
        exit 1
    }
    
    try {
        docker-compose -f $dockerComposeFile up -d
        
        # Wait for server to be ready
        $maxAttempts = 30
        $attempt = 0
        while ($attempt -lt $maxAttempts) {
            if (Test-OAuth2ServerRunning) {
                Write-ColorOutput "✅ OAuth2 server is ready" $Green
                return
            }
            
            $attempt++
            Write-Host "⏳ Waiting for OAuth2 server to start... ($attempt/$maxAttempts)"
            Start-Sleep -Seconds 2
        }
        
        Write-ColorOutput "❌ OAuth2 server failed to start within expected time" $Red
        exit 1
    }
    catch {
        Write-ColorOutput "❌ Failed to start OAuth2 server: $_" $Red
        exit 1
    }
}

function Test-NodeModules {
    $packageJsonPath = "Platform\infra\security\tests\ts\package.json"
    $nodeModulesPath = "Platform\infra\security\tests\ts\node_modules"
    
    if (-not (Test-Path $packageJsonPath)) {
        Write-ColorOutput "❌ Error: $packageJsonPath not found" $Red
        return $false
    }
    
    if (-not (Test-Path $nodeModulesPath)) {
        Write-ColorOutput "📦 Installing TypeScript test dependencies..." $Blue
        Push-Location "Platform\infra\security\tests\ts"
        try {
            npm install
            if ($LASTEXITCODE -ne 0) {
                Write-ColorOutput "❌ Failed to install dependencies" $Red
                return $false
            }
        }
        finally {
            Pop-Location
        }
    }
    
    return $true
}

# Main execution
Write-ColorOutput "🧪 TypeScript OAuth2 Integration Tests Runner" $Blue
Write-ColorOutput "=============================================" $Blue

# Check if we're in the correct directory
if (-not (Test-Path "Platform\infra\security\tests\ts\package.json")) {
    Write-ColorOutput "❌ Error: Not in project root directory" $Red
    Write-ColorOutput "   Please run this script from the CoyoteSense platform root" $Yellow
    exit 1
}

# Check Node.js and npm
try {
    $nodeVersion = node --version
    $npmVersion = npm --version
    Write-ColorOutput "📋 Node.js version: $nodeVersion" $Green
    Write-ColorOutput "📋 npm version: $npmVersion" $Green
}
catch {
    Write-ColorOutput "❌ Error: Node.js or npm not found" $Red
    Write-ColorOutput "   Please install Node.js from https://nodejs.org/" $Yellow
    exit 1
}

# Install dependencies if needed
if (-not (Test-NodeModules)) {
    exit 1
}

# Check OAuth2 server status
if (-not $SkipServerCheck) {
    Write-ColorOutput "🔍 Checking OAuth2 server status..." $Blue
    
    if (-not (Test-OAuth2ServerRunning)) {
        Write-ColorOutput "⚠️  OAuth2 server not running" $Yellow
        Write-ColorOutput "   Attempting to start OAuth2 server..." $Blue
        Start-OAuth2Server
    }
    else {
        Write-ColorOutput "✅ OAuth2 server is already running" $Green
    }
}

# Set test environment variables
$env:NODE_ENV = "test"
$env:AUTH_TEST_SERVER_URL = "http://localhost:8081"
$env:AUTH_TEST_CLIENT_ID = "test-client-id"
$env:AUTH_TEST_CLIENT_SECRET = "test-client-secret"

if ($Verbose) {
    $env:AUTH_TEST_DEBUG = "true"
}

# Build Jest command
$jestArgs = @()
$jestArgs += "--testPathPattern=real-oauth2-integration"
$jestArgs += "--verbose"

if ($Coverage) {
    $jestArgs += "--coverage"
}

if ($Verbose) {
    $jestArgs += "--detectOpenHandles"
    $jestArgs += "--forceExit"
}

# Run the tests
Write-ColorOutput "🚀 Running TypeScript integration tests..." $Blue
Write-ColorOutput "   Test file: real-oauth2-integration.test.ts" $Blue
Write-ColorOutput "   OAuth2 server: http://localhost:8081" $Blue

Push-Location "Platform\infra\security\tests\ts"
try {
    $jestCommand = "npx jest " + ($jestArgs -join " ")
    Write-ColorOutput "   Command: $jestCommand" $Blue
    
    Invoke-Expression $jestCommand
    $testExitCode = $LASTEXITCODE
    
    if ($testExitCode -eq 0) {
        Write-ColorOutput "✅ All TypeScript integration tests passed!" $Green
    }
    else {
        Write-ColorOutput "❌ Some TypeScript integration tests failed" $Red
    }
    
    exit $testExitCode
}
catch {
    Write-ColorOutput "❌ Failed to run TypeScript integration tests: $_" $Red
    exit 1
}
finally {
    Pop-Location
}
