#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Run all tests except real OAuth2 integration tests

.DESCRIPTION
    This script runs all unit tests, mock tests, and other non-integration tests
    across all languages in the CoyoteSense platform. It excludes real OAuth2
    integration tests that require external server setup.

.PARAMETER Coverage
    Run tests with coverage reporting where supported (default: false)

.PARAMETER Language
    Run tests for specific language only. Options: 'csharp', 'cpp', 'typescript', 'all' (default: 'all')

.PARAMETER Verbose
    Show detailed output from test runs (default: false)

.EXAMPLE
    .\run_tests.ps1
    Run all non-integration tests

.EXAMPLE
    .\run_tests.ps1 -Coverage
    Run all tests with coverage

.EXAMPLE
    .\run_tests.ps1 -Language typescript -Verbose
    Run only TypeScript tests with verbose output
#>

param(
    [switch]$Coverage = $false,
    [ValidateSet('csharp', 'cpp', 'typescript', 'all')]
    [string]$Language = 'all',
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

function Run-CSharpTests {
    Write-Section "C# Tests (Unit/Mock)"
    
    if (-not (Test-Command "dotnet")) {
        Write-ColorOutput "[SKIP] .NET SDK not found - skipping C# tests" $Yellow
        return $false
    }
    
    $testProjects = @(
        "Platform\infra\security\tests\dotnet\CoyoteSense.Security.Client.Tests.csproj"
    )
    
    $success = $true
    foreach ($project in $testProjects) {
        if (Test-Path $project) {
            Write-ColorOutput "[RUN] Testing $project" $Cyan
            try {
                $testArgs = @("test", $project, "--no-restore")
                if ($Coverage) {
                    $testArgs += @("--collect", "XPlat Code Coverage")
                }
                if ($Verbose) {
                    $testArgs += @("--verbosity", "normal")
                }
                # Exclude real integration tests
                $testArgs += @("--filter", "Category!=RealIntegration")
                
                & dotnet @testArgs
                if ($LASTEXITCODE -ne 0) {
                    Write-ColorOutput "[FAIL] C# tests failed in $project" $Red
                    $success = $false
                }
                else {
                    Write-ColorOutput "[PASS] C# tests passed in $project" $Green
                }
            }
            catch {
                Write-ColorOutput "[ERROR] Failed to run C# tests: $_" $Red
                $success = $false
            }
        }
        else {
            Write-ColorOutput "[SKIP] Project not found: $project" $Yellow
        }
    }
    
    return $success
}

function Run-CppTests {
    Write-Section "C++ Tests (Unit/Mock)"
    
    # Look for C++ test executables or build scripts
    $cppTestDirs = @(
        "Platform\infra\security\tests\cpp",
        "Platform\infra\http\tests"
    )
    
    $success = $true
    $hasTests = $false
    
    foreach ($testDir in $cppTestDirs) {
        if (Test-Path $testDir) {
            Write-ColorOutput "[RUN] Checking C++ tests in $testDir" $Cyan
            
            # Look for test executables or CMake projects
            $testFiles = Get-ChildItem -Path $testDir -Recurse -Include "*.test.exe", "*test*.exe", "CMakeLists.txt" -ErrorAction SilentlyContinue
            
            if ($testFiles) {
                $hasTests = $true
                # For now, just indicate tests are available
                Write-ColorOutput "[INFO] C++ test infrastructure found in $testDir" $Cyan
                Write-ColorOutput "[SKIP] C++ unit tests require build setup - use build scripts in the directory" $Yellow
            }
        }
    }
    
    if (-not $hasTests) {
        Write-ColorOutput "[SKIP] No C++ test infrastructure found" $Yellow
    }
    
    return $success
}

function Run-TypeScriptTests {
    Write-Section "TypeScript/JavaScript Tests (Unit/Mock)"
    
    if (-not (Test-Command "npm")) {
        Write-ColorOutput "[SKIP] Node.js/npm not found - skipping TypeScript tests" $Yellow
        return $false
    }
    
    $testDirs = @(
        "Platform\infra\security\tests\ts"
    )
    
    $success = $true
    foreach ($testDir in $testDirs) {
        if ((Test-Path $testDir) -and (Test-Path "$testDir\package.json")) {
            Write-ColorOutput "[RUN] Testing TypeScript in $testDir" $Cyan
            
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
                
                # Run unit tests (exclude integration tests)
                Write-ColorOutput "[INFO] Running unit tests..." $Cyan
                if ($Coverage) {
                    npm run test:coverage --silent
                }
                else {
                    npm test -- --testPathIgnorePatterns="/integration/" --silent
                }
                
                if ($LASTEXITCODE -ne 0) {
                    Write-ColorOutput "[FAIL] TypeScript tests failed" $Red
                    $success = $false
                }
                else {
                    Write-ColorOutput "[PASS] TypeScript tests passed" $Green
                }
            }
            catch {
                Write-ColorOutput "[ERROR] Failed to run TypeScript tests: $_" $Red
                $success = $false
            }
            finally {
                Pop-Location
            }
        }
        else {
            Write-ColorOutput "[SKIP] TypeScript project not found: $testDir" $Yellow
        }
    }
    
    return $success
}

# Main execution
Write-Section "CoyoteSense Platform Test Runner"
Write-ColorOutput "Running all tests except real OAuth2 integration tests" $Magenta
Write-ColorOutput "Language filter: $Language" $Cyan
if ($Coverage) { Write-ColorOutput "Coverage reporting: Enabled" $Cyan }
if ($Verbose) { Write-ColorOutput "Verbose output: Enabled" $Cyan }

# Check if we're in the correct directory
if (-not (Test-Path "Platform\infra\security")) {
    Write-ColorOutput "[ERROR] Not in project root directory" $Red
    Write-ColorOutput "        Please run this script from the CoyoteSense platform root" $Yellow
    exit 1
}

$overallSuccess = $true

# Run tests based on language filter
if ($Language -eq 'all' -or $Language -eq 'csharp') {
    $overallSuccess = (Run-CSharpTests) -and $overallSuccess
}

if ($Language -eq 'all' -or $Language -eq 'cpp') {
    $overallSuccess = (Run-CppTests) -and $overallSuccess
}

if ($Language -eq 'all' -or $Language -eq 'typescript') {
    $overallSuccess = (Run-TypeScriptTests) -and $overallSuccess
}

# Summary
Write-Section "Test Summary"
if ($overallSuccess) {
    Write-ColorOutput "[SUCCESS] All available tests passed!" $Green
    Write-ColorOutput "" 
    Write-ColorOutput "To run real OAuth2 integration tests:" $Cyan
    Write-ColorOutput "  .\run_integration_tests.ps1" $Cyan
    exit 0
}
else {
    Write-ColorOutput "[FAILURE] Some tests failed" $Red
    Write-ColorOutput "" 
    Write-ColorOutput "Check the output above for details" $Yellow
    exit 1
}
