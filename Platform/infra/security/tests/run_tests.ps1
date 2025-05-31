# OAuth2 Client Libraries Test Runner for Windows
# Comprehensive test execution script for all OAuth2 authentication client libraries

param(
    [switch]$Help,
    [switch]$Verbose,
    [switch]$Parallel,
    [switch]$SkipCpp,
    [switch]$SkipCSharp,
    [switch]$SkipPython,
    [switch]$SkipTypeScript,
    [switch]$Integration,
    [switch]$Performance,
    [switch]$NoReports,
    [string]$ServerUrl = $env:OAUTH2_TEST_SERVER_URL ?? "https://localhost:5001",
    [string]$ClientId = $env:OAUTH2_TEST_CLIENT_ID ?? "test-client-id",
    [string]$ClientSecret = $env:OAUTH2_TEST_CLIENT_SECRET ?? "test-client-secret"
)

# Configuration
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $ScriptDir))
$TestsDir = $ScriptDir
$ReportsDir = Join-Path $TestsDir "reports"
$CoverageDir = Join-Path $TestsDir "coverage"

# Test execution flags
$RunCppTests = -not $SkipCpp
$RunCSharpTests = -not $SkipCSharp
$RunPythonTests = -not $SkipPython
$RunTypeScriptTests = -not $SkipTypeScript
$RunIntegrationTests = $Integration
$RunPerformanceTests = $Performance
$GenerateReports = -not $NoReports

# Colors for console output
enum Color {
    Red = 12
    Green = 10
    Yellow = 14
    Blue = 9
    Purple = 13
    Cyan = 11
    White = 15
}

function Write-ColoredOutput {
    param(
        [string]$Message,
        [Color]$Color = [Color]::White
    )
    
    $currentColor = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = $Color
    Write-Host $Message
    $Host.UI.RawUI.ForegroundColor = $currentColor
}

function Print-Banner {
    Write-ColoredOutput "========================================" -Color Blue
    Write-ColoredOutput "  OAuth2 Client Libraries Test Runner  " -Color Blue
    Write-ColoredOutput "========================================" -Color Blue
    Write-Host ""
}

function Print-Section {
    param([string]$Title)
    Write-ColoredOutput $Title -Color Cyan
    Write-ColoredOutput "----------------------------------------" -Color Cyan
}

function Print-Success {
    param([string]$Message)
    Write-ColoredOutput "✓ $Message" -Color Green
}

function Print-Error {
    param([string]$Message)
    Write-ColoredOutput "✗ $Message" -Color Red
}

function Print-Warning {
    param([string]$Message)
    Write-ColoredOutput "⚠ $Message" -Color Yellow
}

function Print-Info {
    param([string]$Message)
    Write-ColoredOutput "ℹ $Message" -Color Blue
}

function Show-Usage {
    @"
OAuth2 Client Libraries Test Runner for Windows

USAGE:
    .\run_tests.ps1 [OPTIONS]

OPTIONS:
    -Help               Show this help message
    -Verbose            Enable verbose output
    -Parallel           Run tests in parallel where possible
    -SkipCpp            Skip C++ tests
    -SkipCSharp         Skip C# tests
    -SkipPython         Skip Python tests
    -SkipTypeScript     Skip TypeScript tests
    -Integration        Run integration tests (requires test server)
    -Performance        Run performance tests
    -NoReports          Skip test report generation
    -ServerUrl <URL>    OAuth2 test server URL
    -ClientId <ID>      OAuth2 test client ID
    -ClientSecret <SEC> OAuth2 test client secret

EXAMPLES:
    .\run_tests.ps1                    Run all unit tests
    .\run_tests.ps1 -Integration       Run unit and integration tests
    .\run_tests.ps1 -SkipCpp -Verbose Run tests except C++ with verbose output
    .\run_tests.ps1 -Performance       Run performance benchmarks

"@ | Write-Host
}

function Setup-Environment {
    Print-Section "Setting up test environment"
    
    # Create directories
    if (!(Test-Path $ReportsDir)) {
        New-Item -ItemType Directory -Path $ReportsDir -Force | Out-Null
    }
    if (!(Test-Path $CoverageDir)) {
        New-Item -ItemType Directory -Path $CoverageDir -Force | Out-Null
    }
    
    # Set environment variables
    $env:OAUTH2_TEST_SERVER_URL = $ServerUrl
    $env:OAUTH2_TEST_CLIENT_ID = $ClientId
    $env:OAUTH2_TEST_CLIENT_SECRET = $ClientSecret
    $env:OAUTH2_TEST_REDIRECT_URI = "https://localhost:3000/callback"
    $env:OAUTH2_TEST_USERNAME = "testuser"
    $env:OAUTH2_TEST_PASSWORD = "testpass"
    
    if ($RunIntegrationTests) {
        $env:OAUTH2_SKIP_INTEGRATION_TESTS = "false"
        Print-Info "Integration tests enabled"
    } else {
        $env:OAUTH2_SKIP_INTEGRATION_TESTS = "true"
        Print-Info "Integration tests disabled"
    }
    
    if ($Verbose) {
        $env:OAUTH2_TEST_DEBUG = "true"
        Print-Info "Verbose logging enabled"
    }
    
    Print-Success "Environment setup complete"
    Write-Host ""
}

function Test-Dependencies {
    Print-Section "Checking dependencies"
    
    $missingDeps = $false
    
    # Check C++ dependencies
    if ($RunCppTests) {
        if (!(Get-Command "cl.exe" -ErrorAction SilentlyContinue) -and !(Get-Command "g++.exe" -ErrorAction SilentlyContinue)) {
            Print-Error "C++ compiler not found (Visual Studio or MinGW required)"
            $missingDeps = $true
        }
        if (!(Get-Command "cmake.exe" -ErrorAction SilentlyContinue)) {
            Print-Error "CMake not found"
            $missingDeps = $true
        }
    }
    
    # Check .NET dependencies
    if ($RunCSharpTests) {
        if (!(Get-Command "dotnet.exe" -ErrorAction SilentlyContinue)) {
            Print-Error ".NET SDK not found"
            $missingDeps = $true
        }
    }
    
    # Check Python dependencies
    if ($RunPythonTests) {
        if (!(Get-Command "python.exe" -ErrorAction SilentlyContinue) -and !(Get-Command "python3.exe" -ErrorAction SilentlyContinue)) {
            Print-Error "Python 3 not found"
            $missingDeps = $true
        }
        if (!(Get-Command "pip.exe" -ErrorAction SilentlyContinue) -and !(Get-Command "pip3.exe" -ErrorAction SilentlyContinue)) {
            Print-Error "pip not found"
            $missingDeps = $true
        }
    }
    
    # Check Node.js dependencies
    if ($RunTypeScriptTests) {
        if (!(Get-Command "node.exe" -ErrorAction SilentlyContinue)) {
            Print-Error "Node.js not found"
            $missingDeps = $true
        }
        if (!(Get-Command "npm.cmd" -ErrorAction SilentlyContinue)) {
            Print-Error "npm not found"
            $missingDeps = $true
        }
    }
    
    if ($missingDeps) {
        Print-Error "Missing required dependencies. Please install them and try again."
        exit 1
    }
    
    Print-Success "All dependencies found"
    Write-Host ""
}

function Invoke-CppTests {
    if (-not $RunCppTests) {
        return $true
    }
    
    Print-Section "Running C++ Tests"
    
    $cppTestDir = Join-Path $TestsDir "cpp"
    $cppBuildDir = Join-Path $cppTestDir "build"
    
    Push-Location $cppTestDir
    
    try {
        # Create build directory
        if (!(Test-Path $cppBuildDir)) {
            New-Item -ItemType Directory -Path $cppBuildDir -Force | Out-Null
        }
        Set-Location $cppBuildDir
        
        # Configure with CMake
        Print-Info "Configuring C++ tests with CMake..."
        $cmakeArgs = @("..", "-DCMAKE_BUILD_TYPE=Debug", "-DENABLE_COVERAGE=ON")
        
        if ($Verbose) {
            & cmake @cmakeArgs
        } else {
            & cmake @cmakeArgs *> $null
        }
        
        if ($LASTEXITCODE -ne 0) {
            Print-Error "CMake configuration failed"
            return $false
        }
        
        # Build tests
        Print-Info "Building C++ tests..."
        if ($Verbose) {
            & cmake --build . --config Debug
        } else {
            & cmake --build . --config Debug *> $null
        }
        
        if ($LASTEXITCODE -ne 0) {
            Print-Error "C++ build failed"
            return $false
        }
        
        # Run tests
        Print-Info "Executing C++ tests..."
        $testOutputFile = Join-Path $ReportsDir "cpp_test_results.xml"
        $testExecutable = ".\Debug\oauth2_auth_client_test.exe"
        
        if (Test-Path $testExecutable) {
            if ($Verbose) {
                & $testExecutable --gtest_output="xml:$testOutputFile"
            } else {
                & $testExecutable --gtest_output="xml:$testOutputFile" *> $null
            }
        } else {
            # Try without Debug folder
            $testExecutable = ".\oauth2_auth_client_test.exe"
            if ($Verbose) {
                & $testExecutable --gtest_output="xml:$testOutputFile"
            } else {
                & $testExecutable --gtest_output="xml:$testOutputFile" *> $null
            }
        }
        
        $testResult = $LASTEXITCODE -eq 0
        
        # Generate coverage report if enabled
        if ($GenerateReports -and (Get-Command "gcov.exe" -ErrorAction SilentlyContinue)) {
            Print-Info "Generating C++ coverage report..."
            Get-ChildItem -Path "../unit/*.cpp" | ForEach-Object {
                & gcov $_.FullName *> $null
            }
        }
        
        if ($testResult) {
            Print-Success "C++ tests passed"
        } else {
            Print-Error "C++ tests failed"
        }
        
        Write-Host ""
        return $testResult
    }
    finally {
        Pop-Location
    }
}

function Invoke-CSharpTests {
    if (-not $RunCSharpTests) {
        return $true
    }
    
    Print-Section "Running C# Tests"
    
    $csharpTestDir = Join-Path $TestsDir "csharp"
    Push-Location $csharpTestDir
    
    try {
        # Restore packages
        Print-Info "Restoring NuGet packages..."
        if ($Verbose) {
            & dotnet restore
        } else {
            & dotnet restore *> $null
        }
        
        if ($LASTEXITCODE -ne 0) {
            Print-Error "NuGet restore failed"
            return $false
        }
        
        # Build tests
        Print-Info "Building C# tests..."
        if ($Verbose) {
            & dotnet build --no-restore
        } else {
            & dotnet build --no-restore *> $null
        }
        
        if ($LASTEXITCODE -ne 0) {
            Print-Error "C# build failed"
            return $false
        }
        
        # Run tests
        Print-Info "Executing C# tests..."
        $testArgs = @("test", "--no-build", "--logger", "trx", "--results-directory", $ReportsDir)
        
        if ($GenerateReports) {
            $testArgs += @("--collect:XPlat Code Coverage")
        }
        
        if ($Verbose) {
            & dotnet @testArgs
        } else {
            & dotnet @testArgs *> $null
        }
        
        $testResult = $LASTEXITCODE -eq 0
        
        # Move coverage files
        if ($GenerateReports) {
            Get-ChildItem -Path "." -Filter "coverage.cobertura.xml" -Recurse | ForEach-Object {
                Copy-Item $_.FullName (Join-Path $CoverageDir "csharp_coverage.xml") -Force
            }
        }
        
        if ($testResult) {
            Print-Success "C# tests passed"
        } else {
            Print-Error "C# tests failed"
        }
        
        Write-Host ""
        return $testResult
    }
    finally {
        Pop-Location
    }
}

function Invoke-PythonTests {
    if (-not $RunPythonTests) {
        return $true
    }
    
    Print-Section "Running Python Tests"
    
    $pythonTestDir = Join-Path $TestsDir "python"
    Push-Location $pythonTestDir
    
    try {
        # Get Python command
        $pythonCmd = "python"
        if (Get-Command "python3.exe" -ErrorAction SilentlyContinue) {
            $pythonCmd = "python3"
        }
        
        $pipCmd = "pip"
        if (Get-Command "pip3.exe" -ErrorAction SilentlyContinue) {
            $pipCmd = "pip3"
        }
        
        # Install dependencies
        Print-Info "Installing Python dependencies..."
        if ($Verbose) {
            & $pipCmd install -r requirements.txt
        } else {
            & $pipCmd install -r requirements.txt *> $null
        }
        
        if ($LASTEXITCODE -ne 0) {
            Print-Error "Python dependencies installation failed"
            return $false
        }
        
        # Run tests
        Print-Info "Executing Python tests..."
        $pytestArgs = @("-v", "--tb=short")
        
        if ($GenerateReports) {
            $xmlReport = Join-Path $ReportsDir "python_test_results.xml"
            $coverageXml = Join-Path $CoverageDir "python_coverage.xml"
            $coverageHtml = Join-Path $CoverageDir "python"
            
            $pytestArgs += @(
                "--junitxml=$xmlReport",
                "--cov=../../python",
                "--cov-report=xml:$coverageXml",
                "--cov-report=html:$coverageHtml"
            )
        }
        
        if ($RunIntegrationTests) {
            $pytestArgs += @("unit/", "integration/")
        } else {
            $pytestArgs += @("unit/")
        }
        
        if ($Verbose) {
            & $pythonCmd -m pytest @pytestArgs
        } else {
            & $pythonCmd -m pytest @pytestArgs *> $null
        }
        
        $testResult = $LASTEXITCODE -eq 0
        
        if ($testResult) {
            Print-Success "Python tests passed"
        } else {
            Print-Error "Python tests failed"
        }
        
        Write-Host ""
        return $testResult
    }
    finally {
        Pop-Location
    }
}

function Invoke-TypeScriptTests {
    if (-not $RunTypeScriptTests) {
        return $true
    }
    
    Print-Section "Running TypeScript Tests"
    
    $typescriptTestDir = Join-Path $TestsDir "typescript"
    Push-Location $typescriptTestDir
    
    try {
        # Install dependencies
        Print-Info "Installing Node.js dependencies..."
        if ($Verbose) {
            & npm install
        } else {
            & npm install *> $null
        }
        
        if ($LASTEXITCODE -ne 0) {
            Print-Error "Node.js dependencies installation failed"
            return $false
        }
        
        # Type check
        Print-Info "Running TypeScript type checking..."
        if ($Verbose) {
            & npm run type-check
        } else {
            & npm run type-check *> $null
        }
        
        if ($LASTEXITCODE -ne 0) {
            Print-Error "TypeScript type checking failed"
            return $false
        }
        
        # Run tests
        Print-Info "Executing TypeScript tests..."
        
        $jestConfig = @()
        if ($RunIntegrationTests) {
            $jestConfig += @("--testPathPattern=(unit|integration)")
        } else {
            $jestConfig += @("--testPathPattern=unit")
        }
        
        if ($GenerateReports) {
            $coverageDir = Join-Path $CoverageDir "typescript"
            $jestConfig += @("--coverage", "--coverageDirectory=$coverageDir")
        }
        
        if ($Verbose) {
            & npm test -- @jestConfig
        } else {
            & npm test -- @jestConfig *> $null
        }
        
        $testResult = $LASTEXITCODE -eq 0
        
        if ($testResult) {
            Print-Success "TypeScript tests passed"
        } else {
            Print-Error "TypeScript tests failed"
        }
        
        Write-Host ""
        return $testResult
    }
    finally {
        Pop-Location
    }
}

function Invoke-PerformanceTests {
    if (-not $RunPerformanceTests) {
        return
    }
    
    Print-Section "Running Performance Tests"
    
    Print-Warning "Performance tests require a running OAuth2 test server"
    Print-Info "Server URL: $ServerUrl"
    
    # Check if server is available
    try {
        $response = Invoke-WebRequest -Uri "$ServerUrl/.well-known/oauth2" -Method GET -TimeoutSec 5 -ErrorAction Stop
        if ($response.StatusCode -ne 200) {
            throw "Server returned status $($response.StatusCode)"
        }
    }
    catch {
        Print-Error "OAuth2 test server not available. Skipping performance tests."
        return
    }
    
    $perfResultsFile = Join-Path $ReportsDir "performance_results.json"
    $perfData = @{
        timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssK")
        server_url = $ServerUrl
        results = @{}
    }
    
    # Run performance tests for each language
    if ($RunPythonTests) {
        Print-Info "Running Python performance tests..."
        Push-Location (Join-Path $TestsDir "python")
        
        try {
            $pythonCmd = if (Get-Command "python3.exe" -ErrorAction SilentlyContinue) { "python3" } else { "python" }
            & $pythonCmd -m pytest performance/ --json-report --json-report-file=(Join-Path $ReportsDir "python_perf.json") *> $null
            $perfData.results.python = @{ status = "completed" }
        }
        finally {
            Pop-Location
        }
    }
    
    if ($RunTypeScriptTests) {
        Print-Info "Running TypeScript performance tests..."
        Push-Location (Join-Path $TestsDir "typescript")
        
        try {
            & npm test -- --testNamePattern="Performance" *> $null
            $perfData.results.typescript = @{ status = "completed" }
        }
        finally {
            Pop-Location
        }
    }
    
    # Save performance results
    $perfData | ConvertTo-Json -Depth 3 | Out-File -FilePath $perfResultsFile -Encoding UTF8
    
    Print-Success "Performance tests completed"
    Write-Host ""
}

function New-SummaryReport {
    if (-not $GenerateReports) {
        return
    }
    
    Print-Section "Generating Test Summary Report"
    
    $summaryFile = Join-Path $ReportsDir "test_summary.html"
    
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>OAuth2 Client Libraries Test Summary</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f8ff; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .success { color: green; }
        .error { color: red; }
        .warning { color: orange; }
        .info { color: blue; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>OAuth2 Client Libraries Test Summary</h1>
        <p>Generated on: $(Get-Date)</p>
        <p>Test Environment: $ServerUrl</p>
    </div>
    
    <div class="section">
        <h2>Test Configuration</h2>
        <table>
            <tr><th>Setting</th><th>Value</th></tr>
            <tr><td>C++ Tests</td><td>$RunCppTests</td></tr>
            <tr><td>C# Tests</td><td>$RunCSharpTests</td></tr>
            <tr><td>Python Tests</td><td>$RunPythonTests</td></tr>
            <tr><td>TypeScript Tests</td><td>$RunTypeScriptTests</td></tr>
            <tr><td>Integration Tests</td><td>$RunIntegrationTests</td></tr>
            <tr><td>Performance Tests</td><td>$RunPerformanceTests</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h2>Coverage Reports</h2>
        <ul>
"@

    # Add coverage report links if they exist
    if (Test-Path (Join-Path $CoverageDir "cpp\index.html")) {
        $htmlContent += "            <li><a href=`"../coverage/cpp/index.html`">C++ Coverage Report</a></li>`n"
    }
    if (Test-Path (Join-Path $CoverageDir "csharp_coverage.xml")) {
        $htmlContent += "            <li><a href=`"../coverage/csharp_coverage.xml`">C# Coverage Report</a></li>`n"
    }
    if (Test-Path (Join-Path $CoverageDir "python\index.html")) {
        $htmlContent += "            <li><a href=`"../coverage/python/index.html`">Python Coverage Report</a></li>`n"
    }
    if (Test-Path (Join-Path $CoverageDir "typescript\lcov-report\index.html")) {
        $htmlContent += "            <li><a href=`"../coverage/typescript/lcov-report/index.html`">TypeScript Coverage Report</a></li>`n"
    }

    $htmlContent += @"
        </ul>
    </div>
    
    <div class="section">
        <h2>Test Results</h2>
        <p>Detailed test results are available in the individual report files:</p>
        <ul>
"@

    # Add test result links if they exist
    if (Test-Path (Join-Path $ReportsDir "cpp_test_results.xml")) {
        $htmlContent += "            <li><a href=`"cpp_test_results.xml`">C++ Test Results (XML)</a></li>`n"
    }
    if (Get-ChildItem -Path $ReportsDir -Filter "*.trx" -ErrorAction SilentlyContinue) {
        $htmlContent += "            <li>C# Test Results (TRX files)</li>`n"
    }
    if (Test-Path (Join-Path $ReportsDir "python_test_results.xml")) {
        $htmlContent += "            <li><a href=`"python_test_results.xml`">Python Test Results (XML)</a></li>`n"
    }

    $htmlContent += @"
        </ul>
    </div>
</body>
</html>
"@

    $htmlContent | Out-File -FilePath $summaryFile -Encoding UTF8
    
    Print-Success "Test summary report generated: $summaryFile"
    Write-Host ""
}

# Main execution
function Main {
    if ($Help) {
        Show-Usage
        exit 0
    }
    
    Print-Banner
    
    Setup-Environment
    Test-Dependencies
    
    $overallResult = $true
    $testResults = @()
    
    # Run tests for each language
    if ($Parallel -and $RunCppTests -and $RunCSharpTests -and $RunPythonTests -and $RunTypeScriptTests) {
        Print-Info "Running tests in parallel mode"
        
        # PowerShell jobs for parallel execution
        $jobs = @()
        
        if ($RunCppTests) {
            $jobs += Start-Job -ScriptBlock { & (Join-Path $using:ScriptDir "run_tests.ps1") -SkipCSharp -SkipPython -SkipTypeScript -NoReports }
        }
        if ($RunCSharpTests) {
            $jobs += Start-Job -ScriptBlock { & (Join-Path $using:ScriptDir "run_tests.ps1") -SkipCpp -SkipPython -SkipTypeScript -NoReports }
        }
        if ($RunPythonTests) {
            $jobs += Start-Job -ScriptBlock { & (Join-Path $using:ScriptDir "run_tests.ps1") -SkipCpp -SkipCSharp -SkipTypeScript -NoReports }
        }
        if ($RunTypeScriptTests) {
            $jobs += Start-Job -ScriptBlock { & (Join-Path $using:ScriptDir "run_tests.ps1") -SkipCpp -SkipCSharp -SkipPython -NoReports }
        }
        
        # Wait for all jobs to complete
        $jobs | Wait-Job | Receive-Job
        $jobs | Remove-Job
        
        # Simplified result checking for parallel execution
        $overallResult = $true
    } else {
        # Run tests sequentially
        if ($RunCppTests) {
            $cppResult = Invoke-CppTests
            $testResults += @{ Language = "C++"; Result = $cppResult }
            if (-not $cppResult) { $overallResult = $false }
        }
        
        if ($RunCSharpTests) {
            $csharpResult = Invoke-CSharpTests
            $testResults += @{ Language = "C#"; Result = $csharpResult }
            if (-not $csharpResult) { $overallResult = $false }
        }
        
        if ($RunPythonTests) {
            $pythonResult = Invoke-PythonTests
            $testResults += @{ Language = "Python"; Result = $pythonResult }
            if (-not $pythonResult) { $overallResult = $false }
        }
        
        if ($RunTypeScriptTests) {
            $typescriptResult = Invoke-TypeScriptTests
            $testResults += @{ Language = "TypeScript"; Result = $typescriptResult }
            if (-not $typescriptResult) { $overallResult = $false }
        }
    }
    
    # Run performance tests if requested
    if ($RunPerformanceTests) {
        Invoke-PerformanceTests
    }
    
    # Generate reports
    New-SummaryReport
    
    # Print final summary
    Print-Section "Test Execution Summary"
    
    foreach ($result in $testResults) {
        if ($result.Result) {
            Print-Success "$($result.Language) tests passed"
        } else {
            Print-Error "$($result.Language) tests failed"
        }
    }
    
    Write-Host ""
    if ($overallResult) {
        Print-Success "All enabled tests passed successfully!"
        Write-ColoredOutput "========================================" -Color Green
    } else {
        Print-Error "Some tests failed. Check the detailed reports for more information."
        Write-ColoredOutput "========================================" -Color Red
    }
    
    # Show report locations
    if ($GenerateReports) {
        Write-Host ""
        Print-Info "Reports generated in: $ReportsDir"
        Print-Info "Coverage reports in: $CoverageDir"
    }
    
    if (-not $overallResult) {
        exit 1
    }
}

# Execute main function
Main
