# Test script with just the relevant section
function global:Print-Error { param($msg) Write-Host $msg -ForegroundColor Red }
function global:Print-Success { param($msg) Write-Host $msg -ForegroundColor Green }
function global:Print-Section { param($msg) Write-Host $msg -ForegroundColor Yellow }

$TestsDir = "."
$ReportsDir = "."
$RunCppTests = $true
$Verbose = $false
$GenerateReports = $false

function global:Invoke-CppTests {
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
        Write-Host "ℹ Configuring C++ tests with CMake..." -ForegroundColor Blue
        $cmakeArgs = @("..", "-DCMAKE_BUILD_TYPE=Debug", "-DENABLE_COVERAGE=ON")
        
        if ($Verbose) {
            Write-Host "Would run: cmake $cmakeArgs"
        } else {
            Write-Host "Would run: cmake $cmakeArgs (silent)"
        }
        
        $LASTEXITCODE = 0  # Simulate success
        if ($LASTEXITCODE -ne 0) {
            Print-Error "CMake configuration failed"
            return $false
        }
        
        # Build tests
        Write-Host "ℹ Building C++ tests..." -ForegroundColor Blue
        if ($Verbose) {
            Write-Host "Would run: cmake --build . --config Debug"
        } else {
            Write-Host "Would run: cmake --build . --config Debug (silent)"
        }
        
        if ($LASTEXITCODE -ne 0) {
            Print-Error "C++ build failed"
            return $false
        }
        
        # Run tests
        Write-Host "ℹ Executing C++ tests..." -ForegroundColor Blue
        $testOutputFile = Join-Path $ReportsDir "cpp_test_results.xml"
        $testExecutable = ".\Debug\oauth2_auth_client_test.exe"
        
        $testResult = $true  # Simulate success
        
        # Generate coverage report if enabled
        if ($GenerateReports -and (Get-Command "gcov.exe" -ErrorAction SilentlyContinue)) {
            Write-Host "ℹ Generating C++ coverage report..." -ForegroundColor Blue
            Get-ChildItem -Path "../unit/*.cpp" -ErrorAction SilentlyContinue | ForEach-Object {
                Write-Host "Would run: gcov $($_.FullName)"
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

Write-Host "Testing C++ function..."
Invoke-CppTests
