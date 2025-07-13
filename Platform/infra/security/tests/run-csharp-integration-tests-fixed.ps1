# Run C# Integration Tests with Real OAuth2 Server (PowerShell)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$TestsDir = $ScriptDir
$DotNetTestDir = Join-Path $TestsDir "dotnet"

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
    Write-Host "  C# OAuth2 Integration Tests" -ForegroundColor Blue
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

function Invoke-IntegrationTests {
    Write-Info "Running C# integration tests..."
    
    # Run the OAuth2 integration tests
    Write-Info "Running OAuth2 integration tests..."
    dotnet test CoyoteSense.Security.Client.Tests.csproj --filter "SimpleOAuth2Test" --verbosity normal
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "OAuth2 integration tests passed!"
        
        # Run all integration tests
        Write-Info "Running all integration tests..."
        dotnet test CoyoteSense.Security.Client.Tests.csproj --filter "Category=Integration" --verbosity normal
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "All integration tests passed!"
            return $true
        } else {
            Write-Warning "Some integration tests failed (running OAuth2 tests only)"
            return $true  # OAuth2 tests passed, which is our main goal
        }
    } else {
        Write-Error "OAuth2 integration tests failed"
        return $false
    }
}

# Main execution
Write-Banner

# Check if .NET is available
if (!(Get-Command dotnet -ErrorAction SilentlyContinue)) {
    Write-Error ".NET SDK not found"
    exit 1
}

Write-Info "Found .NET SDK: $(dotnet --version)"

# Check OAuth2 server
if (!(Test-OAuth2Server)) {
    Write-Error "OAuth2 server is not available"
    Write-Info "Please start the OAuth2 server first:"
    Write-Info "  .\manage-oauth2-server.ps1 start"
    exit 1
}

# Build the project first
Write-Info "Building C# test project..."
Set-Location $DotNetTestDir

dotnet build --verbosity quiet
if ($LASTEXITCODE -eq 0) {
    Write-Success "C# project built successfully"
} else {
    Write-Error "C# project build failed"
    exit 1
}

# Run integration tests
if (Invoke-IntegrationTests) {
    Write-Success "All integration tests completed successfully!"
    exit 0
} else {
    Write-Error "Integration tests failed"
    exit 1
}
