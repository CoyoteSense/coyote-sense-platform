# OAuth2 Test Server Management Script (PowerShell)
# Manages the OAuth2 Mock Server for integration testing

param(
    [Parameter(Position=0)]
    [ValidateSet("start", "stop", "status", "test", "restart")]
    [string]$Command = "status"
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$DockerComposeFile = Join-Path $ScriptDir "docker-compose.oauth2.yml"
$OAuth2ServerUrl = "http://localhost:8081"

function Write-Success {
    param([string]$Message)
    Write-Host "✓ $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "✗ $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "ℹ $Message" -ForegroundColor Blue
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠ $Message" -ForegroundColor Yellow
}

function Start-OAuth2Server {
    Write-Info "Starting OAuth2 Mock Server..."
    
    # Check if Docker is available
    if (!(Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Error "Docker is not installed or not in PATH"
        return $false
    }
    
    # Use docker compose (new) or docker-compose (legacy)
    $DockerCmd = "docker"
    try {
        docker compose version 2>$null | Out-Null
        $DockerArgs = "compose", "-f", $DockerComposeFile, "up", "-d", "oauth2-mock"
    } catch {
        if (Get-Command docker-compose -ErrorAction SilentlyContinue) {
            $DockerCmd = "docker-compose"
            $DockerArgs = "-f", $DockerComposeFile, "up", "-d", "oauth2-mock"
        } else {
            Write-Error "Neither 'docker compose' nor 'docker-compose' is available"
            return $false
        }
    }
    
    Write-Info "Using command: $DockerCmd $($DockerArgs -join ' ')"
    
    # Start the OAuth2 server
    & $DockerCmd @DockerArgs
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "OAuth2 Mock Server started successfully"
        Write-Info "Server URL: $OAuth2ServerUrl"
        Write-Info "Waiting for server to be ready..."
        
        # Wait for server to be ready
        $retries = 30
        $count = 0
        while ($count -lt $retries) {
            try {
                $response = Invoke-WebRequest -Uri "$OAuth2ServerUrl/.well-known/oauth2" -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
                if ($response.StatusCode -eq 200) {
                    Write-Success "OAuth2 server is ready!"
                    return $true
                }
            } catch {
                # Ignore errors and continue waiting
            }
            Write-Host "." -NoNewline
            Start-Sleep -Seconds 1
            $count++
        }
        
        Write-Host ""
        Write-Error "OAuth2 server did not become ready within 30 seconds"
        return $false
    } else {
        Write-Error "Failed to start OAuth2 Mock Server"
        return $false
    }
}

function Stop-OAuth2Server {
    Write-Info "Stopping OAuth2 Mock Server..."
    
    # Use docker compose (new) or docker-compose (legacy)
    $DockerCmd = "docker"
    try {
        docker compose version 2>$null | Out-Null
        $DockerArgs = "compose", "-f", $DockerComposeFile, "down"
    } catch {
        if (Get-Command docker-compose -ErrorAction SilentlyContinue) {
            $DockerCmd = "docker-compose"
            $DockerArgs = "-f", $DockerComposeFile, "down"
        } else {
            Write-Error "Neither 'docker compose' nor 'docker-compose' is available"
            return $false
        }
    }
    
    & $DockerCmd @DockerArgs
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "OAuth2 Mock Server stopped successfully"
        return $true
    } else {
        Write-Error "Failed to stop OAuth2 Mock Server"
        return $false
    }
}

function Test-OAuth2Server {
    Write-Info "Checking OAuth2 Mock Server status..."
    
    try {
        $response = Invoke-WebRequest -Uri "$OAuth2ServerUrl/.well-known/oauth2" -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) {
            Write-Success "OAuth2 server is running and accessible"
            Write-Info "Server URL: $OAuth2ServerUrl"
            return $true
        } else {
            Write-Error "OAuth2 server returned status code: $($response.StatusCode)"
            return $false
        }
    } catch {
        Write-Error "OAuth2 server is not accessible: $($_.Exception.Message)"
        return $false
    }
}

function Test-OAuth2ServerFunctionality {
    Write-Info "Testing OAuth2 Mock Server..."
    
    # Test client credentials flow
    Write-Info "Testing client credentials flow..."
    
    try {
        $body = @{
            grant_type = "client_credentials"
            client_id = "test-client-id"
            client_secret = "test-client-secret"
            scope = "api.read api.write"
        }
        
        $response = Invoke-WebRequest -Uri "$OAuth2ServerUrl/token" -Method POST -Body $body -ContentType "application/x-www-form-urlencoded" -UseBasicParsing -ErrorAction SilentlyContinue
        
        if ($response.StatusCode -eq 200 -and $response.Content -like "*access_token*") {
            Write-Success "Client credentials flow works!"
            Write-Info "Token response: $($response.Content)"
        } else {
            Write-Error "Client credentials flow failed"
            Write-Error "Response: $($response.Content)"
            return $false
        }
    } catch {
        Write-Error "Client credentials flow failed: $($_.Exception.Message)"
        return $false
    }
    
    # Test server discovery
    Write-Info "Testing server discovery..."
    
    try {
        $response = Invoke-WebRequest -Uri "$OAuth2ServerUrl/.well-known/oauth2" -UseBasicParsing -ErrorAction SilentlyContinue
        
        if ($response.StatusCode -eq 200 -and $response.Content -like "*token_endpoint*") {
            Write-Success "Server discovery works!"
            Write-Info "Discovery response: $($response.Content)"
        } else {
            Write-Error "Server discovery failed"
            Write-Error "Response: $($response.Content)"
            return $false
        }
    } catch {
        Write-Error "Server discovery failed: $($_.Exception.Message)"
        return $false
    }
    
    return $true
}

function Show-Usage {
    Write-Host "Usage: .\manage-oauth2-server.ps1 [start|stop|status|test|restart]"
    Write-Host ""
    Write-Host "Commands:"
    Write-Host "  start    - Start the OAuth2 Mock Server"
    Write-Host "  stop     - Stop the OAuth2 Mock Server"
    Write-Host "  status   - Check if the OAuth2 Mock Server is running"
    Write-Host "  test     - Test the OAuth2 Mock Server functionality"
    Write-Host "  restart  - Restart the OAuth2 Mock Server"
    Write-Host ""
}

# Main execution
switch ($Command) {
    "start" {
        $success = Start-OAuth2Server
        if (-not $success) { exit 1 }
    }
    "stop" {
        $success = Stop-OAuth2Server
        if (-not $success) { exit 1 }
    }
    "status" {
        $success = Test-OAuth2Server
        if (-not $success) { exit 1 }
    }
    "test" {
        $success = Test-OAuth2ServerFunctionality
        if (-not $success) { exit 1 }
    }
    "restart" {
        $success = Stop-OAuth2Server
        if ($success) {
            Start-Sleep -Seconds 2
            $success = Start-OAuth2Server
        }
        if (-not $success) { exit 1 }
    }
    default {
        Show-Usage
        exit 1
    }
}
