# OAuth2 Test Server Management Script (PowerShell)
# Manages Docker containers for OAuth2 integration testing

param(
    [Parameter(Position=0)]
    [ValidateSet("start", "stop", "restart", "status", "logs", "test", "clean")]
    [string]$Command = "status",
    
    [Parameter(Position=1)]
    [ValidateSet("mock", "keycloak", "hydra", "spring", "all")]
    [string]$Server = "mock",
    
    [switch]$Detach,
    [switch]$Verbose,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

# Script configuration
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DockerComposeFile = Join-Path $ScriptDir "docker-compose.oauth2.yml"

function Write-Success {
    param([string]$Message)
    Write-Host "✓ $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "✗ $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠ $Message" -ForegroundColor Yellow
}

function Write-Info {
    param([string]$Message)
    Write-Host "ℹ $Message" -ForegroundColor Blue
}

function Show-Usage {
    Write-Host @"
Usage: .\manage-oauth2-servers.ps1 [COMMAND] [SERVER] [OPTIONS]

Manage OAuth2 test servers for integration testing.

COMMANDS:
    start [server]      Start OAuth2 server(s)
    stop [server]       Stop OAuth2 server(s)
    restart [server]    Restart OAuth2 server(s)
    status              Show status of all servers
    logs [server]       Show logs for server
    test [server]       Test server connectivity
    clean               Stop and remove all containers and volumes

SERVERS:
    mock               OAuth2 Mock Server (recommended for testing)
    keycloak          Keycloak Identity Provider
    hydra             Ory Hydra OAuth2 Server
    spring            Spring Authorization Server
    all               All servers (default)

OPTIONS:
    -Detach           Run in background (detached mode)
    -Verbose          Enable verbose output
    -Help             Show this help message

EXAMPLES:
    .\manage-oauth2-servers.ps1 start mock                Start OAuth2 Mock Server
    .\manage-oauth2-servers.ps1 start keycloak -Detach    Start Keycloak in background
    .\manage-oauth2-servers.ps1 test mock                 Test OAuth2 Mock Server
    .\manage-oauth2-servers.ps1 logs keycloak             Show Keycloak logs
    .\manage-oauth2-servers.ps1 status                    Show status of all servers
    .\manage-oauth2-servers.ps1 clean                     Clean up all containers

ENDPOINTS (when running):
    OAuth2 Mock Server:    http://localhost:8081
    Keycloak:             http://localhost:8080
    Ory Hydra:            http://localhost:4444
    Spring Auth Server:   http://localhost:9000

"@
}

function Test-Docker {
    try {
        docker --version | Out-Null
    } catch {
        Write-Error "Docker is not installed or not in PATH"
        exit 1
    }
    
    try {
        docker-compose --version | Out-Null
        $script:ComposeCommand = "docker-compose"
    } catch {
        try {
            docker compose version | Out-Null
            $script:ComposeCommand = "docker compose"
        } catch {
            Write-Error "Docker Compose is not installed"
            exit 1
        }
    }
    
    try {
        docker info | Out-Null
    } catch {
        Write-Error "Docker daemon is not running"
        exit 1
    }
}

function Start-Server {
    param([string]$ServerName)
    
    $DetachFlag = if ($Detach) { "-d" } else { "" }
    
    Write-Info "Starting OAuth2 server: $ServerName"
    
    switch ($ServerName) {
        "mock" {
            & $script:ComposeCommand -f $DockerComposeFile up $DetachFlag oauth2-mock
        }
        "keycloak" {
            & $script:ComposeCommand -f $DockerComposeFile up $DetachFlag keycloak
        }
        "hydra" {
            & $script:ComposeCommand -f $DockerComposeFile up $DetachFlag hydra
        }
        "spring" {
            & $script:ComposeCommand -f $DockerComposeFile up $DetachFlag spring-authz
        }
        "all" {
            & $script:ComposeCommand -f $DockerComposeFile up $DetachFlag
        }
        default {
            Write-Error "Unknown server: $ServerName"
            Show-Usage
            exit 1
        }
    }
    
    if ($Detach) {
        Write-Success "Started $ServerName in background"
        Write-Info "Use '.\manage-oauth2-servers.ps1 logs $ServerName' to view logs"
        Write-Info "Use '.\manage-oauth2-servers.ps1 status' to check status"
    }
}

function Stop-Server {
    param([string]$ServerName)
    
    Write-Info "Stopping OAuth2 server: $ServerName"
    
    switch ($ServerName) {
        "mock" {
            & $script:ComposeCommand -f $DockerComposeFile stop oauth2-mock
        }
        "keycloak" {
            & $script:ComposeCommand -f $DockerComposeFile stop keycloak
        }
        "hydra" {
            & $script:ComposeCommand -f $DockerComposeFile stop hydra
        }
        "spring" {
            & $script:ComposeCommand -f $DockerComposeFile stop spring-authz
        }
        "all" {
            & $script:ComposeCommand -f $DockerComposeFile stop
        }
        default {
            Write-Error "Unknown server: $ServerName"
            Show-Usage
            exit 1
        }
    }
    
    Write-Success "Stopped $ServerName"
}

function Restart-Server {
    param([string]$ServerName)
    
    Write-Info "Restarting OAuth2 server: $ServerName"
    Stop-Server $ServerName
    Start-Sleep 2
    Start-Server $ServerName
}

function Show-Status {
    Write-Info "OAuth2 Test Servers Status:"
    Write-Host ""
    
    & $script:ComposeCommand -f $DockerComposeFile ps
    
    Write-Host ""
    Write-Info "Service URLs:"
    Write-Host "  OAuth2 Mock Server:    http://localhost:8081"
    Write-Host "  Keycloak:             http://localhost:8080"
    Write-Host "  Ory Hydra:            http://localhost:4444"
    Write-Host "  Spring Auth Server:   http://localhost:9000"
}

function Show-Logs {
    param([string]$ServerName)
    
    switch ($ServerName) {
        "mock" {
            & $script:ComposeCommand -f $DockerComposeFile logs -f oauth2-mock
        }
        "keycloak" {
            & $script:ComposeCommand -f $DockerComposeFile logs -f keycloak
        }
        "hydra" {
            & $script:ComposeCommand -f $DockerComposeFile logs -f hydra
        }
        "spring" {
            & $script:ComposeCommand -f $DockerComposeFile logs -f spring-authz
        }
        "all" {
            & $script:ComposeCommand -f $DockerComposeFile logs -f
        }
        default {
            Write-Error "Unknown server: $ServerName"
            Show-Usage
            exit 1
        }
    }
}

function Test-Server {
    param([string]$ServerName)
    
    Write-Info "Testing OAuth2 server: $ServerName"
    
    $Url = ""
    $WellKnownEndpoint = ""
    
    switch ($ServerName) {
        "mock" {
            $Url = "http://localhost:8081"
            $WellKnownEndpoint = "$Url/.well-known/openid_configuration"
        }
        "keycloak" {
            $Url = "http://localhost:8080"
            $WellKnownEndpoint = "$Url/realms/coyote-test/.well-known/openid_configuration"
        }
        "hydra" {
            $Url = "http://localhost:4444"
            $WellKnownEndpoint = "$Url/.well-known/openid_configuration"
        }
        "spring" {
            $Url = "http://localhost:9000"
            $WellKnownEndpoint = "$Url/.well-known/openid_configuration"
        }
        default {
            Write-Error "Unknown server: $ServerName"
            exit 1
        }
    }
    
    # Test basic connectivity
    Write-Info "Testing connectivity to $Url..."
    try {
        Invoke-RestMethod -Uri $Url -Method Get -TimeoutSec 5 | Out-Null
        Write-Success "Server is responding"
    } catch {
        Write-Error "Server is not responding"
        return $false
    }
    
    # Test OpenID configuration
    Write-Info "Testing OpenID configuration endpoint..."
    try {
        Invoke-RestMethod -Uri $WellKnownEndpoint -Method Get -TimeoutSec 5 | Out-Null
        Write-Success "OpenID configuration endpoint is working"
    } catch {
        Write-Warning "OpenID configuration endpoint is not available"
    }
    
    # Test OAuth2 token endpoint for mock server
    if ($ServerName -eq "mock") {
        Write-Info "Testing OAuth2 token endpoint..."
        try {
            $body = @{
                grant_type = "client_credentials"
                client_id = "test-client-id"
                client_secret = "test-client-secret"
                scope = "api.read"
            }
            
            $response = Invoke-RestMethod -Uri "$Url/token" -Method Post -Body $body -ContentType "application/x-www-form-urlencoded" -TimeoutSec 5
            
            if ($response.access_token) {
                Write-Success "OAuth2 token endpoint is working"
            } else {
                Write-Warning "OAuth2 token endpoint test failed"
            }
        } catch {
            Write-Warning "OAuth2 token endpoint test failed: $($_.Exception.Message)"
        }
    }
    
    Write-Success "Server $ServerName is ready for integration tests"
    return $true
}

function Remove-AllContainers {
    Write-Info "Cleaning up all OAuth2 test containers..."
    
    & $script:ComposeCommand -f $DockerComposeFile down -v --remove-orphans
    
    Write-Success "All containers and volumes removed"
}

# Show help if requested
if ($Help) {
    Show-Usage
    exit 0
}

# Check Docker availability
Test-Docker

# Execute command
switch ($Command) {
    "start" {
        Start-Server $Server
    }
    "stop" {
        Stop-Server $Server
    }
    "restart" {
        Restart-Server $Server
    }
    "status" {
        Show-Status
    }
    "logs" {
        Show-Logs $Server
    }
    "test" {
        Test-Server $Server
    }
    "clean" {
        Remove-AllContainers
    }
    default {
        Write-Error "Unknown command: $Command"
        Show-Usage
        exit 1
    }
}
