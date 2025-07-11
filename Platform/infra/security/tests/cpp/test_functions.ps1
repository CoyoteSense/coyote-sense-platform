# Simple syntax test
function Test-Syntax {
    Write-Host "Testing syntax"
}

# Test each function signature
function global:Print-Section { param([string]$Title) }
function global:Print-Success { param([string]$Message) }
function global:Print-Error { param([string]$Message) }
function global:Print-Warning { param([string]$Message) }
function global:Print-Info { param([string]$Message) }

# Test basic try/finally
function Test-TryFinally {
    try {
        Write-Host "Test"
        return $true
    }
    finally {
        Write-Host "Finally"
    }
}

Test-Syntax
Test-TryFinally
