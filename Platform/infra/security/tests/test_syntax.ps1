function Test-TryFinally {
    try {
        Write-Host "In try block"
        return $true
    }
    finally {
        Write-Host "In finally block"
    }
}

Test-TryFinally
