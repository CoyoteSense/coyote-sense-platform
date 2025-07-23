#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Fix security vulnerabilities in CoyoteSense platform dependencies

.DESCRIPTION
    This script updates vulnerable dependencies and regenerates package-lock.json files
    to fix the identified security issues:
    - CVE-2025-7338: Multer vulnerable to Denial of Service
    - Form-data uses unsafe random function for boundary generation

.PARAMETER Force
    Force update even if vulnerabilities are already fixed

.EXAMPLE
    .\fix-security-vulnerabilities.ps1
    Fix security vulnerabilities in all affected packages
#>

param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# Colors for output
$Green = "`e[32m"
$Red = "`e[31m"
$Yellow = "`e[33m"
$Blue = "`e[34m"
$Cyan = "`e[36m"
$Reset = "`e[0m"

function Write-ColorOutput {
    param([string]$Message, [string]$Color = $Reset)
    Write-Host "${Color}${Message}${Reset}"
}

function Write-Section {
    param([string]$Title)
    Write-ColorOutput "`n$('='*60)" $Cyan
    Write-ColorOutput "  $Title" $Cyan
    Write-ColorOutput "$('='*60)" $Cyan
}

Write-Section "CoyoteSense Security Vulnerability Fix"
Write-ColorOutput "Fixing identified security vulnerabilities in dependencies" $Blue

# Check if we're in the correct directory
if (-not (Test-Path "Platform\infra\security\tests")) {
    Write-ColorOutput "ERROR: Please run from project root directory" $Red
    exit 1
}

# List of packages to update
$packagesToUpdate = @(
    @{
        Path = "Platform\infra\http\tests\integration"
        Name = "HTTP Integration Tests"
        Dependencies = @{
            "multer" = "^2.0.0-rc.3"
        }
    },
    @{
        Path = "Platform\infra\security\tests\ts"
        Name = "Security TypeScript Tests"
        Dependencies = @{}
        Overrides = @{
            "form-data" = "^4.0.0"
        }
    }
)

$totalFixed = 0
$totalErrors = 0

foreach ($package in $packagesToUpdate) {
    Write-Section "Processing $($package.Name)"
    
    $packagePath = $package.Path
    $packageJsonPath = "$packagePath\package.json"
    
    if (-not (Test-Path $packageJsonPath)) {
        Write-ColorOutput "WARNING: package.json not found at $packageJsonPath" $Yellow
        continue
    }
    
    Push-Location $packagePath
    try {
        Write-ColorOutput "Working directory: $(Get-Location)" $Blue
        
        # Update dependencies if specified
        if ($package.Dependencies.Count -gt 0) {
            Write-ColorOutput "Updating dependencies..." $Blue
            foreach ($dep in $package.Dependencies.GetEnumerator()) {
                $depName = $dep.Key
                $depVersion = $dep.Value
                Write-ColorOutput "  Updating $depName to $depVersion" $Blue
                
                $npmCommand = "npm install $depName@$depVersion --save"
                Write-ColorOutput "  Running: $npmCommand" $Blue
                
                $result = Invoke-Expression $npmCommand 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-ColorOutput "  ✓ Successfully updated $depName" $Green
                } else {
                    Write-ColorOutput "  ✗ Failed to update $depName" $Red
                    Write-ColorOutput "  Error: $result" $Red
                    $totalErrors++
                }
            }
        }
        
        # Add overrides if specified
        if ($package.Overrides.Count -gt 0) {
            Write-ColorOutput "Adding package overrides..." $Blue
            
            # Read current package.json
            $packageJson = Get-Content $packageJsonPath | ConvertFrom-Json
            
            # Add overrides section
            if (-not $packageJson.overrides) {
                $packageJson | Add-Member -MemberType NoteProperty -Name "overrides" -Value @{}
            }
            
            foreach ($override in $package.Overrides.GetEnumerator()) {
                $packageJson.overrides | Add-Member -MemberType NoteProperty -Name $override.Key -Value $override.Value -Force
                Write-ColorOutput "  Added override: $($override.Key) = $($override.Value)" $Blue
            }
            
            # Write back to package.json
            $packageJson | ConvertTo-Json -Depth 10 | Set-Content $packageJsonPath
            Write-ColorOutput "  ✓ Updated package.json with overrides" $Green
        }
        
        # Regenerate package-lock.json
        Write-ColorOutput "Regenerating package-lock.json..." $Blue
        $result = npm install 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "  ✓ Successfully regenerated package-lock.json" $Green
            $totalFixed++
        } else {
            Write-ColorOutput "  ✗ Failed to regenerate package-lock.json" $Red
            Write-ColorOutput "  Error: $result" $Red
            $totalErrors++
        }
        
        # Run security audit
        Write-ColorOutput "Running security audit..." $Blue
        $auditResult = npm audit --audit-level=high 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "  ✓ No high/critical vulnerabilities found" $Green
        } else {
            Write-ColorOutput "  ⚠ Security audit found issues:" $Yellow
            Write-ColorOutput "  $auditResult" $Yellow
        }
        
    }
    catch {
        Write-ColorOutput "Error processing $($package.Name): $_" $Red
        $totalErrors++
    }
    finally {
        Pop-Location
    }
}

# Summary
Write-Section "Security Fix Summary"

if ($totalErrors -eq 0) {
    Write-ColorOutput "✓ Successfully fixed security vulnerabilities in $totalFixed packages" $Green
    Write-ColorOutput "✓ All package-lock.json files have been regenerated" $Green
    Write-ColorOutput "✓ Multer updated to secure version 2.0.0-rc.3" $Green
    Write-ColorOutput "✓ Form-data overrides added to prevent unsafe random usage" $Green
} else {
    Write-ColorOutput "⚠ Fixed $totalFixed packages but encountered $totalErrors errors" $Yellow
    Write-ColorOutput "Please review the errors above and fix manually if needed" $Yellow
}

Write-ColorOutput "`nNext steps:" $Blue
Write-ColorOutput "1. Test the updated packages to ensure functionality is preserved" $Blue
Write-ColorOutput "2. Run integration tests to verify security fixes work correctly" $Blue
Write-ColorOutput "3. Consider running 'npm audit fix' in individual packages if needed" $Blue

if ($totalErrors -gt 0) {
    exit 1
} else {
    exit 0
} 