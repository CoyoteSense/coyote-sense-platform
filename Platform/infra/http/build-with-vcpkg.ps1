# Build script for HTTP client with vcpkg CURL
# Run this script from the http directory

param(
    [string]$VcpkgRoot = "C:\vcpkg",
    [string]$BuildType = "Release"
)

# Check if vcpkg exists
if (-not (Test-Path $VcpkgRoot)) {
    Write-Error "vcpkg not found at $VcpkgRoot. Please install vcpkg first."
    Write-Host "To install vcpkg:"
    Write-Host "1. git clone https://github.com/Microsoft/vcpkg.git C:\vcpkg"
    Write-Host "2. cd C:\vcpkg"
    Write-Host "3. .\bootstrap-vcpkg.bat"
    Write-Host "4. .\vcpkg install curl[tool]:x64-windows"
    exit 1
}

# Set environment variable
$env:VCPKG_ROOT = $VcpkgRoot

# Create build directory
$BuildDir = "build-vcpkg"
if (Test-Path $BuildDir) {
    Remove-Item -Recurse -Force $BuildDir
}
New-Item -ItemType Directory -Path $BuildDir | Out-Null

# Configure CMake with vcpkg toolchain
Set-Location $BuildDir
cmake .. `
    -DCMAKE_TOOLCHAIN_FILE="$VcpkgRoot\scripts\buildsystems\vcpkg.cmake" `
    -DCMAKE_BUILD_TYPE=$BuildType `
    -DBUILD_HTTP_CLIENT_EXAMPLES=ON `
    -DBUILD_HTTP_CLIENT_TESTS=ON

if ($LASTEXITCODE -ne 0) {
    Write-Error "CMake configuration failed"
    exit 1
}

# Build
cmake --build . --config $BuildType

if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed"
    exit 1
}

Write-Host "✅ Build completed successfully!" -ForegroundColor Green
Write-Host "Built with CURL support using vcpkg" -ForegroundColor Green

# Go back to original directory
Set-Location ..
