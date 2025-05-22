# Generate Protocol Buffer code for C++
# This script generates C++ code from .proto files

param(
    [string]$ProtoDir = "..\..\..\..\Models\proto",
    [string]$OutputDir = "..\..\..\..\Models\generated\cpp"
)

Write-Host "Generating Protocol Buffer code for C++"
Write-Host "Proto directory: $ProtoDir"
Write-Host "Output directory: $OutputDir"

# Check if protoc is available
if (-not (Get-Command "protoc" -ErrorAction SilentlyContinue)) {
    Write-Error "protoc compiler not found. Please install Protocol Buffers."
    Write-Host "Download from: https://github.com/protocolbuffers/protobuf/releases"
    exit 1
}

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force
    Write-Host "Created output directory: $OutputDir"
}

# Find all .proto files
$protoFiles = Get-ChildItem -Path $ProtoDir -Filter "*.proto"

if ($protoFiles.Count -eq 0) {
    Write-Warning "No .proto files found in $ProtoDir"
    exit 1
}

Write-Host "Found $($protoFiles.Count) proto files:"
$protoFiles | ForEach-Object { Write-Host "  - $($_.Name)" }

# Generate C++ code
foreach ($protoFile in $protoFiles) {
    Write-Host "Generating code for $($protoFile.Name)..."
    
    $command = "protoc"
    $args = @(
        "--cpp_out=$OutputDir",
        "--proto_path=$ProtoDir",
        $protoFile.FullName
    )
    
    try {
        & $command $args
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ✓ Successfully generated $($protoFile.BaseName).pb.h and $($protoFile.BaseName).pb.cc"
        } else {
            Write-Error "  ✗ Failed to generate code for $($protoFile.Name)"
        }
    } catch {
        Write-Error "  ✗ Error running protoc: $($_.Exception.Message)"
    }
}

# Generate a CMakeLists.txt for the generated files
$cmakeContent = @"
# Generated CMakeLists.txt for Protocol Buffer files
cmake_minimum_required(VERSION 3.8)

project(CoyoteProto)

# Find Protobuf
find_package(Protobuf REQUIRED)

# Collect all generated .cc files
file(GLOB PROTO_SOURCES "*.pb.cc")
file(GLOB PROTO_HEADERS "*.pb.h")

# Create library for protocol buffer files
if(PROTO_SOURCES)
    add_library(CoyoteProto STATIC `${PROTO_SOURCES})
    
    target_include_directories(CoyoteProto PUBLIC 
        `${CMAKE_CURRENT_SOURCE_DIR}
        `${Protobuf_INCLUDE_DIRS}
    )
    
    target_link_libraries(CoyoteProto `${Protobuf_LIBRARIES})
    
    # Set C++17 standard
    set_property(TARGET CoyoteProto PROPERTY CXX_STANDARD 17)
    
    # Export the library
    set_target_properties(CoyoteProto PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY `${CMAKE_BINARY_DIR}/lib
        LIBRARY_OUTPUT_DIRECTORY `${CMAKE_BINARY_DIR}/lib
    )
    
    message(STATUS "Created CoyoteProto library with `${CMAKE_CURRENT_SOURCE_DIR}")
else()
    message(WARNING "No Protocol Buffer source files found")
endif()
"@

$cmakeFile = Join-Path $OutputDir "CMakeLists.txt"
Set-Content -Path $cmakeFile -Value $cmakeContent
Write-Host "Generated CMakeLists.txt for Protocol Buffer files"

Write-Host ""
Write-Host "Protocol Buffer code generation completed!"
Write-Host "Generated files are in: $OutputDir"
Write-Host ""
Write-Host "To use in your project, add to your CMakeLists.txt:"
Write-Host "  add_subdirectory($OutputDir)"
Write-Host "  target_link_libraries(your_target CoyoteProto)"
