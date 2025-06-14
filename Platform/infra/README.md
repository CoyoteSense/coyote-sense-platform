# HTTP and Security Components Analysis

## Project Overview

CoyoteSense is a **hybrid event-driven, actor-based platform focused on trading automation**. The platform leverages:

- **Event-Driven Architecture (EDA)** with Redis for low-latency event streaming
- **Actor-based concurrency** managed by Docker Compose or Kubernetes
- **Modular infrastructure components** providing foundational services
- **YAML-based CoyoteFlow configuration** for declarative business logic

## Infrastructure Components Structure

The platform follows a consistent organizational pattern for infrastructure components:

```
Platform/infra/<component>/
├── factory/                 # Factory implementations for creating instances
│   ├── cpp/
│   ├── dotnet/
│   ├── python/
│   └── ts/
├── interfaces/              # Interface definitions and types
│   ├── cpp/
│   ├── dotnet/
│   ├── python/
│   └── ts/
├── modes/                   # Runtime mode implementations
│   ├── debug/
│   ├── mock/
│   ├── real/
│   └── simulation/
└── [component-specific folders]
```

## HTTP Component Analysis

### Location: `Platform/infra/http/`

The HTTP component provides the foundational HTTP client infrastructure for the platform.

#### Structure:
```
Platform/infra/http/
├── build/                   # Build artifacts
├── build-scripts/           # Build automation scripts
├── examples/                # Usage examples
├── factory/                 # HTTP client factory implementations
│   ├── cpp/
│   ├── dotnet/
│   │   └── HttpClientFactory.cs
│   ├── python/
│   └── ts/
├── interfaces/              # HTTP client interfaces and implementations
│   ├── cpp/
│   ├── dotnet/
│   │   ├── BaseHttpClient.cs
│   │   ├── Configuration.cs
│   │   ├── Coyote.Infra.Http.csproj    # ✅ PROJECT FILE LOCATION
│   │   └── HttpClient.cs
│   ├── python/
│   └── ts/
├── modes/                   # Runtime mode implementations
├── tests/                   # Unit and integration tests
├── ts/                      # TypeScript specific implementations
├── vcpkg_installed/         # C++ dependencies
├── CMakeLists.txt          # C++ build configuration
├── README.md               # Component documentation
├── run-tests.ps1           # Test runner script
└── vcpkg.json              # C++ package management
```

#### Key Features:
- **Multi-language support**: C++, .NET, Python, TypeScript
- **Runtime modes**: Debug, Mock, Real, Simulation
- **Factory pattern**: Centralized client creation
- **Configuration-driven**: Flexible configuration system
- **Testing infrastructure**: Comprehensive test suite

#### .NET Implementation:
- **Project file**: `interfaces/dotnet/Coyote.Infra.Http.csproj`
- **Factory class**: `factory/dotnet/HttpClientFactory.cs`
- **Main interfaces**: `BaseHttpClient.cs`, `HttpClient.cs`
- **Configuration**: `Configuration.cs`

## Security Component Analysis

### Location: `Platform/infra/security/`

The Security component provides authentication, authorization, and secure secret management.

#### Structure:
```
Platform/infra/security/
├── clients/                 # Client implementations
├── examples/                # Usage examples
├── extensions/              # Security extensions
├── factory/                 # Security client factory implementations
│   ├── cpp/
│   ├── dotnet/
│   │   ├── AuthClientFactory.cs
│   │   └── SecureStoreClientFactory.cs
│   ├── py/
│   └── ts/
├── interfaces/              # Security interfaces and implementations
│   ├── cpp/
│   ├── dotnet/
│   │   ├── AuthInterfaces.cs
│   │   ├── Coyote.Infra.Security.csproj    # ✅ PROJECT FILE LOCATION
│   │   ├── IAuthClient.cs
│   │   └── ISecureStoreClient.cs
│   ├── python/
│   └── ts/
├── modes/                   # Runtime mode implementations
├── options/                 # Configuration options
├── security/                # Core security implementations
├── tests/                   # Security tests
└── README.md               # Component documentation
```

#### Key Features:
- **KeyVault Integration**: Secure secret management
- **Authentication Methods**: 
  - mTLS (mutual TLS)
  - Unit Role-based authentication
  - Service Principal authentication
  - Kubernetes JWT authentication
- **Token Management**: Automatic token refresh and lifecycle management
- **Security Patterns**: 
  - No local persistence of secrets
  - On-demand HTTPS fetch
  - Short-lived tokens with tight TTL
  - TLS/mTLS everywhere
- **Options Pattern**: Strongly-typed configuration with validation

#### .NET Implementation:
- **Project file**: `interfaces/dotnet/Coyote.Infra.Security.csproj`
- **Factory classes**: 
  - `factory/dotnet/AuthClientFactory.cs`
  - `factory/dotnet/SecureStoreClientFactory.cs`
- **Interface definitions**:
  - `IAuthClient.cs`
  - `ISecureStoreClient.cs`
  - `AuthInterfaces.cs`

## Project File Location Analysis

### Current Structure ✅ CORRECT

Both HTTP and Security components follow the **same organizational pattern**:

```
Platform/infra/<component>/interfaces/dotnet/<Component>.csproj
```

**HTTP Component:**
- `Platform/infra/http/interfaces/dotnet/Coyote.Infra.Http.csproj`

**Security Component:**
- `Platform/infra/security/interfaces/dotnet/Coyote.Infra.Security.csproj`

### Why This Structure Makes Sense:

1. **Consistency**: Both components follow identical patterns
2. **Logical Grouping**: Interfaces folder contains the main API contracts and implementations
3. **Language Isolation**: Each language has its own subfolder with build artifacts
4. **Dependency Management**: Project files are close to their dependent source files
5. **Build Separation**: Each component can be built independently

### Alternative Structures Considered:

❌ **Root Level**: `Platform/infra/security/Coyote.Infra.Security.csproj`
- **Problem**: Mixes build artifacts with source organization
- **Issue**: Doesn't follow established HTTP component pattern

❌ **Factory Level**: `Platform/infra/security/factory/dotnet/Coyote.Infra.Security.csproj`
- **Problem**: Factory is for implementation, not the main project
- **Issue**: Separates project file from main interfaces

❌ **Separate Projects Folder**: `Platform/infra/security/projects/dotnet/Coyote.Infra.Security.csproj`
- **Problem**: Creates unnecessary nesting
- **Issue**: Inconsistent with established HTTP pattern

## Security Architecture Highlights

### 1. Authentication Flow
```
Unit → AuthClient → KeyVault → Bearer Token → Secret Access
```

### 2. Supported Authentication Methods
- **Unit Role**: Role-based authentication with unit identity
- **mTLS**: Mutual TLS certificate-based authentication
- **Service Principal**: Client ID/Secret based authentication
- **Kubernetes JWT**: Service account JWT authentication

### 3. Token Management
- **Short-lived tokens** (5-15 minutes TTL)
- **Automatic refresh** with retry logic
- **Memory-only storage** (no disk persistence)
- **Secure disposal** on process exit

### 4. Security Patterns
- **Zero-trust architecture**
- **Least privilege access**
- **Comprehensive audit logging**
- **Fail-safe operations**

## HTTP Infrastructure Highlights

### 1. Multi-Mode Support
- **Real Mode**: Production HTTP operations
- **Mock Mode**: Testing with simulated responses
- **Debug Mode**: Enhanced logging and debugging
- **Simulation Mode**: Replay and testing scenarios

### 2. Configuration Management
- **Centralized configuration**
- **Environment-specific settings**
- **Runtime mode switching**
- **Validation and defaults**

### 3. Factory Pattern Benefits
- **Consistent client creation**
- **Mode-specific implementations**
- **Configuration injection**
- **Lifecycle management**

## Recommendations

### 1. Current Structure ✅
The current placement of `Coyote.Infra.Security.csproj` in `Platform/infra/security/interfaces/dotnet/` is **correct and consistent** with the established HTTP component pattern.

### 2. Consistency Maintenance
- Ensure all infrastructure components follow the same pattern
- Document the organizational principles clearly
- Maintain language folder standardization

### 3. Build Integration
- Consider creating solution files at the component level
- Implement consistent build scripts across components
- Establish dependency management patterns

### 4. Testing Strategy
- Align security testing with HTTP component testing patterns
- Implement comprehensive integration tests
- Establish security-specific test scenarios

## Conclusion

The CoyoteSense platform demonstrates a well-structured approach to infrastructure component organization. The HTTP and Security components both follow consistent patterns that promote:

- **Maintainability**: Clear separation of concerns
- **Scalability**: Modular architecture supports growth
- **Consistency**: Standardized patterns across components
- **Multi-language support**: Consistent organization across languages

The current location of the `Coyote.Infra.Security.csproj` file is appropriate and follows established conventions.

# Infra Folder Refactor Guide

## Goal
Refactor the `Platform/infra` directory so that every infrastructure **unit** follows a predictable, polyglot skeleton and can be built & **tested** in isolation.

---

## Current Infrastructure Units Discovery

Based on analysis of `Platform/infra/`, the following infrastructure units have been identified:

| Unit | Current Structure | Languages | Has Tests | Notes |
|------|-------------------|-----------|-----------|-------|
| **broker** | `broker/redis/` | All | ❓ | Redis broker implementation |
| **cfg** | `cfg/` | cpp, dotnet, python, ts | ❓ | Configuration management |
| **http** | `http/` | cpp, dotnet, python, ts | ✅ | HTTP client infrastructure |
| **log** | `log/` | cpp, dotnet, python, ts | ❓ | Logging infrastructure |
| **msg** | `msg/` | cpp, dotnet, python, ts | ❓ | Messaging infrastructure |
| **security** | `security/` | cpp, dotnet, python, ts | ✅ | Authentication & secrets |
| **ws** | `ws/` | cpp, dotnet, python, ts | ❓ | WebSocket infrastructure |

### Current Structure Pattern
```
Platform/infra/<unit>/
├── factory/
│   ├── cpp/
│   ├── dotnet/
│   ├── python/  (or py/)
│   └── ts/
├── interfaces/
│   ├── cpp/
│   ├── dotnet/           # Contains .csproj files
│   ├── python/
│   └── ts/
├── modes/
└── [unit-specific folders]
```

---

## Target Directory Template

```text
Platform/infra/<unit>/
├── modes/
│   ├── real/            # docker-compose.yml, .env.example …
│   ├── mock/
│   └── debug/
└── src/
    ├── cpp/
    │   ├── include/<unit>/interfaces/…
    │   ├── src/impl/real/…
    │   ├── src/impl/mock/…
    │   ├── src/impl/debug/…
    │   ├── factory/…         # picks impl by MODE env var
    │   └── CMakeLists.txt
    ├── dotnet/
    │   ├── interfaces/…
    │   ├── impl/real/…
    │   ├── impl/mock/…
    │   ├── impl/debug/…
    │   ├── factory/
    │   └── Coyote.Infra.<Unit>.csproj
    ├── python/
    │   ├── <unit>/interfaces.py
    │   ├── <unit>/impl/real.py
    │   ├── <unit>/impl/mock.py
    │   ├── <unit>/impl/debug.py
    │   ├── <unit>/factory.py
    │   └── pyproject.toml
    └── ts/
        └── …mirror same pattern…
```

*Everything that compiles lives in **`src/<lang>/…`**; configuration‑only artefacts live in **`modes/…`**.*

---

## Detailed Migration Plan

### Phase 1: Structure Preparation

#### 1.1 Create Target Directories
For each infrastructure unit, create the new directory structure:

```powershell
# Create target structure for each unit
$units = @('broker', 'cfg', 'http', 'log', 'msg', 'security', 'ws')
foreach ($unit in $units) {
    # Create main structure
    New-Item -Path "Platform/infra/$unit/src" -ItemType Directory -Force
    New-Item -Path "Platform/infra/$unit/modes/real" -ItemType Directory -Force
    New-Item -Path "Platform/infra/$unit/modes/mock" -ItemType Directory -Force
    New-Item -Path "Platform/infra/$unit/modes/debug" -ItemType Directory -Force
    
    # Create language-specific source directories
    foreach ($lang in @('cpp', 'dotnet', 'python', 'ts')) {
        New-Item -Path "Platform/infra/$unit/src/$lang/interfaces" -ItemType Directory -Force
        New-Item -Path "Platform/infra/$unit/src/$lang/impl/real" -ItemType Directory -Force
        New-Item -Path "Platform/infra/$unit/src/$lang/impl/mock" -ItemType Directory -Force
        New-Item -Path "Platform/infra/$unit/src/$lang/impl/debug" -ItemType Directory -Force
        New-Item -Path "Platform/infra/$unit/src/$lang/factory" -ItemType Directory -Force
    }
}
```

#### 1.2 Special Handling for Broker Unit
The broker unit has a nested structure (`broker/redis/`). Flatten it to `broker/`:

```powershell
# Move broker/redis/* to broker/
Move-Item "Platform/infra/broker/redis/*" "Platform/infra/broker/" -Force
Remove-Item "Platform/infra/broker/redis" -Recurse -Force
```

### Phase 2: File Migration

#### 2.1 Move Interface Files
```powershell
# For each unit, move interface files
$units = @('broker', 'cfg', 'http', 'log', 'msg', 'security', 'ws')
foreach ($unit in $units) {
    foreach ($lang in @('cpp', 'dotnet', 'python', 'ts')) {
        if (Test-Path "Platform/infra/$unit/interfaces/$lang") {
            Move-Item "Platform/infra/$unit/interfaces/$lang/*" "Platform/infra/$unit/src/$lang/interfaces/" -Force
        }
    }
}
```

#### 2.2 Move Factory Files
```powershell
# Move factory implementations
foreach ($unit in $units) {
    foreach ($lang in @('cpp', 'dotnet', 'python', 'ts')) {
        if (Test-Path "Platform/infra/$unit/factory/$lang") {
            Move-Item "Platform/infra/$unit/factory/$lang/*" "Platform/infra/$unit/src/$lang/factory/" -Force
        }
    }
}
```

#### 2.3 Move Mode Configurations
```powershell
# Move existing mode configurations if they exist
foreach ($unit in $units) {
    if (Test-Path "Platform/infra/$unit/modes") {
        # Move mode-specific configs to new structure
        Get-ChildItem "Platform/infra/$unit/modes" | ForEach-Object {
            if ($_.Name -in @('real', 'mock', 'debug')) {
                Move-Item $_.FullName "Platform/infra/$unit/modes/" -Force
            }
        }
    }
}
```

### Phase 3: Project File Updates

#### 3.1 .NET Project Files
Update each `Coyote.Infra.<Unit>.csproj` file:

```xml
<!-- Update file paths in .csproj files -->
<ItemGroup>
  <Compile Include="interfaces\**\*.cs" />
  <Compile Include="impl\**\*.cs" />
  <Compile Include="factory\**\*.cs" />
</ItemGroup>
```

#### 3.2 C++ CMakeLists.txt
```cmake
# Update CMakeLists.txt for new structure
set(UNIT_NAME "http")  # Replace with actual unit name

# Include directories
target_include_directories(coyote_infra_${UNIT_NAME} 
    PUBLIC include/${UNIT_NAME}/interfaces
    PRIVATE src/impl
)

# Source files
file(GLOB_RECURSE SOURCES
    "src/impl/**/*.cpp"
    "factory/*.cpp"
)

target_sources(coyote_infra_${UNIT_NAME} PRIVATE ${SOURCES})
```

#### 3.3 Python pyproject.toml
```toml
[build-system]
requires = ["setuptools>=45", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "coyote-infra-{unit}"
version = "0.1.0"
description = "CoyoteSense {Unit} Infrastructure Component"

[tool.setuptools.packages.find]
where = [""]
include = ["{unit}*"]

[tool.setuptools.package-dir]
"{unit}" = "{unit}"
```

### Phase 4: Test Migration

#### 4.1 Create Test Structure
```powershell
# Create test directories
foreach ($unit in $units) {
    foreach ($lang in @('cpp', 'dotnet', 'python', 'ts')) {
        New-Item -Path "Platform/infra/$unit/tests/$lang" -ItemType Directory -Force
    }
}
```

#### 4.2 Move Existing Tests
```powershell
# Move existing test files (if they exist)
foreach ($unit in $units) {
    if (Test-Path "Platform/infra/$unit/tests") {
        # Organize by language
        Get-ChildItem "Platform/infra/$unit/tests" -Recurse -File | ForEach-Object {
            $lang = switch ($_.Extension) {
                '.cs' { 'dotnet' }
                '.cpp' { 'cpp' }
                '.h' { 'cpp' }
                '.py' { 'python' }
                '.ts' { 'ts' }
                '.js' { 'ts' }
                default { 'misc' }
            }
            
            if ($lang -ne 'misc') {
                $targetDir = "Platform/infra/$unit/tests/$lang"
                Move-Item $_.FullName $targetDir -Force
            }
        }
    }
}
```

### Phase 5: Build Script Updates

#### 5.1 Update Build Scripts
Create or update build scripts to handle new structure:

```powershell
# build-infra.ps1
param(
    [string]$Unit = "",
    [string]$Language = "",
    [string]$Mode = "real"
)

$units = @('broker', 'cfg', 'http', 'log', 'msg', 'security', 'ws')
$languages = @('cpp', 'dotnet', 'python', 'ts')

if ($Unit -and $Language) {
    # Build specific unit/language combination
    Build-InfraComponent -Unit $Unit -Language $Language -Mode $Mode
} elseif ($Unit) {
    # Build all languages for specific unit
    foreach ($lang in $languages) {
        Build-InfraComponent -Unit $Unit -Language $lang -Mode $Mode
    }
} else {
    # Build all units and languages
    foreach ($unit in $units) {
        foreach ($lang in $languages) {
            Build-InfraComponent -Unit $unit -Language $lang -Mode $Mode
        }
    }
}

function Build-InfraComponent {
    param($Unit, $Language, $Mode)
    
    $srcPath = "Platform/infra/$Unit/src/$Language"
    if (-not (Test-Path $srcPath)) {
        Write-Warning "No $Language source found for $Unit unit"
        return
    }
    
    Set-Location $srcPath
    $env:MODE = $Mode
    
    switch ($Language) {
        'dotnet' {
            dotnet build
            dotnet test
        }
        'cpp' {
            cmake -B build -S .
            cmake --build build
            ctest --test-dir build
        }
        'python' {
            pip install -e .
            pytest
        }
        'ts' {
            npm install
            npm run build
            npm test
        }
    }
}
```

### Phase 6: Documentation Updates

#### 6.1 Create Unit README Files
For each unit, create a comprehensive README:

```markdown
# {Unit} Infrastructure Component

## Overview
Brief description of the {unit} component's purpose and capabilities.

## Architecture
Description of the component architecture and key interfaces.

## Supported Languages
- C++ (CMake build)
- .NET (dotnet build)  
- Python (pip install)
- TypeScript (npm build)

## Runtime Modes
- **Real**: Production implementation
- **Mock**: Testing with simulated behavior
- **Debug**: Enhanced logging and debugging

## Building

### All Languages
```bash
# From component root
./build.ps1
```

### Specific Language
```bash
# .NET
cd src/dotnet && dotnet build

# C++
cd src/cpp && cmake -B build && cmake --build build

# Python  
cd src/python && pip install -e .

# TypeScript
cd src/ts && npm install && npm run build
```

## Testing
```bash
# Run all tests
./test.ps1

# Language-specific tests
cd src/dotnet && dotnet test
cd src/cpp && ctest --test-dir build
cd src/python && pytest
cd src/ts && npm test
```

## Configuration
Runtime mode is controlled via the `MODE` environment variable:
```bash
export MODE=real    # or mock, debug
```

Mode-specific configurations are in `modes/{mode}/` directories.
```

### Phase 7: Cleanup

#### 7.1 Remove Old Directories
```powershell
# Remove old structure after successful migration
foreach ($unit in $units) {
    Remove-Item "Platform/infra/$unit/factory" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "Platform/infra/$unit/interfaces" -Recurse -Force -ErrorAction SilentlyContinue
}
```

---

## Naming Conventions

| Artifact        | Pattern                      | Example                        |
|-----------------|------------------------------|--------------------------------|
| Unit folder     | `kebab-case`                 | `http`                         |
| .NET project    | `Coyote.Infra.<Unit>`        | `Coyote.Infra.Http`            |
| Python package  | `coyote_infra_<unit>`        | `coyote_infra_http`            |
| C++ target      | `coyote_infra_<unit>`        | `coyote_infra_http`            |
| NPM scope       | `@coyote/infra-<unit>`       | `@coyote/infra-http`           |
| Docker image    | `coyote/infra-<unit>-<lang>` | `coyote/infra-http-py`         |

---

## Migration Verification Checklist

### Pre-Migration
- [ ] Backup current `Platform/infra` directory
- [ ] Document current build/test procedures
- [ ] Identify all existing dependencies and references

### Per Unit Migration
- [ ] Create new directory structure
- [ ] Move source files to appropriate locations
- [ ] Update project files (.csproj, CMakeLists.txt, pyproject.toml, package.json)
- [ ] Move and organize test files
- [ ] Update import/include statements
- [ ] Create unit README.md
- [ ] Test build process: `dotnet build`, `cmake --build`, `pip install`, `npm run build`
- [ ] Test execution: `dotnet test`, `ctest`, `pytest`, `npm test`

### Post-Migration
- [ ] Update CI/CD pipeline configurations
- [ ] Update Docker build contexts
- [ ] Update documentation references
- [ ] Remove old directory structure
- [ ] Verify end-to-end integration

---

## Commit Message Template

```text
refactor(infra): reorganise infra units into unified polyglot layout

* move source to infra/<unit>/src/<lang>/
* add per-mode config folders under infra/<unit>/modes/
* update project references (.csproj, CMakeLists, pyproject, tsconfig)
* migrate tests; ensure `dotnet test`, `pytest`, `ctest`, and `npm test` all pass

BREAKING CHANGE: Infrastructure component paths have changed
- Interfaces moved from infra/<unit>/interfaces/<lang>/ to infra/<unit>/src/<lang>/interfaces/
- Factories moved from infra/<unit>/factory/<lang>/ to infra/<unit>/src/<lang>/factory/
- Project files relocated to src/<lang>/ directories
- Import/include paths updated across all languages
```

---

## After the Merge

Run the top‑level task runner:

```bash
just build-all          # or `make`, `task`, etc.
just test-all
```

Both commands must finish without errors to confirm that every **infra unit**—and its **tests**—build successfully in their new home.

---

## Risk Mitigation

### High-Risk Items
1. **Project References**: .csproj, CMakeLists.txt path updates
2. **Import Statements**: Python imports, C++ includes, TypeScript imports
3. **CI/CD Pipelines**: Build script path patterns
4. **Docker Contexts**: Dockerfile COPY commands

### Mitigation Strategies
1. **Staged Migration**: Migrate one unit at a time
2. **Automated Testing**: Run full test suite after each unit migration
3. **Rollback Plan**: Keep backup of working state
4. **Parallel Development**: Create migration branch, test thoroughly before merge

### Testing Strategy
1. **Unit Tests**: Must pass for each language in each unit
2. **Integration Tests**: Cross-unit communication must work
3. **Build Tests**: All build scripts must execute successfully
4. **Deployment Tests**: Docker builds and deployments must work

---
