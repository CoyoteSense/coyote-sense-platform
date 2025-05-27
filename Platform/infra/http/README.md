# Coyote HTTP Client Infrastructure

This directory contains the HTTP client infrastructure for the Coyote platform, implemented using a hybrid architecture that provides both language-agnostic organization and language-specific implementations.

## Architecture Overview

The infrastructure uses a **hybrid directory structure** that balances logical organization with language-specific needs:

```
http/
├── interfaces/           # HTTP client interfaces
│   ├── cpp/             # C++ interface headers
│   └── python/          # Python interface modules
├── factory/             # Factory pattern implementations  
│   ├── cpp/             # C++ factory headers
│   └── python/          # Python factory modules
├── modes/               # Runtime mode implementations
│   ├── real/            # Production HTTP clients
│   │   ├── cpp/         # C++ real client
│   │   └── python/      # Python real client
│   └── mock/            # Testing/simulation clients
│       ├── cpp/         # C++ mock client  
│       └── python/      # Python mock client
├── examples/            # Usage examples
│   ├── cpp/             # C++ examples
│   └── python/          # Python examples  
├── tests/               # Test suites
│   ├── cpp/             # C++ unit tests
│   └── python/          # Python unit tests
└── build-scripts/       # Language-specific build systems
    ├── common/          # Cross-language build automation
    ├── cpp/             # C++ CMake configuration
    └── python/          # Python packaging & tools
```

## Key Features

- **Language-agnostic interfaces**: Common HTTP client contract across C++ and Python
- **Factory pattern**: Runtime mode selection (production vs testing)
- **Mock clients**: Full-featured simulation for testing
- **Unified build system**: Single command builds all languages
- **Comprehensive testing**: Unit tests for all components

## Quick Start

### Build All Languages
```powershell
.\build-scripts\common\build-all.ps1
```

### Build Specific Language with Tests
```powershell
# C++ only
.\build-scripts\common\build-all.ps1 -Language cpp -Tests

# Python only  
.\build-scripts\common\build-all.ps1 -Language python -Tests
```

### Development Build (Python)
```powershell
.\build-scripts\common\build-all.ps1 -Language python -Dev -Tests -Coverage
```

## Runtime Modes

The HTTP client supports multiple runtime modes:

- **Production**: Real HTTP requests to actual endpoints
- **Testing**: Mock responses for unit testing  
- **Simulation**: Configurable mock behavior for integration testing

Mode selection via environment variables:
```bash
# Use mock client for testing
export COYOTE_RUNTIME_MODE=testing

# Use real client for production  
export COYOTE_RUNTIME_MODE=production
```

## Language-Specific Details

### C++ Components
- **CMake-based build system** with vcpkg integration
- **Modern C++17** features and best practices
- **Header-only interfaces** for easy integration
- **Google Test** for unit testing

### Python Components  
- **Modern packaging** with pyproject.toml
- **Type hints** throughout codebase
- **pytest** for testing with coverage support
- **Development tools**: linting, formatting, type checking

## Directory Structure Benefits

This hybrid approach provides:

1. **Logical Organization**: Easy to find interfaces, factories, modes
2. **Language Separation**: Clean separation of C++ and Python code  
3. **Shared Concepts**: Common patterns across languages
4. **Scalability**: Easy to add new languages or components
5. **Build Isolation**: Language-specific build systems don't interfere

## Recent Changes

### Completed Infrastructure Reorganization (May 2025)
- ✅ **Hybrid Architecture**: Implemented logical organization with language-specific subdirectories
- ✅ **Consolidated Tests**: Unified test directory structure (`tests/cpp/`, `tests/python/`)
- ✅ **Build Automation**: Cross-language build scripts with PowerShell automation
- ✅ **Python Packaging**: Modern pyproject.toml configuration with development tools
- ✅ **Clean Structure**: Removed duplicate/obsolete files and directories
- ✅ **Comprehensive .gitignore**: Excludes build artifacts and cache files
- ✅ **Updated Documentation**: Reflects new hybrid architecture

### Test Suite Status
- **C++ Tests**: CMake integration (pending Visual Studio setup)
- **Python Tests**: 27/27 tests passing with full coverage
- **Build Scripts**: Functional for both languages with error handling

The reorganization successfully created a maintainable, scalable codebase that supports both current languages and future expansion.

## Contributing

When adding new components:

1. **Follow the hybrid pattern**: Add language subdirectories under logical categories
2. **Maintain interface consistency**: Ensure C++ and Python interfaces match
3. **Add comprehensive tests**: Both unit tests and integration examples
4. **Update build scripts**: Add new components to language-specific builds
5. **Document changes**: Update this README and inline documentation

## Build System Details

### Master Build Script
Located at `build-scripts/common/build-all.ps1`, supports:
- Single command for all languages
- Language-specific builds  
- Development workflows
- Testing and coverage
- Clean builds

### Language-Specific Scripts
- **C++**: `build-scripts/cpp/build.ps1` - CMake configuration
- **Python**: `build-scripts/python/build.ps1` - pip/setuptools integration

For detailed build options, run:
```powershell
.\build-scripts\common\build-all.ps1 -Help
```
