# CoyoteSense HTTP Component Test Suite

This directory contains comprehensive tests for the CoyoteSense HTTP component across multiple programming languages: C#, Python, TypeScript, and C++.

## Quick Start

Run all unit tests:
```powershell
.\run-all-tests.ps1
```

Run tests for a specific language:
```powershell
.\run-all-tests.ps1 -Language python
```

Include C++ integration tests (requires Docker):
```powershell
.\run-all-tests.ps1 -IncludeIntegration
```

## Test Structure

```
tests/
├── run-all-tests.ps1           # Unified test runner
├── dotnet/                     # C# tests (30 unit tests)
├── python/                     # Python tests (27 tests)
├── ts/                         # TypeScript tests (138 tests)
├── cpp/                        # C++ tests (28 unit tests)
└── integration/                # C++ Docker integration tests
```

## Test Runner Features

### Language Support
- **C# (.NET)**: Unit tests with integration tests excluded by default
- **Python**: pytest-based tests with comprehensive mocking
- **TypeScript**: Jest-based tests with extensive coverage
- **C++**: GoogleTest-based unit tests with optional Docker integration tests

### Command Line Options
- `-Language <lang>`: Run tests for specific language (csharp, python, typescript, cpp, all)
- `-IncludeIntegration`: Enable C++ Docker-based integration tests
- `-Help`: Show detailed usage information

### Test Counts
- **Total Unit Tests**: 223 tests across all languages
- **C#**: 30 unit tests (integration tests excluded)
- **Python**: 27 tests
- **TypeScript**: 138 tests  
- **C++**: 28 unit tests

## Prerequisites

### Common Requirements
- Windows with PowerShell
- Git (for repository access)

### Language-Specific Requirements

#### C# (.NET)
- .NET SDK 6.0 or later
- No additional setup required

#### Python
- Python 3.7 or later
- pytest and other dependencies (installed automatically)

#### TypeScript
- Node.js 16 or later
- npm (comes with Node.js)
- Dependencies installed via `npm install`

#### C++
- CMake 3.20 or later
- vcpkg (set VCPKG_ROOT environment variable)
- Visual Studio 2019 or later with C++ support
- Library must be built first: `cmake --build build --config Release`

#### C++ Integration Tests (Optional)
- Docker Desktop
- Docker Compose

## Build Requirements

### C++ Library Build
The C++ tests require the library to be built first. From the main HTTP directory:

```powershell
# First time setup
cmake -B build -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"

# Build the library and tests
cmake --build build --config Release
```

## Test Execution Details

### Unit Tests (Default)
- **C#**: Excludes `RealHttpClientIntegrationTests` that require network connectivity
- **Python**: All tests run (mocked dependencies)
- **TypeScript**: All tests run (mocked dependencies) 
- **C++**: Unit tests only, excludes integration tests requiring test server

### Integration Tests (Optional)
- **C++**: Docker-based tests that start a real HTTP test server
- **C#/TypeScript**: Integration tests excluded from default run to avoid network failures

## Error Handling

The test runner provides:
- Clear error messages for missing dependencies
- Graceful handling of missing test directories
- Detailed failure reporting
- Summary of results across all languages

## CI/CD Integration

The unified test runner is designed for:
- Local development testing
- Continuous Integration pipelines
- Automated testing in Docker environments
- Cross-platform compatibility (Windows focus)

## Troubleshooting

### Common Issues

1. **C++ tests not found**: Ensure the library is built first
2. **VCPKG_ROOT not set**: Set environment variable pointing to vcpkg installation
3. **Docker tests fail**: Ensure Docker Desktop is running and docker-compose is available
4. **Python tests fail**: Check Python installation and pytest availability
5. **TypeScript build fails**: Run `npm install` in the ts directory first

### Debug Mode

For detailed debugging, examine individual test output:
- C#: `dotnet test --verbosity diagnostic`
- Python: `python -m pytest -v -s`
- TypeScript: `npm test -- --verbose`
- C++: `ctest --output-on-failure --verbose`

## Contributing

When adding new tests:
1. Follow the existing test structure for your language
2. Update test counts in `run-all-tests.ps1` 
3. Ensure tests are self-contained and don't require external services
4. Add integration tests to the appropriate integration directory
5. Update this README with any new requirements

## Test Quality Standards

All tests should:
- Run reliably in isolation
- Use proper mocking for external dependencies
- Include both positive and negative test cases
- Follow language-specific testing best practices
- Complete within reasonable time limits (< 60 seconds per language)
