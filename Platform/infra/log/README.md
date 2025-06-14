# Log Infrastructure Component

## Overview
The Log component provides [brief description of component purpose and capabilities].

## Architecture
[Description of the component architecture and key interfaces]

## Supported Languages
- **C++** (CMake build)
- **.NET** (dotnet build)  
- **Python** (pip install)
- **TypeScript** (npm build)

## Runtime Modes
- **Real**: Production implementation with actual external dependencies
- **Mock**: Testing implementation with simulated behavior
- **Debug**: Enhanced logging and debugging capabilities

## Building

### All Languages
```powershell
# From component root
.\build.ps1
```

### Language-Specific Builds

#### .NET
```bash
cd src/dotnet
dotnet build
dotnet run
```

#### C++
```bash
cd src/cpp
cmake -B build -S .
cmake --build build
./build/coyote_infra_log
```

#### Python
```bash
cd src/python
pip install -e .
python -m coyote_infra_log
```

#### TypeScript
```bash
cd src/ts
npm install
npm run build
npm start
```

## Testing

### All Tests
```powershell
.\test.ps1
```

### Language-Specific Tests
```bash
# .NET
cd src/dotnet && dotnet test

# C++
cd src/cpp && ctest --test-dir build

# Python  
cd src/python && pytest

# TypeScript
cd src/ts && npm test
```

## Configuration

Runtime mode is controlled via the MODE environment variable:
```bash
export MODE=real    # or mock, debug
```

Mode-specific configurations are stored in:
- modes/real/ - Production configuration
- modes/mock/ - Testing configuration  
- modes/debug/ - Debug configuration

## Docker Support

Build Docker images for each language:
```bash
# Build all language images
docker-compose -f modes/real/docker-compose.yml build

# Build specific language
docker build -f src/dotnet/Dockerfile -t coyote/infra-log-dotnet .
```

## API Reference

[Link to detailed API documentation]

## Examples

See the modes/ directory for configuration examples and the language-specific src/ directories for implementation examples.

## Contributing

1. Follow the established patterns in other infrastructure components
2. Ensure all tests pass across all supported languages
3. Update this README with any new features or changes
4. Test in all three runtime modes (real, mock, debug)
