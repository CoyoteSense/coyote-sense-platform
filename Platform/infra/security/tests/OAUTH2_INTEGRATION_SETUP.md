# OAuth2 Integration Testing Setup

## Prerequisites

- **Docker Desktop** - Download from https://www.docker.com/products/docker-desktop/
- **.NET SDK** - For C# tests
- **Node.js** - For TypeScript tests
- **Visual Studio Build Tools** - For C++ tests (Windows)
- **GCC/Clang** - For C++ tests (Linux/Mac)

## Quick Setup

### 1. Start OAuth2 Server
```powershell
# PowerShell (Windows)
.\manage-oauth2-server.ps1 start

# Bash (Linux/Mac)
./manage-oauth2-server.sh start
```

### 2. Run Integration Tests
```powershell
# All languages
.\run_integration_tests.ps1

# Specific language
.\run_integration_tests.ps1 -Language cs    # C# only
.\run_integration_tests.ps1 -Language cpp   # C++ only
.\run_integration_tests.ps1 -Language ts    # TypeScript only
```

> **Note for C++ Integration Tests on Windows:**
>
> To run C++ integration tests, you **must** launch your terminal from a [Visual Studio Developer Command Prompt](https://learn.microsoft.com/en-us/cpp/build/building-on-the-command-line?view=msvc-170#developer_command_prompt) (or use `Developer PowerShell for VS`). This ensures the `cl.exe` compiler and all required environment variables are available. If you run from a standard PowerShell or Command Prompt, C++ tests will be skipped with a message about missing build tools or `cl.exe` not found.
>
> **How to open:**
> - Open the Start Menu, search for "Developer Command Prompt for VS" or "Developer PowerShell for VS" (matching your Visual Studio version), and launch it.
> - Navigate to your project directory and run the integration test commands as above.
>
> If you still see C++ tests being skipped, verify that `cl.exe` is available by running `cl` in your terminal. If not, ensure Visual Studio Build Tools are installed and you are using the correct environment.

### 3. Stop OAuth2 Server
```powershell
# PowerShell (Windows)
.\manage-oauth2-server.ps1 stop

# Bash (Linux/Mac)
./manage-oauth2-server.sh stop
```

## OAuth2 Server Details

- **URL**: http://localhost:8081
- **Client ID**: test-client-id
- **Client Secret**: test-client-secret
- **Supported Flows**: Client Credentials, Token Introspection
- **Discovery Endpoint**: http://localhost:8081/.well-known/oauth2

## Test Results Summary

### ✅ Integration Tests Status
- **C# Tests**: ✅ PASSED - All real OAuth2 integration tests working
- **C++ Tests**: ✅ PASSED - libcurl-based integration tests with vcpkg dependencies  
- **TypeScript Tests**: ✅ PASSED - All 11 integration tests (server connectivity, client credentials, token introspection, error handling, performance)

### ✅ Unit/Mock Tests Status  
- **C# Tests**: ✅ PASSED - 118 tests passed, 6 skipped (known hanging/concurrent tests)
- **C++ Tests**: ✅ PASSED - All unit tests with mock infrastructure
- **Python Tests**: ✅ PASSED - All validation tests
- **TypeScript Tests**: ✅ PASSED - Type checking and core functionality

## Troubleshooting

### OAuth2 Server Issues
```bash
# Check if server is running
curl http://localhost:8081/.well-known/oauth2

# View server logs
docker logs oauth2-server

# Restart server
.\manage-oauth2-server.ps1 restart
```

### Build Issues
```bash
# C++ build requirements
# Windows: Ensure Visual Studio Build Tools installed
# Linux: sudo apt install build-essential cmake libcurl4-openssl-dev

# TypeScript dependencies
cd ts && npm install

# C# dependencies  
cd dotnet && dotnet restore
```

### C# Integration Tests
- OAuth2 server connectivity
- Client credentials flow
- Token acquisition and validation
- Error handling scenarios

### C++ Integration Tests  
- libcurl-based HTTP client
- JSON response parsing
- Real server authentication
- Build system integration (CMake/vcpkg)

### TypeScript Integration Tests
- Server connectivity and discovery
- Client credentials with scopes
- Token introspection (valid/invalid tokens)
- Error handling and network failures
- Performance and concurrent requests (11 tests total)

## Troubleshooting

### Docker Issues
```bash
# Check if Docker is running
docker --version
docker ps

# Restart Docker if needed
docker-compose -f docker-compose.oauth2.yml down
docker-compose -f docker-compose.oauth2.yml up -d
```

### Build Issues (C++)
```bash
# Windows - Visual Studio not found
# Install Visual Studio Build Tools or Visual Studio Community

# Linux - Missing dependencies
sudo apt-get install build-essential cmake libcurl4-openssl-dev nlohmann-json3-dev

# Mac - Missing dependencies  
brew install cmake curl nlohmann-json
```

### Port Conflicts
If port 8081 is in use, modify `docker-compose.oauth2.yml`:
```yaml
ports:
  - "8082:8080"  # Use port 8082 instead
```

Then update the server URL in test scripts.

**Bash (Linux/Mac):**
```bash
# Run C# integration tests with real OAuth2 server
./run-csharp-integration-tests.sh
```

### OAuth2 Server Configuration

The OAuth2 Mock Server is configured with:

- **Server URL**: `http://localhost:8081`
- **Client ID**: `test-client-id`
- **Client Secret**: `test-client-secret`
- **Scopes**: `api.read`, `api.write`, `openid`, `profile`, `email`
- **Test User**: `testuser` / `testpass`

### Available Endpoints

- **Discovery**: `http://localhost:8081/.well-known/oauth2`
- **Token**: `http://localhost:8081/token`
- **Authorization**: `http://localhost:8081/auth`
- **Introspection**: `http://localhost:8081/introspect`
- **Revocation**: `http://localhost:8081/revoke`
- **UserInfo**: `http://localhost:8081/userinfo`

### Manual Testing

You can manually test the OAuth2 server:

```bash
# Get access token using client credentials
curl -X POST http://localhost:8081/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=test-client-id&client_secret=test-client-secret&scope=api.read api.write"
```

### Integration Test Features

The C# integration tests verify:

1. **Client Credentials Flow** - Basic OAuth2 authentication
2. **Token Introspection** - Verify token is valid and active
3. **Server Discovery** - Automatic endpoint discovery
4. **Token Revocation** - Properly revoke tokens
5. **Multiple Requests** - Concurrent token requests

### Troubleshooting

#### Docker Issues

If you get Docker errors:
1. Make sure Docker Desktop is running
2. Try restarting Docker Desktop
3. Check Docker version: `docker --version`

#### OAuth2 Server Issues

If the server doesn't start:
1. Check if port 8081 is available: `netstat -an | findstr 8081`
2. Try restarting: `.\manage-oauth2-server.ps1 restart`
3. Check logs: `docker logs oauth2-mock`

#### Test Failures

If integration tests fail:
1. Verify server is running: `.\manage-oauth2-server.ps1 status`
2. Test server manually: `.\manage-oauth2-server.ps1 test`
3. Check server logs: `docker logs oauth2-mock`

### Clean Up

To stop the OAuth2 server:

```powershell
# PowerShell
.\manage-oauth2-server.ps1 stop

# Bash
./manage-oauth2-server.sh stop
```

### Next Steps

Once the C# integration tests work, we can:

1. **Add Python Integration Tests** - Similar tests for Python client
2. **Add TypeScript Integration Tests** - Similar tests for TypeScript client
3. **Add More Complex Scenarios** - Authorization code flow, refresh tokens, etc.
4. **Performance Testing** - Load testing with multiple clients

The OAuth2 Mock Server supports all major OAuth2 flows and can be extended for more complex testing scenarios.
