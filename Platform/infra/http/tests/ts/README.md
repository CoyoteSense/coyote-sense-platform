# CoyoteSense HTTP Client

A comprehensive TypeScript HTTP client library with multiple operation modes for production, testing, debugging, and simulation scenarios.

## Features

- **Multiple Operation Modes**: Real, Mock, Debug, Record, Replay, and Simulation
- **TypeScript Native**: Full TypeScript support with type safety
- **Dependency Injection**: Built-in DI container for easy testing and configuration
- **Environment-based Configuration**: Automatic mode detection via environment variables
- **Comprehensive Testing**: Full test coverage with Jest
- **Production Ready**: Built with reliability and performance in mind

## Installation

```bash
npm install @coyote-sense/http-client
```

## Quick Start

```typescript
import { createClient, RuntimeMode } from '@coyote-sense/http-client';

// Create a client for the current environment
const client = createClient();

// Or specify a mode explicitly
const mockClient = createClient(RuntimeMode.TESTING);

// Make requests
const response = await client.getAsync('https://api.example.com/users');
console.log(response.body);
```

## Operation Modes

### Real Mode (Production)

Uses Node.js native fetch for actual HTTP requests.

```typescript
import { RealHttpClient } from '@coyote-sense/http-client';

const client = new RealHttpClient({
  baseUrl: 'https://api.example.com',
  timeout: 5000,
  defaultHeaders: {
    'Authorization': 'Bearer token',
    'Content-Type': 'application/json'
  },
  retryAttempts: 3
});

const response = await client.getAsync('/users');
```

### Mock Mode (Testing)

Provides configurable mock responses for testing.

```typescript
import { MockHttpClient } from '@coyote-sense/http-client';

const client = new MockHttpClient({
  defaultStatusCode: 200,
  defaultBody: '{"test": "data"}',
  defaultHeaders: { 'Content-Type': 'application/json' }
});

// Set up specific responses
client.setPredefinedResponse('https://api.example.com/users', 200, 
  JSON.stringify([{ id: 1, name: 'John' }]));

const response = await client.getAsync('https://api.example.com/users');
```

### Debug Mode (Development)

Wraps any HTTP client with enhanced logging and debugging capabilities.

```typescript
import { DebugHttpClient, RealHttpClient } from '@coyote-sense/http-client';

const realClient = new RealHttpClient();
const debugClient = new DebugHttpClient(realClient, {
  logRequests: true,
  logResponses: true,
  logHeaders: true,
  logTiming: true
});

const response = await debugClient.getAsync('https://api.example.com/users');
// Logs detailed request/response information
```

### Record Mode (Capture)

Records all HTTP requests and responses for later replay.

```typescript
import { RecordHttpClient, RealHttpClient } from '@coyote-sense/http-client';

const realClient = new RealHttpClient();
const recordClient = new RecordHttpClient(realClient, {
  recordingDirectory: './recordings',
  filenameTemplate: 'recording_{timestamp}_{method}_{url}.json'
});

const response = await recordClient.getAsync('https://api.example.com/users');
// Saves request/response to file
```

### Replay Mode (Playback)

Replays previously recorded HTTP interactions.

```typescript
import { ReplayHttpClient } from '@coyote-sense/http-client';

const client = new ReplayHttpClient({
  recordingDirectory: './recordings',
  strictMatching: false,
  fallbackResponse: {
    statusCode: 404,
    body: 'Recording not found',
    headers: {}
  }
});

const response = await client.getAsync('https://api.example.com/users');
// Returns recorded response if available
```

### Simulation Mode (Testing & Development)

Simulates various response patterns and behaviors.

```typescript
import { SimulationHttpClient } from '@coyote-sense/http-client';

const client = new SimulationHttpClient({
  scenarioFile: './scenarios.json',
  globalLatencyMs: 100,
  globalFailureRate: 0.05 // 5% failure rate
});

// Add custom scenarios
client.addScenario({
  name: 'API Success',
  pattern: '/api/*',
  statusCode: 200,
  body: '{"success": true}',
  latencyMs: 50
});

const response = await client.getAsync('https://api.example.com/api/test');
```

## Environment-based Configuration

The library automatically detects the operation mode based on environment variables:

```bash
# Set mode via environment variable
export COYOTE_RUNTIME_MODE=testing
export MODE=production
export NODE_ENV=development
```

Priority order:
1. `COYOTE_RUNTIME_MODE`
2. `MODE`
3. `NODE_ENV` (development → testing, production → real)
4. Default: `real`

## Dependency Injection

Use the built-in container for easy testing and configuration:

```typescript
import { createHttpClientContainer } from '@coyote-sense/http-client';

// Create container with configuration
const container = createHttpClientContainer({
  mode: {
    mode: RuntimeMode.TESTING,
    mock: {
      defaultStatusCode: 200,
      defaultBody: '{"test": true}'
    }
  }
});

// Get client from container
const client = container.resolve('httpClient');
```

## Configuration

### Global Configuration

```typescript
interface HttpClientConfig {
  mode: HttpClientModeConfig;
  logging: LoggingConfig;
}

interface HttpClientModeConfig {
  mode: RuntimeMode;
  real?: RealHttpConfig;
  mock?: MockHttpConfig;
  debug?: DebugHttpConfig;
  record?: RecordHttpConfig;
  replay?: ReplayHttpConfig;
  simulation?: SimulationHttpConfig;
}
```

### Mode-specific Configuration

Each mode has its own configuration interface:

- `RealHttpConfig`: timeout, retries, base URL, headers
- `MockHttpConfig`: default responses, latency simulation
- `DebugHttpConfig`: logging levels and options
- `RecordHttpConfig`: recording directory and file templates
- `ReplayHttpConfig`: replay directory and fallback behavior
- `SimulationHttpConfig`: scenarios, failure rates, latency

## Testing

The library includes comprehensive test suites for all modes:

```bash
# Run all tests
npm test

# Run with coverage
npm run test:coverage

# Watch mode for development
npm run test:watch

# Integration tests
npm run test:integration
```

## Examples

### Basic Usage

```typescript
import { createClient } from '@coyote-sense/http-client';

const client = createClient();

// GET request
const users = await client.getAsync('https://api.example.com/users');

// POST request with JSON
const newUser = await client.postJsonAsync('https://api.example.com/users', {
  name: 'John Doe',
  email: 'john@example.com'
});

// Custom request
const response = await client.executeAsync({
  method: 'PUT',
  url: 'https://api.example.com/users/1',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ name: 'Updated Name' })
});
```

### Testing with Mocks

```typescript
import { MockHttpClient } from '@coyote-sense/http-client';

describe('User Service', () => {
  let httpClient: MockHttpClient;

  beforeEach(() => {
    httpClient = new MockHttpClient();
    httpClient.setPredefinedResponse(
      'https://api.example.com/users',
      200,
      JSON.stringify([{ id: 1, name: 'Test User' }])
    );
  });

  it('should fetch users', async () => {
    const users = await httpClient.getAsync('https://api.example.com/users');
    expect(users.statusCode).toBe(200);
    expect(JSON.parse(users.body)).toHaveLength(1);
  });
});
```

### Recording and Replay

```typescript
// Record phase
import { RecordHttpClient, RealHttpClient } from '@coyote-sense/http-client';

const recordClient = new RecordHttpClient(
  new RealHttpClient(),
  { recordingDirectory: './test-recordings' }
);

await recordClient.getAsync('https://api.example.com/users');

// Replay phase
import { ReplayHttpClient } from '@coyote-sense/http-client';

const replayClient = new ReplayHttpClient({
  recordingDirectory: './test-recordings'
});

const response = await replayClient.getAsync('https://api.example.com/users');
// Returns the recorded response
```

## API Reference

### Core Interfaces

#### HttpRequest
```typescript
interface HttpRequest {
  method: HttpMethod;
  url: string;
  headers: Record<string, string>;
  body?: string;
}
```

#### HttpResponse
```typescript
interface HttpResponse {
  statusCode: number;
  body: string;
  headers: Record<string, string>;
  errorMessage?: string;
  isSuccess: boolean;
}
```

#### IHttpClient
```typescript
interface IHttpClient {
  executeAsync(request: HttpRequest): Promise<HttpResponse>;
  getAsync(url: string, headers?: Record<string, string>): Promise<HttpResponse>;
  postAsync(url: string, body: string, headers?: Record<string, string>): Promise<HttpResponse>;
  postJsonAsync(url: string, data: any, headers?: Record<string, string>): Promise<HttpResponse>;
  putAsync(url: string, body: string, headers?: Record<string, string>): Promise<HttpResponse>;
  deleteAsync(url: string, headers?: Record<string, string>): Promise<HttpResponse>;
  pingAsync(): Promise<boolean>;
  getMode(): string;
}
```

## License

MIT

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to our repository.

## Support

For questions and support, please open an issue on our GitHub repository.
