/**
 * Advanced Features Example
 * 
 * Demonstrates advanced features including recording/replay, 
 * dependency injection, and configuration patterns.
 */

import { 
  RecordHttpClient, 
  ReplayHttpClient, 
  RealHttpClient,
  createHttpClientContainer,
  RuntimeMode,
  HttpClientConfig
} from '../index.js';

// Recording and Replay Example
export async function recordReplayExample() {
  console.log('=== Recording and Replay Example ===\n');

  // Note: This is a conceptual example since we're mocking fs operations
  console.log('1. Recording phase (would record to files):');
  
  const realClient = new RealHttpClient({
    baseUrl: 'https://jsonplaceholder.typicode.com',
    timeout: 5000
  });

  const recordClient = new RecordHttpClient(realClient, {
    recordingDirectory: './recordings',
    filenameTemplate: 'recording_{timestamp}_{method}_{url}.json',
    prettyPrint: true,
    includeHeaders: true,
    includeTimestamp: true
  });

  try {
    // This would record the request/response to a file
    const response = await recordClient.getAsync('/posts/1');
    console.log(`Recorded response: ${response.statusCode}`);
    console.log(`Recording mode: ${recordClient.getMode()}`);
  } catch (error) {
    console.log('Recording example (mock mode)');
  }

  console.log('\n2. Replay phase (would replay from files):');
  
  const replayClient = new ReplayHttpClient({
    recordingDirectory: './recordings',
    strictMatching: false,
    fallbackResponse: {
      statusCode: 200,
      body: '{"message": "Fallback response - no recording found"}',
      headers: { 'Content-Type': 'application/json' }
    }
  });

  try {
    // This would replay the recorded response
    const replayResponse = await replayClient.getAsync('/posts/1');
    console.log(`Replay response: ${replayResponse.statusCode}`);
    console.log(`Replay body: ${replayResponse.body}`);
  } catch (error) {
    console.log('Replay example (mock mode)');
  }
}

// Dependency Injection Example
export async function dependencyInjectionExample() {
  console.log('\n=== Dependency Injection Example ===\n');

  // Create configuration
  const config: HttpClientConfig = {
    mode: {
      mode: RuntimeMode.TESTING,
      mock: {
        defaultStatusCode: 200,
        defaultBody: '{"message": "DI configured response"}',
        defaultHeaders: { 'Content-Type': 'application/json' },
        simulateLatencyMs: 10
      }
    },
    logging: {
      level: 'info',
      enableConsole: true,
      enableFile: false
    }
  };

  // Create container with configuration
  const container = createHttpClientContainer(config);

  // Register additional services in the container
  container.register('apiBaseUrl', 'https://api.example.com');
  container.register('userService', (c) => new UserService(c.resolve('httpClient')));

  // Resolve services
  const httpClient = container.resolve('httpClient');
  const userService = container.resolve('userService');
  const baseUrl = container.resolve('apiBaseUrl');

  console.log(`HTTP Client mode: ${httpClient.getMode()}`);
  console.log(`Base URL: ${baseUrl}`);

  try {
    const response = await httpClient.getAsync('https://api.example.com/test');
    console.log(`DI Response: ${response.body}`);
  } catch (error) {
    console.error('DI example error:', error);
  }
}

// Sample service for DI example
class UserService {
  constructor(private httpClient: any) {}

  async getUser(id: number) {
    const response = await this.httpClient.getAsync(`/users/${id}`);
    return JSON.parse(response.body);
  }
}

// Configuration Patterns Example
export async function configurationPatternsExample() {
  console.log('\n=== Configuration Patterns Example ===\n');

  // Environment-based configuration
  console.log('1. Environment-based configuration:');
  
  // Simulate different environment variables
  const originalEnv = process.env.COYOTE_RUNTIME_MODE;
  
  process.env.COYOTE_RUNTIME_MODE = 'testing';
  const testContainer = createHttpClientContainer();
  const testClient = testContainer.resolve('httpClient');
  console.log(`Test environment mode: ${testClient.getMode()}`);
  
  process.env.COYOTE_RUNTIME_MODE = 'production';
  const prodContainer = createHttpClientContainer();
  const prodClient = prodContainer.resolve('httpClient');
  console.log(`Production environment mode: ${prodClient.getMode()}`);
  
  // Restore original environment
  if (originalEnv) {
    process.env.COYOTE_RUNTIME_MODE = originalEnv;
  } else {
    delete process.env.COYOTE_RUNTIME_MODE;
  }

  // Configuration override patterns
  console.log('\n2. Configuration override patterns:');
  
  const customConfig: HttpClientConfig = {
    mode: {
      mode: RuntimeMode.REAL,
      real: {
        baseUrl: 'https://custom.api.com',
        timeout: 10000,
        defaultHeaders: {
          'Authorization': 'Bearer custom-token',
          'X-Custom-Header': 'custom-value'
        },
        retryAttempts: 5,
        retryDelayMs: 2000
      }
    },
    logging: {
      level: 'debug',
      enableConsole: true,
      enableFile: true,
      filename: 'custom-http.log'
    }
  };

  const customContainer = createHttpClientContainer(customConfig);
  const customClient = customContainer.resolve('httpClient');
  console.log(`Custom configured mode: ${customClient.getMode()}`);

  // Multi-mode configuration
  console.log('\n3. Multi-mode configuration:');
  
  const multiModeConfig: HttpClientConfig = {
    mode: {
      mode: RuntimeMode.DEBUG,
      debug: {
        logRequests: true,
        logResponses: true,
        logHeaders: true,
        logTiming: true,
        logLevel: 'debug'
      },
      real: {
        baseUrl: 'https://api.example.com',
        timeout: 5000
      }
    },
    logging: {
      level: 'debug',
      enableConsole: true
    }
  };

  const debugContainer = createHttpClientContainer(multiModeConfig);
  const debugClient = debugContainer.resolve('httpClient');
  console.log(`Debug wrapped mode: ${debugClient.getMode()}`);
}

// Performance and Reliability Example
export async function performanceExample() {
  console.log('\n=== Performance and Reliability Example ===\n');

  // Configure a client with performance settings
  const performantClient = new RealHttpClient({
    baseUrl: 'https://api.example.com',
    timeout: 3000,
    retryAttempts: 3,
    retryDelayMs: 1000,
    defaultHeaders: {
      'Keep-Alive': 'timeout=5, max=1000',
      'Connection': 'keep-alive'
    }
  });

  console.log('1. Performance configuration:');
  console.log(`Mode: ${performantClient.getMode()}`);

  // Ping test for reliability
  console.log('\n2. Reliability testing:');
  try {
    const pingResult = await performantClient.pingAsync();
    console.log(`Ping successful: ${pingResult}`);
  } catch (error) {
    console.log('Ping test (simulated)');
  }

  // Batch request simulation
  console.log('\n3. Batch request pattern:');
  const urls = [
    'https://api.example.com/users/1',
    'https://api.example.com/users/2',
    'https://api.example.com/users/3'
  ];

  try {
    const batchPromises = urls.map(url => performantClient.getAsync(url));
    const results = await Promise.allSettled(batchPromises);
    
    results.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        console.log(`Request ${index + 1}: Success (${result.value.statusCode})`);
      } else {
        console.log(`Request ${index + 1}: Failed (${result.reason})`);
      }
    });
  } catch (error) {
    console.log('Batch request test (simulated)');
  }
}

// Run all advanced examples
async function runAllAdvancedExamples() {
  await recordReplayExample();
  await dependencyInjectionExample();
  await configurationPatternsExample();
  await performanceExample();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runAllAdvancedExamples().catch(console.error);
}
