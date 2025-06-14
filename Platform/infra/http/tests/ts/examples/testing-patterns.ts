/**
 * Testing Patterns Example
 * 
 * Demonstrates different testing patterns using the HTTP client library.
 */

import { MockHttpClient, DebugHttpClient, SimulationHttpClient } from '../index.js';

// Example service to test
class UserService {
  constructor(private httpClient: any) {}

  async getUser(id: number) {
    const response = await this.httpClient.getAsync(`https://api.example.com/users/${id}`);
    if (!response.isSuccess) {
      throw new Error(`Failed to get user: ${response.errorMessage}`);
    }
    return JSON.parse(response.body);
  }

  async createUser(user: { name: string; email: string }) {
    const response = await this.httpClient.postJsonAsync('https://api.example.com/users', user);
    if (!response.isSuccess) {
      throw new Error(`Failed to create user: ${response.errorMessage}`);
    }
    return JSON.parse(response.body);
  }
}

// Testing with Mock Client
export function testWithMockClient() {
  console.log('=== Testing with Mock Client ===\n');

  const mockClient = new MockHttpClient({
    defaultStatusCode: 200,
    defaultBody: '{"test": "default"}',
    defaultHeaders: { 'Content-Type': 'application/json' }
  });

  // Set up specific mock responses
  mockClient.setPredefinedResponse(
    'https://api.example.com/users/1',
    200,
    JSON.stringify({ id: 1, name: 'John Doe', email: 'john@example.com' })
  );

  mockClient.setPredefinedResponse(
    'https://api.example.com/users',
    201,
    JSON.stringify({ id: 2, name: 'Jane Smith', email: 'jane@example.com' }),
    { 'Location': '/users/2' }
  );

  const userService = new UserService(mockClient);

  // Test scenarios
  async function runMockTests() {
    try {
      console.log('1. Getting user:');
      const user = await userService.getUser(1);
      console.log(`User: ${JSON.stringify(user)}`);

      console.log('\n2. Creating user:');
      const newUser = await userService.createUser({
        name: 'Jane Smith',
        email: 'jane@example.com'
      });
      console.log(`Created user: ${JSON.stringify(newUser)}`);

    } catch (error) {
      console.error('Test error:', error);
    }
  }

  return runMockTests();
}

// Testing with Debug Client
export function testWithDebugClient() {
  console.log('\n=== Testing with Debug Client ===\n');

  const mockClient = new MockHttpClient();
  const debugClient = new DebugHttpClient(mockClient, {
    logRequests: true,
    logResponses: true,
    logHeaders: true,
    logTiming: true,
    logLevel: 'debug'
  }, console);

  const userService = new UserService(debugClient);

  async function runDebugTests() {
    try {
      console.log('Making request with debug logging:');
      await userService.getUser(1);
    } catch (error) {
      console.error('Debug test error:', error);
    }
  }

  return runDebugTests();
}

// Testing with Simulation Client
export function testWithSimulationClient() {
  console.log('\n=== Testing with Simulation Client ===\n');

  const simulationClient = new SimulationHttpClient({
    scenarioFile: '',
    globalLatencyMs: 50,
    globalFailureRate: 0.1,
    defaultScenario: {
      statusCode: 200,
      body: '{"simulation": "default"}',
      headers: { 'Content-Type': 'application/json' },
      latencyMs: 100
    }
  });

  // Add custom scenarios
  simulationClient.addScenario({
    name: 'User API Success',
    pattern: '/users/*',
    statusCode: 200,
    body: '{"id": 1, "name": "Simulated User", "email": "sim@example.com"}',
    headers: { 'Content-Type': 'application/json' },
    latencyMs: 75
  });

  simulationClient.addScenario({
    name: 'Slow Response',
    pattern: '/slow/*',
    statusCode: 200,
    body: '{"message": "This was slow"}',
    headers: { 'Content-Type': 'application/json' },
    latencyMs: 500
  });

  simulationClient.addScenario({
    name: 'Server Error',
    pattern: '/error/*',
    statusCode: 500,
    body: '{"error": "Internal Server Error"}',
    headers: { 'Content-Type': 'application/json' },
    latencyMs: 10
  });

  const userService = new UserService(simulationClient);

  async function runSimulationTests() {
    try {
      console.log('1. Normal user request:');
      const user = await userService.getUser(1);
      console.log(`User: ${JSON.stringify(user)}`);

      console.log('\n2. Testing simulation scenarios:');
      const stats = simulationClient.getStats();
      console.log(`Available scenarios: ${stats.totalScenarios}`);

      // Test different patterns
      console.log('\n3. Testing different URL patterns:');
      
      const apiResponse = await simulationClient.getAsync('https://api.example.com/users/123');
      console.log(`API response: ${apiResponse.statusCode} - ${apiResponse.body.substring(0, 50)}...`);

      const slowResponse = await simulationClient.getAsync('https://api.example.com/slow/test');
      console.log(`Slow response: ${slowResponse.statusCode} - ${slowResponse.body}`);

    } catch (error) {
      console.error('Simulation test error:', error);
    }
  }

  return runSimulationTests();
}

// Error handling patterns
export function testErrorHandling() {
  console.log('\n=== Error Handling Patterns ===\n');

  const mockClient = new MockHttpClient();
  
  // Set up error responses
  mockClient.setPredefinedResponse(
    'https://api.example.com/users/404',
    404,
    JSON.stringify({ error: 'User not found' })
  );

  mockClient.setPredefinedResponse(
    'https://api.example.com/users/500',
    500,
    JSON.stringify({ error: 'Internal Server Error' })
  );

  async function runErrorTests() {
    try {
      console.log('1. Testing 404 error:');
      const notFoundResponse = await mockClient.getAsync('https://api.example.com/users/404');
      console.log(`404 Response: ${notFoundResponse.statusCode} - ${notFoundResponse.body}`);
      console.log(`Is success: ${notFoundResponse.isSuccess}`);

      console.log('\n2. Testing 500 error:');
      const serverErrorResponse = await mockClient.getAsync('https://api.example.com/users/500');
      console.log(`500 Response: ${serverErrorResponse.statusCode} - ${serverErrorResponse.body}`);
      console.log(`Is success: ${serverErrorResponse.isSuccess}`);

    } catch (error) {
      console.error('Error test error:', error);
    }
  }

  return runErrorTests();
}

// Run all testing examples
async function runAllTests() {
  await testWithMockClient();
  await testWithDebugClient();
  await testWithSimulationClient();
  await testErrorHandling();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runAllTests().catch(console.error);
}
