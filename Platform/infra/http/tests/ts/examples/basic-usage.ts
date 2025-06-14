/**
 * Basic HTTP Client Usage Example
 * 
 * Demonstrates the basic usage of the HTTP client library.
 */

import { createClient, RuntimeMode } from '../index.js';

async function basicExample() {
  console.log('=== Basic HTTP Client Usage ===\n');

  // Create a client using environment detection
  const client = createClient();
  console.log(`Current mode: ${client.getMode()}`);

  // Example API endpoint (you can replace with a real endpoint)
  const apiUrl = 'https://jsonplaceholder.typicode.com';

  try {
    // GET request
    console.log('\n1. GET Request:');
    const users = await client.getAsync(`${apiUrl}/users/1`);
    console.log(`Status: ${users.statusCode}`);
    console.log(`Response: ${users.body.substring(0, 100)}...`);

    // POST request with JSON
    console.log('\n2. POST Request:');
    const newPost = await client.postJsonAsync(`${apiUrl}/posts`, {
      title: 'Test Post',
      body: 'This is a test post',
      userId: 1
    });
    console.log(`Status: ${newPost.statusCode}`);
    console.log(`Response: ${newPost.body.substring(0, 100)}...`);

    // Custom request with headers
    console.log('\n3. Custom Request:');
    const customResponse = await client.executeAsync({
      method: 'GET',
      url: `${apiUrl}/posts/1`,
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'CoyoteSense-Example/1.0'
      },
      body: ''
    });
    console.log(`Status: ${customResponse.statusCode}`);
    console.log(`Headers: ${JSON.stringify(customResponse.headers, null, 2)}`);

    // Ping test
    console.log('\n4. Ping Test:');
    const pingResult = await client.pingAsync();
    console.log(`Ping result: ${pingResult}`);

  } catch (error) {
    console.error('Error occurred:', error);
  }
}

async function mockExample() {
  console.log('\n=== Mock Client Usage ===\n');

  // Create a mock client for testing
  const mockClient = createClient(RuntimeMode.TESTING);
  console.log(`Mock mode: ${mockClient.getMode()}`);

  try {
    // Mock client will return predefined responses
    const response = await mockClient.getAsync('https://api.example.com/test');
    console.log(`Mock response status: ${response.statusCode}`);
    console.log(`Mock response body: ${response.body}`);

  } catch (error) {
    console.error('Mock error:', error);
  }
}

// Run examples
async function runExamples() {
  await basicExample();
  await mockExample();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runExamples().catch(console.error);
}

export { basicExample, mockExample };
