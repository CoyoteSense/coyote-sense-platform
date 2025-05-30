import { MockHttpClient } from '../src/modes/mock/mock-http-client';
import { DebugHttpClient } from '../src/modes/debug/debug-http-client';
import { HttpMethod, HttpRequest } from '../src/interfaces/http-client';
import { DEFAULT_HTTP_OPTIONS, DEFAULT_MOCK_OPTIONS, DEFAULT_DEBUG_OPTIONS, RuntimeMode } from '../src/interfaces/configuration';

describe('Basic Integration Tests', () => {
  test('MockHttpClient should work with default options', async () => {
    const client = new MockHttpClient(DEFAULT_HTTP_OPTIONS, DEFAULT_MOCK_OPTIONS);
      const request: HttpRequest = {
      method: HttpMethod.GET,
      url: 'https://api.example.com/users',
      headers: {}
    };

    const response = await client.executeAsync(request);
    
    expect(response.statusCode).toBe(200);
    expect(response.isSuccess).toBe(true);
    expect(response.body).toBe('{"message":"Mock response"}');
  });  test('DebugHttpClient should wrap inner client via MockHttpClient', async () => {
    const mockLogger = {
      debug: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    } as any;
    
    // Create a mock client as the inner client
    const mockClient = new MockHttpClient(DEFAULT_HTTP_OPTIONS, DEFAULT_MOCK_OPTIONS);
    const debugClient = new DebugHttpClient(mockClient, DEFAULT_DEBUG_OPTIONS, mockLogger);
    
    const request: HttpRequest = {
      method: HttpMethod.POST,
      url: 'https://api.example.com/users',
      headers: { 'Content-Type': 'application/json' },
      body: '{"name":"test"}'
    };

    const response = await debugClient.executeAsync(request);
    
    expect(response.statusCode).toBe(200);
    expect(response.isSuccess).toBe(true);
  });
  test('Factory should create clients', async () => {
    const { createHttpClient } = await import('../src/factory/http-client-factory');
    
    const mockLogger = {
      debug: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    } as any;
    
    const client = createHttpClient(RuntimeMode.MOCK, mockLogger);    const request: HttpRequest = {
      method: HttpMethod.GET,
      url: 'https://api.example.com/test',
      headers: {}
    };

    const response = await client.executeAsync(request);
    expect(response).toBeDefined();
    expect(response.statusCode).toBeGreaterThanOrEqual(200);
  });
});
