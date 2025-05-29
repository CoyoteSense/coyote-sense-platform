/**
 * Mock HTTP Client Tests
 * 
 * Tests for the mock HTTP client functionality including predefined responses,
 * JSON responses, and pattern matching.
 */

import { MockHttpClient } from '../src/modes/mock/mock-http-client';
import { HttpMethod } from '../src/interfaces/http-client';
import { DEFAULT_HTTP_OPTIONS, DEFAULT_MOCK_OPTIONS } from '../src/interfaces/configuration';

describe('MockHttpClient', () => {
  let client: MockHttpClient;
  let mockLogger: Console;

  beforeEach(() => {
    mockLogger = {
      debug: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    } as any;

    client = new MockHttpClient(DEFAULT_HTTP_OPTIONS, DEFAULT_MOCK_OPTIONS, mockLogger);
  });

  afterEach(() => {
    client.dispose();
  });

  describe('basic functionality', () => {
    it('should return default response when no predefined response exists', async () => {
      const request = client.createRequest();
      request.url = 'https://api.example.com/test';
      request.method = HttpMethod.GET;

      const response = await client.executeAsync(request);

      expect(response.statusCode).toBe(DEFAULT_MOCK_OPTIONS.defaultStatusCode);
      expect(response.body).toBe(DEFAULT_MOCK_OPTIONS.defaultBody);
      expect(response.headers).toEqual(expect.objectContaining(DEFAULT_MOCK_OPTIONS.defaultHeaders));
      expect(response.isSuccess).toBe(true);
    });

    it('should log debug messages', async () => {
      const request = client.createRequest();
      request.url = 'https://api.example.com/test';
      request.method = HttpMethod.GET;

      await client.executeAsync(request);

      expect(mockLogger.debug).toHaveBeenCalledWith(
        'Mock HTTP client executing GET request to https://api.example.com/test'
      );
      expect(mockLogger.debug).toHaveBeenCalledWith(
        'Mock HTTP client returning status 200 for https://api.example.com/test'
      );
    });

    it('should simulate latency', async () => {
      const mockOptions = { ...DEFAULT_MOCK_OPTIONS, simulateLatencyMs: 100 };
      client = new MockHttpClient(DEFAULT_HTTP_OPTIONS, mockOptions, mockLogger);

      const request = client.createRequest();
      request.url = 'https://api.example.com/test';

      const startTime = Date.now();
      await client.executeAsync(request);
      const duration = Date.now() - startTime;

      expect(duration).toBeGreaterThanOrEqual(95); // Allow some timing variance
    });
  });

  describe('predefined responses', () => {
    it('should return predefined response for exact URL match', async () => {
      const url = 'https://api.example.com/users';
      const statusCode = 201;
      const body = '{"id": 123}';
      const headers = { 'Content-Type': 'application/json', 'X-Custom': 'header' };

      client.setPredefinedResponse(url, statusCode, body, headers);

      const request = client.createRequest();
      request.url = url;
      request.method = HttpMethod.POST;

      const response = await client.executeAsync(request);

      expect(response.statusCode).toBe(statusCode);
      expect(response.body).toBe(body);
      expect(response.headers).toEqual(headers);
      expect(response.isSuccess).toBe(true);
    });

    it('should return predefined JSON response', async () => {
      const url = 'https://api.example.com/users';
      const data = { id: 123, name: 'John Doe', email: 'john@example.com' };
      const statusCode = 200;

      client.setPredefinedJsonResponse(url, data, statusCode);

      const request = client.createRequest();
      request.url = url;

      const response = await client.executeAsync(request);

      expect(response.statusCode).toBe(statusCode);
      expect(response.body).toBe(JSON.stringify(data));
      expect(response.headers['Content-Type']).toBe('application/json');
      expect(response.isSuccess).toBe(true);

      const parsedData = client.getContent(response);
      expect(parsedData).toEqual(data);
    });

    it('should match wildcard patterns', async () => {
      client.setPredefinedResponse('*/users/*', 200, 'Wildcard match');

      const request = client.createRequest();
      request.url = 'https://api.example.com/users/123';

      const response = await client.executeAsync(request);

      expect(response.body).toBe('Wildcard match');
    });

    it('should match partial URL patterns', async () => {
      client.setPredefinedResponse('api.example.com', 200, 'Partial match');

      const request = client.createRequest();
      request.url = 'https://api.example.com/any/path';

      const response = await client.executeAsync(request);

      expect(response.body).toBe('Partial match');
    });

    it('should prioritize exact matches over pattern matches', async () => {
      const exactUrl = 'https://api.example.com/users/123';
      
      client.setPredefinedResponse('*/users/*', 200, 'Pattern match');
      client.setPredefinedResponse(exactUrl, 201, 'Exact match');

      const request = client.createRequest();
      request.url = exactUrl;

      const response = await client.executeAsync(request);

      expect(response.statusCode).toBe(201);
      expect(response.body).toBe('Exact match');
    });
  });

  describe('configuration methods', () => {
    it('should set default response', () => {
      const statusCode = 500;
      const body = 'Server Error';
      const headers = { 'Content-Type': 'text/plain' };
      const delayMs = 50;

      client.setDefaultResponse(statusCode, body, headers, delayMs);

      // Access private properties through any for testing
      const mockOptions = (client as any).mockOptions;
      expect(mockOptions.defaultStatusCode).toBe(statusCode);
      expect(mockOptions.defaultBody).toBe(body);
      expect(mockOptions.defaultHeaders).toEqual(headers);
      expect(mockOptions.simulateLatencyMs).toBe(delayMs);
    });

    it('should clear predefined responses', () => {
      client.setPredefinedResponse('https://api.example.com/test', 200, 'Test');
      expect(client.getConfiguredUrls()).toContain('https://api.example.com/test');

      client.clearPredefinedResponses();
      expect(client.getConfiguredUrls()).toHaveLength(0);
    });

    it('should return configured URLs', () => {
      const urls = [
        'https://api.example.com/users',
        'https://api.example.com/orders',
        '*/products/*'
      ];

      urls.forEach(url => {
        client.setPredefinedResponse(url, 200, 'Test');
      });

      const configuredUrls = client.getConfiguredUrls();
      expect(configuredUrls).toHaveLength(urls.length);
      urls.forEach(url => {
        expect(configuredUrls).toContain(url);
      });
    });
  });

  describe('HTTP methods', () => {
    it('should handle GET request', async () => {
      const response = await client.getAsync('https://api.example.com/test');
      expect(response.isSuccess).toBe(true);
    });

    it('should handle POST request with JSON', async () => {
      const data = { name: 'John', age: 30 };
      const response = await client.postJsonAsync('https://api.example.com/users', data);
      
      expect(response.isSuccess).toBe(true);
    });

    it('should handle PUT request with JSON', async () => {
      const data = { id: 1, name: 'Updated Name' };
      const response = await client.putJsonAsync('https://api.example.com/users/1', data);
      
      expect(response.isSuccess).toBe(true);
    });

    it('should handle DELETE request', async () => {
      const response = await client.deleteAsync('https://api.example.com/users/1');
      expect(response.isSuccess).toBe(true);
    });
  });

  describe('ping functionality', () => {
    it('should always return true for ping', async () => {
      const result = await client.pingAsync('https://api.example.com');
      expect(result).toBe(true);
    });

    it('should log ping debug message', async () => {
      await client.pingAsync('https://api.example.com');
      expect(mockLogger.debug).toHaveBeenCalledWith('Mock HTTP client ping to https://api.example.com');
    });
  });

  describe('error responses', () => {
    it('should return error response for 4xx status codes', async () => {
      client.setPredefinedResponse('https://api.example.com/error', 404, 'Not Found');

      const request = client.createRequest();
      request.url = 'https://api.example.com/error';

      const response = await client.executeAsync(request);

      expect(response.statusCode).toBe(404);
      expect(response.isSuccess).toBe(false);
      expect(response.errorMessage).toBe('Mock error response 404');
    });

    it('should return error response for 5xx status codes', async () => {
      client.setPredefinedResponse('https://api.example.com/error', 500, 'Internal Server Error');

      const request = client.createRequest();
      request.url = 'https://api.example.com/error';

      const response = await client.executeAsync(request);

      expect(response.statusCode).toBe(500);
      expect(response.isSuccess).toBe(false);
      expect(response.errorMessage).toBe('Mock error response 500');
    });
  });

  describe('content parsing', () => {
    it('should parse valid JSON content', () => {
      const jsonData = { id: 1, name: 'Test' };
      const response = {
        statusCode: 200,
        body: JSON.stringify(jsonData),
        headers: {},
        isSuccess: true
      };

      const parsedContent = client.getContent(response);
      expect(parsedContent).toEqual(jsonData);
    });

    it('should return null for invalid JSON content', () => {
      const response = {
        statusCode: 200,
        body: 'invalid json {',
        headers: {},
        isSuccess: true
      };

      // Spy on console.warn to check if warning is logged
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      const parsedContent = client.getContent(response);
      expect(parsedContent).toBeNull();
      expect(consoleSpy).toHaveBeenCalledWith(
        'Failed to parse response body as JSON:',
        expect.any(SyntaxError)
      );

      consoleSpy.mockRestore();
    });

    it('should return null for empty body', () => {
      const response = {
        statusCode: 200,
        body: '',
        headers: {},
        isSuccess: true
      };

      const parsedContent = client.getContent(response);
      expect(parsedContent).toBeNull();
    });
  });
});
