/**
 * Simple working test to verify our test setup and core functionality
 */

import { RealHttpClient } from '../src/modes/real/real-http-client';
import { MockHttpClient } from '../src/modes/mock/mock-http-client';
import { HttpMethod, HttpRequest } from '../src/interfaces/http-client';
import { DEFAULT_HTTP_OPTIONS, DEFAULT_MOCK_OPTIONS } from '../src/interfaces/configuration';

// Mock fetch globally for RealHttpClient tests
global.fetch = jest.fn();

describe('HTTP Client Core Functionality', () => {
  beforeEach(() => {
    if (global.fetch) {
      (global.fetch as jest.MockedFunction<typeof fetch>).mockClear();
    }
  });

  describe('MockHttpClient', () => {
    it('should create and execute basic request', async () => {
      const client = new MockHttpClient(DEFAULT_HTTP_OPTIONS, DEFAULT_MOCK_OPTIONS);
      
      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/test'
      };

      const response = await client.executeAsync(request);
      
      expect(response).toBeDefined();
      expect(response.statusCode).toBe(200);
      expect(response.isSuccess).toBe(true);
    });

    it('should handle POST requests', async () => {
      const client = new MockHttpClient(DEFAULT_HTTP_OPTIONS, DEFAULT_MOCK_OPTIONS);
      
      const request: HttpRequest = {
        method: HttpMethod.POST,
        url: '/users',
        body: '{"name": "test"}'
      };

      const response = await client.executeAsync(request);
      
      expect(response).toBeDefined();
      expect(response.statusCode).toBe(200);
    });
  });

  describe('RealHttpClient', () => {
    it('should create client successfully', () => {
      const client = new RealHttpClient(DEFAULT_HTTP_OPTIONS);
      expect(client).toBeDefined();
    });

    it('should handle mocked GET request', async () => {
      const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
      const mockResponse = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: new Headers({ 'content-type': 'application/json' }),
        text: jest.fn().mockResolvedValue('{"result": "success"}')
      };
      mockFetch.mockResolvedValue(mockResponse as any);

      const client = new RealHttpClient(DEFAULT_HTTP_OPTIONS);
      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/test'
      };

      const response = await client.executeAsync(request);
      
      expect(response.statusCode).toBe(200);
      expect(response.body).toBe('{"result": "success"}');
      expect(response.isSuccess).toBe(true);
    });
  });
});
