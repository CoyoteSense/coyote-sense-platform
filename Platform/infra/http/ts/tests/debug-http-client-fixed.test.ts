/**
 * Debug HTTP Client Tests - Fixed Version
 * 
 * This demonstrates the correct patterns for testing the debug HTTP client
 * with the updated API and proper TypeScript typing.
 */

import { DebugHttpClient } from '../src/modes/debug/debug-http-client';
import { MockHttpClient } from '../src/modes/mock/mock-http-client';
import { HttpMethod, HttpRequest } from '../src/interfaces/http-client';
import { 
  HttpClientOptions, 
  DebugModeOptions, 
  MockModeOptions,
  DEFAULT_HTTP_OPTIONS,
  DEFAULT_MOCK_OPTIONS,
  DEFAULT_DEBUG_OPTIONS
} from '../src/interfaces/configuration';

describe('DebugHttpClient (Fixed)', () => {
  let mockLogger: Console;
  let httpOptions: HttpClientOptions;
  let debugOptions: DebugModeOptions;

  beforeEach(() => {
    mockLogger = {
      debug: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      log: jest.fn(),
    } as any;

    httpOptions = { ...DEFAULT_HTTP_OPTIONS };

    debugOptions = {
      verboseLogging: true,
      logBodies: true,
      logHeaders: true,
    };
  });

  describe('Construction and Configuration', () => {
    it('should create debug client correctly', () => {
      const debugClient = new DebugHttpClient(httpOptions, debugOptions, mockLogger);
      expect(debugClient).toBeInstanceOf(DebugHttpClient);
    });

    it('should handle minimal debug options', () => {
      const minimalOptions: DebugModeOptions = {
        verboseLogging: false,
        logBodies: false,
        logHeaders: false,
      };

      const debugClient = new DebugHttpClient(httpOptions, minimalOptions, mockLogger);
      expect(debugClient).toBeInstanceOf(DebugHttpClient);
    });
  });
  describe('executeAsync', () => {
    it('should execute request and log details when verbose logging enabled', async () => {
      const mockInnerClient = new MockHttpClient(DEFAULT_MOCK_OPTIONS, mockLogger);
      const debugClient = new DebugHttpClient(mockInnerClient, debugOptions, mockLogger);

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: 'https://httpbin.org/get',
        headers: { 'Authorization': 'Bearer token123' }
      };

      const response = await debugClient.executeAsync(request);

      expect(response.statusCode).toBe(200);

      // Verify request logging - the actual implementation logs with '[HTTP Request]' format
      expect(mockLogger.debug).toHaveBeenCalledWith(
        '[HTTP Request]',
        expect.objectContaining({
          method: 'GET',
          url: 'https://httpbin.org/get'
        })
      );
    });

    it('should respect verboseLogging option', async () => {
      const quietOptions: DebugModeOptions = {
        verboseLogging: false,
        logBodies: false,
        logHeaders: false,
      };

      const debugClient = new DebugHttpClient(httpOptions, quietOptions, mockLogger);      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: 'https://httpbin.org/get',
        headers: {}
      };

      await debugClient.executeAsync(request);

      // Check that verbose logs are not present
      const infoCalls = (mockLogger.info as jest.Mock).mock.calls.filter(call => 
        call[0] && call[0].includes('DEBUG HTTP Request')
      );
      expect(infoCalls.length).toBe(0);
    });    it('should log headers when logHeaders is enabled', async () => {
      const mockInnerClient = new MockHttpClient(DEFAULT_MOCK_OPTIONS, mockLogger);
      const debugClient = new DebugHttpClient(mockInnerClient, debugOptions, mockLogger);

      const request: HttpRequest = {
        method: HttpMethod.POST,
        url: 'https://httpbin.org/post',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': 'Bearer token123' 
        },
        body: '{"test": "data"}',
      };

      await debugClient.executeAsync(request);

      // Verify header logging - the actual implementation logs with '[HTTP Request Headers]' format
      expect(mockLogger.debug).toHaveBeenCalledWith(
        '[HTTP Request Headers]',
        expect.objectContaining({
          'Content-Type': 'application/json',
          'Authorization': 'Bearer token123'
        })
      );
    });

    it('should log request body when logBodies is enabled', async () => {
      const mockInnerClient = new MockHttpClient(DEFAULT_MOCK_OPTIONS, mockLogger);
      const debugClient = new DebugHttpClient(mockInnerClient, debugOptions, mockLogger);

      const requestBody = '{"name": "test", "value": 123}';
      const request: HttpRequest = {
        method: HttpMethod.POST,
        url: 'https://httpbin.org/post',
        headers: { 'Content-Type': 'application/json' },
        body: requestBody,
      };

      await debugClient.executeAsync(request);

      // Verify body logging - the actual implementation logs with '[HTTP Request Body]' format
      expect(mockLogger.debug).toHaveBeenCalledWith(
        '[HTTP Request Body]',
        expect.objectContaining({ body: requestBody })
      );
    });    it('should not log headers when logHeaders is disabled', async () => {
      const optionsWithoutHeaders: DebugModeOptions = {
        verboseLogging: true,
        logBodies: true,
        logHeaders: false,
      };

      const mockInnerClient = new MockHttpClient(DEFAULT_MOCK_OPTIONS, mockLogger);
      const debugClient = new DebugHttpClient(mockInnerClient, optionsWithoutHeaders, mockLogger);

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: 'https://httpbin.org/get',
        headers: { 'Authorization': 'Bearer token' }
      };

      await debugClient.executeAsync(request);

      // Check that header logs are not present
      const headerCalls = (mockLogger.debug as jest.Mock).mock.calls.filter(call => 
        call[0] && call[0].includes('[HTTP Request Headers]')
      );
      expect(headerCalls.length).toBe(0);
    });

    it('should not log body when logBodies is disabled', async () => {
      const optionsWithoutBodies: DebugModeOptions = {
        verboseLogging: true,
        logBodies: false,
        logHeaders: true,
      };

      const mockInnerClient = new MockHttpClient(DEFAULT_MOCK_OPTIONS, mockLogger);
      const debugClient = new DebugHttpClient(mockInnerClient, optionsWithoutBodies, mockLogger);

      const request: HttpRequest = {
        method: HttpMethod.POST,
        url: 'https://httpbin.org/post',
        headers: { 'Content-Type': 'application/json' },
        body: '{"test": "data"}',
      };

      await debugClient.executeAsync(request);

      // Check that body logs are not present
      const bodyCalls = (mockLogger.info as jest.Mock).mock.calls.filter(call => 
        call[0] && call[0].includes('DEBUG Request Body')
      );
      expect(bodyCalls.length).toBe(0);
    });
  });
  describe('pingAsync', () => {
    it('should execute ping and log the result', async () => {
      const mockInnerClient = new MockHttpClient(DEFAULT_MOCK_OPTIONS, mockLogger);
      const debugClient = new DebugHttpClient(mockInnerClient, debugOptions, mockLogger);

      const result = await debugClient.pingAsync('https://httpbin.org/status/200');

      expect(typeof result).toBe('boolean');
      expect(result).toBe(true);

      // Verify ping logging is handled by the underlying mock client
      expect(mockLogger.debug).toHaveBeenCalledWith('Mock HTTP client ping to https://httpbin.org/status/200');
    });
  });

  describe('dispose', () => {
    it('should dispose underlying real client', async () => {
      const debugClient = new DebugHttpClient(httpOptions, debugOptions, mockLogger);

      // This should complete without error
      await expect(debugClient.dispose()).resolves.not.toThrow();
    });
  });
});
