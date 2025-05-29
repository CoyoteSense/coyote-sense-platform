/**
 * Debug HTTP Client Tests
 * 
 * Tests for the debug HTTP client that wraps other clients with enhanced logging.
 */

import { DebugHttpClient } from '../src/modes/debug/debug-http-client';
import { MockHttpClient } from '../src/modes/mock/mock-http-client';
import { HttpMethod, HttpRequest, HttpResponse, HttpClient } from '../src/interfaces/http-client';
import { DebugModeOptions, MockModeOptions, DEFAULT_HTTP_OPTIONS, DEFAULT_DEBUG_OPTIONS, DEFAULT_MOCK_OPTIONS } from '../src/interfaces/configuration';

describe('DebugHttpClient', () => {
  let debugClient: DebugHttpClient;
  let innerClient: MockHttpClient;
  let mockLogger: Console;

  beforeEach(() => {
    mockLogger = {
      debug: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      log: jest.fn(),
      trace: jest.fn(),
      assert: jest.fn(),
      clear: jest.fn(),
      count: jest.fn(),
      countReset: jest.fn(),
      dir: jest.fn(),
      dirxml: jest.fn(),
      group: jest.fn(),
      groupCollapsed: jest.fn(),
      groupEnd: jest.fn(),
      table: jest.fn(),
      time: jest.fn(),
      timeEnd: jest.fn(),
      timeLog: jest.fn(),
      timeStamp: jest.fn(),
      profile: jest.fn(),
      profileEnd: jest.fn()
    } as any;

    const mockOptions: MockModeOptions = {
      ...DEFAULT_MOCK_OPTIONS
    };

    innerClient = new MockHttpClient(DEFAULT_HTTP_OPTIONS, mockOptions);

    const debugOptions: DebugModeOptions = {
      ...DEFAULT_DEBUG_OPTIONS
    };

    debugClient = new DebugHttpClient(DEFAULT_HTTP_OPTIONS, debugOptions, innerClient);
  });

  describe('constructor', () => {
    it('should create debug client with inner client', () => {
      expect(debugClient).toBeDefined();
      expect(debugClient).toBeInstanceOf(DebugHttpClient);
    });

    it('should use default configuration when none provided', () => {
      const defaultDebugClient = new DebugHttpClient(DEFAULT_HTTP_OPTIONS, DEFAULT_DEBUG_OPTIONS, innerClient);
      expect(defaultDebugClient).toBeDefined();
    });
  });

  describe('executeAsync', () => {
    it('should log request and response details', async () => {
      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/users/123',
        headers: {
          'Authorization': 'Bearer token123'
        }
      };

      const response = await debugClient.executeAsync(request);

      expect(response).toBeDefined();
      expect(response.statusCode).toBe(200);

      // Verify debug logging was called
      expect(mockLogger.debug).toHaveBeenCalled();
      
      // Find request and response log calls
      const debugCalls = (mockLogger.debug as jest.Mock).mock.calls;
      const requestCall = debugCalls.find(call => call[0].includes('[HTTP Request]'));
      const responseCall = debugCalls.find(call => call[0].includes('[HTTP Response]'));
      
      expect(requestCall).toBeDefined();
      expect(responseCall).toBeDefined();
    });

    it('should log timing information', async () => {
      const request: HttpRequest = {
        method: HttpMethod.POST,
        url: '/api/users',
        body: JSON.stringify({ name: 'Test User' })
      };

      const startTime = Date.now();
      await debugClient.executeAsync(request);
      
      // Check for timing logs
      const debugCalls = (mockLogger.debug as jest.Mock).mock.calls;
      const timingCalls = debugCalls.filter(call => 
        call[0].includes('ms') && call[0].includes('HTTP')
      );
      
      expect(timingCalls.length).toBeGreaterThan(0);
    });

    it('should respect logHeaders configuration', async () => {
      const configWithoutHeaders: DebugModeOptions = {
        ...DEFAULT_DEBUG_OPTIONS,
        logHeaders: false
      };

      const clientWithoutHeaders = new DebugHttpClient(DEFAULT_HTTP_OPTIONS, configWithoutHeaders, innerClient);

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/test',
        headers: {
          'Authorization': 'Bearer secret'
        }
      };

      await clientWithoutHeaders.executeAsync(request);

      // Verify headers are not logged
      const debugCalls = (mockLogger.debug as jest.Mock).mock.calls;
      const headerCalls = debugCalls.filter(call => 
        call[0].includes('Authorization') || call[0].includes('Bearer')
      );
      
      expect(headerCalls.length).toBe(0);
    });

    it('should respect logRequests configuration', async () => {
      const configWithoutRequests: DebugModeOptions = {
        ...DEFAULT_DEBUG_OPTIONS,
        logRequests: false
      };

      const clientWithoutRequests = new DebugHttpClient(DEFAULT_HTTP_OPTIONS, configWithoutRequests, innerClient);

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/test'
      };

      await clientWithoutRequests.executeAsync(request);

      // Verify request is not logged but response is
      const debugCalls = (mockLogger.debug as jest.Mock).mock.calls;
      const requestCalls = debugCalls.filter(call => call[0].includes('[HTTP Request]'));
      const responseCalls = debugCalls.filter(call => call[0].includes('[HTTP Response]'));
      
      expect(requestCalls.length).toBe(0);
      expect(responseCalls.length).toBeGreaterThan(0);
    });

    it('should use specified log level', async () => {
      const infoConfig: DebugModeOptions = {
        ...DEFAULT_DEBUG_OPTIONS,
        logLevel: 'info'
      };

      const infoClient = new DebugHttpClient(DEFAULT_HTTP_OPTIONS, infoConfig, innerClient);

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/test'
      };

      await infoClient.executeAsync(request);

      // Verify info level logging
      expect(mockLogger.info).toHaveBeenCalled();
      expect(mockLogger.debug).not.toHaveBeenCalled();
    });
  });

  describe('error handling', () => {
    it('should handle errors from inner client', async () => {
      const errorClient: HttpClient = {
        executeAsync: jest.fn().mockRejectedValue(new Error('Network error')),
        dispose: jest.fn()
      };

      const errorDebugClient = new DebugHttpClient(DEFAULT_HTTP_OPTIONS, DEFAULT_DEBUG_OPTIONS, errorClient);

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/test'
      };

      await expect(errorDebugClient.executeAsync(request)).rejects.toThrow('Network error');

      // Verify error logging
      expect(mockLogger.debug).toHaveBeenCalled();
    });
  });

  describe('spy verification', () => {
    it('should delegate to inner client', async () => {
      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/users/123',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer token'
        }
      };

      const sendSpy = jest.spyOn(innerClient, 'executeAsync');

      await debugClient.executeAsync(request);

      expect(sendSpy).toHaveBeenCalledWith(request);
    });
  });

  describe('dispose', () => {
    it('should dispose inner client', async () => {
      const disposeSpy = jest.spyOn(innerClient, 'dispose');

      await debugClient.dispose();

      expect(disposeSpy).toHaveBeenCalled();
    });

    it('should handle dispose errors', async () => {
      const errorClient: HttpClient = {
        executeAsync: jest.fn(),
        dispose: jest.fn().mockRejectedValue(new Error('Dispose error'))
      };

      const errorDebugClient = new DebugHttpClient(DEFAULT_HTTP_OPTIONS, DEFAULT_DEBUG_OPTIONS, errorClient);

      await expect(errorDebugClient.dispose()).rejects.toThrow('Dispose error');
    });
  });
});
