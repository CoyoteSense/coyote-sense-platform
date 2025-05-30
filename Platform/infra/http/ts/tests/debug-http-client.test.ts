/**
 * Debug HTTP Client Tests
 * 
 * Tests for the debug HTTP client that wraps other clients with enhanced logging.
 */

import { DebugHttpClient } from '../src/modes/debug/debug-http-client';
import { MockHttpClient } from '../src/modes/mock/mock-http-client';
import { HttpMethod, HttpRequest, HttpResponse, HttpClient } from '../src/interfaces/http-client';
import { DebugModeOptions, MockModeOptions, DebugHttpConfig, DEFAULT_HTTP_OPTIONS, DEFAULT_DEBUG_OPTIONS, DEFAULT_MOCK_OPTIONS } from '../src/interfaces/configuration';

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
    } as any;    const mockConfig: MockModeOptions = {
      ...DEFAULT_MOCK_OPTIONS
    };

    innerClient = new MockHttpClient(DEFAULT_HTTP_OPTIONS, mockConfig);

    const debugConfig: DebugModeOptions = {
      ...DEFAULT_DEBUG_OPTIONS
    };

    debugClient = new DebugHttpClient(innerClient, debugConfig, mockLogger);
  });

  describe('constructor', () => {    it('should create debug client with inner client', () => {
      expect(debugClient).toBeDefined();
      // Note: getMode() is not implemented in TypeScript DebugHttpClient
    });    it('should use default configuration when not provided', () => {
      const defaultDebugClient = new DebugHttpClient(DEFAULT_HTTP_OPTIONS, DEFAULT_DEBUG_OPTIONS, mockLogger);
      expect(defaultDebugClient).toBeDefined();
    });
  });

  describe('executeAsync', () => {
    it('should log request and response when logging enabled', async () => {      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/users/123',
        headers: { 'Authorization': 'Bearer token123' }
      };

      const response = await debugClient.executeAsync(request);

      expect(response.statusCode).toBe(200);
      expect(response.body).toBe('{"message":"Mock response"}');

      // Verify request logging
      expect(mockLogger.debug).toHaveBeenCalledWith(
        expect.stringContaining('[HTTP Request]'),
        expect.objectContaining({
          method: 'GET',
          url: '/api/users/123'
        })
      );

      // Verify response logging
      expect(mockLogger.debug).toHaveBeenCalledWith(
        expect.stringContaining('[HTTP Response]'),
        expect.objectContaining({
          statusCode: 200,
          duration: expect.any(String)
        })
      );

      // Verify headers logging
      expect(mockLogger.debug).toHaveBeenCalledWith(
        expect.stringContaining('[HTTP Request Headers]'),
        expect.objectContaining({
          'Authorization': 'Bearer token123'
        })
      );
    });

    it('should log timing information', async () => {
      const request: HttpRequest = {
        method: HttpMethod.POST,
        url: '/api/data',
        body: '{"test": "data"}'
      };      const startTime = Date.now();
      await debugClient.executeAsync(request);
      const endTime = Date.now();

      // Check that timing log was called
      const timingCalls = (mockLogger.debug as jest.Mock).mock.calls.filter(call => 
        call[0].includes('completed in')
      );
      expect(timingCalls.length).toBeGreaterThan(0);

      // Verify timing is reasonable (should be very fast for mock)
      const timingCall = timingCalls[0];
      const loggedDuration = timingCall[0].match(/(\d+)ms/)?.[1];
      if (loggedDuration) {
        const duration = parseInt(loggedDuration);
        expect(duration).toBeLessThan(endTime - startTime + 100); // Add some buffer
      }
    });    it('should not log headers when logHeaders is false', async () => {
      const configWithoutHeaders: DebugModeOptions = {
        verboseLogging: true,
        logBodies: true,
        logHeaders: false
      };

      const clientWithoutHeaders = new DebugHttpClient(innerClient, configWithoutHeaders, mockLogger);

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/test',
        headers: { 'Secret': 'should-not-be-logged' }
      };

      await clientWithoutHeaders.sendAsync(request);

      // Verify headers are not logged
      const headerCalls = (mockLogger.debug as jest.Mock).mock.calls.filter(call => 
        call[0].includes('[HTTP Request Headers]') || call[0].includes('[HTTP Response Headers]')
      );
      expect(headerCalls.length).toBe(0);
    });    it('should not log requests when logRequests is false', async () => {
      const configWithoutRequests: DebugModeOptions = {
        verboseLogging: true,
        logBodies: false,
        logHeaders: false,
        logRequests: false,
        logResponses: true,
        logTiming: false
      };

      const clientWithoutRequests = new DebugHttpClient(innerClient, configWithoutRequests, mockLogger);

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/test'
      };

      await clientWithoutRequests.sendAsync(request);

      // Verify request is not logged but response is
      const requestCalls = (mockLogger.debug as jest.Mock).mock.calls.filter(call => 
        call[0].includes('[HTTP Request]')
      );
      const responseCalls = (mockLogger.debug as jest.Mock).mock.calls.filter(call => 
        call[0].includes('[HTTP Response]')
      );
      
      expect(requestCalls.length).toBe(0);
      expect(responseCalls.length).toBe(1);
    });    it('should use different log levels', async () => {
      const infoConfig: DebugModeOptions = {
        verboseLogging: true,
        logBodies: false,
        logHeaders: false,
        logRequests: true,
        logResponses: true,
        logTiming: false,
        logLevel: 'info'
      };

      const infoClient = new DebugHttpClient(innerClient, infoConfig, mockLogger);

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/test'
      };

      await infoClient.sendAsync(request);

      // Verify info level logging
      expect(mockLogger.info).toHaveBeenCalled();
      expect(mockLogger.debug).not.toHaveBeenCalled();
    });    it('should handle errors from inner client', async () => {
      // Create a mock client that throws an error
      const errorClient: HttpClient = {
        executeAsync: jest.fn().mockRejectedValue(new Error('Network error')),
        pingAsync: jest.fn(),
        getAsync: jest.fn(),
        postJsonAsync: jest.fn(),
        putJsonAsync: jest.fn(),
        deleteAsync: jest.fn(),
        dispose: jest.fn().mockResolvedValue(undefined)      };

      const errorDebugClient = new DebugHttpClient(errorClient, { verboseLogging: true, logBodies: true, logHeaders: true }, mockLogger);

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/test'
      };

      await expect(errorDebugClient.sendAsync(request)).rejects.toThrow('Network error');

      // Verify error logging
      expect(mockLogger.error).toHaveBeenCalledWith(
        expect.stringContaining('[HTTP Error]'),
        expect.any(Error)
      );
    });    it('should pass through all request properties to inner client', async () => {
      const sendSpy = jest.spyOn(innerClient, 'executeAsync');

      const request: HttpRequest = {
        method: HttpMethod.PUT,
        url: '/api/users/123',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': 'Bearer token'
        },
        body: '{"name": "Updated Name"}'
      };

      await debugClient.sendAsync(request);

      expect(sendSpy).toHaveBeenCalledWith(request);
    });
  });

  describe('dispose', () => {
    it('should dispose inner client', async () => {
      const disposeSpy = jest.spyOn(innerClient, 'dispose');

      await debugClient.dispose();

      expect(disposeSpy).toHaveBeenCalled();
    });    it('should handle dispose errors gracefully', async () => {
      const errorClient: HttpClient = {
        executeAsync: jest.fn(),
        pingAsync: jest.fn(),
        getAsync: jest.fn(),
        postJsonAsync: jest.fn(),
        putJsonAsync: jest.fn(),
        deleteAsync: jest.fn(),
        dispose: jest.fn().mockRejectedValue(new Error('Dispose error'))
      };

      const errorDebugClient = new DebugHttpClient(errorClient, { verboseLogging: true, logBodies: true, logHeaders: true }, mockLogger);

      await expect(errorDebugClient.dispose()).resolves.not.toThrow();
      expect(mockLogger.error).toHaveBeenCalledWith(
        expect.stringContaining('Error disposing inner HTTP client'),
        expect.any(Error)
      );
    });
  });
});
