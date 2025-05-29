/**
 * Record HTTP Client Tests
 * 
 * Tests for the HTTP client that records request/response pairs for later replay.
 */

import { RecordHttpClient } from '../src/modes/record/record-http-client';
import { MockHttpClient } from '../src/modes/mock/mock-http-client';
import { HttpMethod, HttpRequest, HttpResponse, HttpClient } from '../src/interfaces/http-client';
import { RecordModeOptions, MockModeOptions } from '../src/interfaces/configuration';
import * as fs from 'fs/promises';
import * as path from 'path';

// Mock fs module
jest.mock('fs/promises');

describe('RecordHttpClient', () => {
  let recordClient: RecordHttpClient;
  let innerClient: MockHttpClient;
  let mockLogger: Console;
  let mockFs: jest.Mocked<typeof fs>;

  beforeEach(() => {
    mockFs = fs as jest.Mocked<typeof fs>;
    mockFs.mkdir.mockResolvedValue(undefined);
    mockFs.writeFile.mockResolvedValue(undefined);
    mockFs.access.mockRejectedValue(new Error('Directory does not exist'));

    mockLogger = {
      debug: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    } as any;

    const mockConfig: MockHttpConfig = {
      defaultStatusCode: 200,
      defaultBody: '{"success": true}',
      defaultHeaders: { 'Content-Type': 'application/json' }
    };

    innerClient = new MockHttpClient(mockConfig, mockLogger);

    const recordConfig: RecordHttpConfig = {
      recordingDirectory: '/test/recordings',
      filenameTemplate: 'recording_{timestamp}_{method}_{url}.json',
      prettyPrint: true,
      includeHeaders: true,
      includeTimestamp: true
    };

    recordClient = new RecordHttpClient(innerClient, recordConfig, mockLogger);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('constructor', () => {
    it('should create record client with inner client', () => {
      expect(recordClient).toBeDefined();
      expect(recordClient.getMode()).toBe('record');
    });

    it('should use default configuration when not provided', () => {
      const defaultRecordClient = new RecordHttpClient(innerClient, undefined, mockLogger);
      expect(defaultRecordClient).toBeDefined();
    });

    it('should create recording directory on initialization', () => {
      expect(mockFs.mkdir).toHaveBeenCalledWith('/test/recordings', { recursive: true });
    });
  });

  describe('sendAsync', () => {
    it('should record successful request and response', async () => {
      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/users/123',
        headers: { 'Authorization': 'Bearer token123' }
      };

      const response = await recordClient.sendAsync(request);

      expect(response.statusCode).toBe(200);
      expect(response.body).toBe('{"success": true}');

      // Verify file was written
      expect(mockFs.writeFile).toHaveBeenCalledWith(
        expect.stringMatching(/\/test\/recordings\/recording_\d+_GET_.*\.json$/),
        expect.stringContaining('"request"'),
        'utf8'
      );

      // Verify the recorded content structure
      const writeCall = mockFs.writeFile.mock.calls[0];
      const recordedContent = JSON.parse(writeCall[1] as string);
      
      expect(recordedContent).toHaveProperty('request');
      expect(recordedContent).toHaveProperty('response');
      expect(recordedContent).toHaveProperty('timestamp');
      expect(recordedContent.request.method).toBe('GET');
      expect(recordedContent.request.url).toBe('/api/users/123');
      expect(recordedContent.response.statusCode).toBe(200);
    });

    it('should record error responses', async () => {
      // Configure mock to return error
      const errorConfig: MockHttpConfig = {
        defaultStatusCode: 404,
        defaultBody: '{"error": "Not found"}',
        defaultHeaders: { 'Content-Type': 'application/json' }
      };

      const errorInnerClient = new MockHttpClient(errorConfig, mockLogger);
      const errorRecordClient = new RecordHttpClient(errorInnerClient, undefined, mockLogger);

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/users/999'
      };

      const response = await errorRecordClient.sendAsync(request);

      expect(response.statusCode).toBe(404);
      expect(mockFs.writeFile).toHaveBeenCalled();

      const writeCall = mockFs.writeFile.mock.calls[0];
      const recordedContent = JSON.parse(writeCall[1] as string);
      expect(recordedContent.response.statusCode).toBe(404);
      expect(recordedContent.response.body).toBe('{"error": "Not found"}');
    });

    it('should sanitize URL for filename', async () => {
      const request: HttpRequest = {
        method: HttpMethod.POST,
        url: '/api/users?page=1&filter=admin',
        body: '{"test": "data"}'
      };

      await recordClient.sendAsync(request);

      expect(mockFs.writeFile).toHaveBeenCalledWith(
        expect.stringMatching(/recording_\d+_POST_api_users_page_1_filter_admin\.json$/),
        expect.any(String),
        'utf8'
      );
    });

    it('should exclude headers when includeHeaders is false', async () => {
      const configWithoutHeaders: RecordHttpConfig = {
        recordingDirectory: '/test/recordings',
        includeHeaders: false,
        prettyPrint: true
      };

      const clientWithoutHeaders = new RecordHttpClient(innerClient, configWithoutHeaders, mockLogger);

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/test',
        headers: { 'Secret': 'should-not-be-recorded' }
      };

      await clientWithoutHeaders.sendAsync(request);

      const writeCall = mockFs.writeFile.mock.calls[0];
      const recordedContent = JSON.parse(writeCall[1] as string);
      
      expect(recordedContent.request).not.toHaveProperty('headers');
      expect(recordedContent.response).not.toHaveProperty('headers');
    });

    it('should not pretty print when prettyPrint is false', async () => {
      const configWithoutPrettyPrint: RecordHttpConfig = {
        recordingDirectory: '/test/recordings',
        prettyPrint: false
      };

      const clientWithoutPrettyPrint = new RecordHttpClient(innerClient, configWithoutPrettyPrint, mockLogger);

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/test'
      };

      await clientWithoutPrettyPrint.sendAsync(request);

      const writeCall = mockFs.writeFile.mock.calls[0];
      const recordedJson = writeCall[1] as string;
      
      // Should be compact JSON (no pretty printing)
      expect(recordedJson).not.toContain('\n  ');
      expect(JSON.parse(recordedJson)).toBeDefined(); // But still valid JSON
    });

    it('should handle file write errors gracefully', async () => {
      mockFs.writeFile.mockRejectedValue(new Error('Write permission denied'));

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/test'
      };

      const response = await recordClient.sendAsync(request);

      // Should still return the response
      expect(response.statusCode).toBe(200);
      
      // Should log the error
      expect(mockLogger.error).toHaveBeenCalledWith(
        expect.stringContaining('Failed to record HTTP request'),
        expect.any(Error)
      );
    });

    it('should use custom filename template', async () => {
      const customConfig: RecordHttpConfig = {
        recordingDirectory: '/test/recordings',
        filenameTemplate: 'custom_{method}_{timestamp}.json'
      };

      const customClient = new RecordHttpClient(innerClient, customConfig, mockLogger);

      const request: HttpRequest = {
        method: HttpMethod.PUT,
        url: '/api/users/123'
      };

      await customClient.sendAsync(request);

      expect(mockFs.writeFile).toHaveBeenCalledWith(
        expect.stringMatching(/custom_PUT_\d+\.json$/),
        expect.any(String),
        'utf8'
      );
    });

    it('should pass through all data from inner client', async () => {
      const sendSpy = jest.spyOn(innerClient, 'sendAsync');

      const request: HttpRequest = {
        method: HttpMethod.POST,
        url: '/api/data',
        headers: { 'Content-Type': 'application/json' },
        body: '{"test": "data"}'
      };

      const response = await recordClient.sendAsync(request);

      expect(sendSpy).toHaveBeenCalledWith(request);
      expect(response).toEqual(expect.objectContaining({
        statusCode: 200,
        body: '{"success": true}',
        headers: expect.objectContaining({
          'Content-Type': 'application/json'
        })
      }));
    });

    it('should exclude timestamp when includeTimestamp is false', async () => {
      const configWithoutTimestamp: RecordHttpConfig = {
        recordingDirectory: '/test/recordings',
        includeTimestamp: false,
        prettyPrint: true
      };

      const clientWithoutTimestamp = new RecordHttpClient(innerClient, configWithoutTimestamp, mockLogger);

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/test'
      };

      await clientWithoutTimestamp.sendAsync(request);

      const writeCall = mockFs.writeFile.mock.calls[0];
      const recordedContent = JSON.parse(writeCall[1] as string);
      
      expect(recordedContent).not.toHaveProperty('timestamp');
    });
  });

  describe('dispose', () => {
    it('should dispose inner client', async () => {
      const disposeSpy = jest.spyOn(innerClient, 'dispose');

      await recordClient.dispose();

      expect(disposeSpy).toHaveBeenCalled();
    });

    it('should handle dispose errors gracefully', async () => {
      const errorClient: IHttpClient = {
        sendAsync: jest.fn(),
        getMode: jest.fn().mockReturnValue('mock'),
        dispose: jest.fn().mockRejectedValue(new Error('Dispose error'))
      };

      const errorRecordClient = new RecordHttpClient(errorClient, undefined, mockLogger);

      await expect(errorRecordClient.dispose()).resolves.not.toThrow();
    });
  });
});
