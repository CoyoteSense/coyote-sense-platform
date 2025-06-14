/**
 * Replay HTTP Client Tests
 * 
 * Tests for the HTTP client that replays previously recorded request/response pairs.
 */

import { ReplayHttpClient } from '../src/modes/replay/replay-http-client';
import { HttpMethod, HttpRequest, HttpResponse } from '../src/interfaces/http-client';
import { ReplayModeOptions, HttpClientOptions, DEFAULT_HTTP_OPTIONS, ReplayHttpConfig } from '../src/interfaces/configuration';
import * as fs from 'fs/promises';
import * as path from 'path';

// Mock fs module
jest.mock('fs/promises');

describe('ReplayHttpClient', () => {
  let replayClient: ReplayHttpClient;
  let mockLogger: Console;
  let mockFs: jest.Mocked<typeof fs>;

  beforeEach(() => {
    mockFs = fs as jest.Mocked<typeof fs>;
    
    mockLogger = {
      debug: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    } as any;

    const replayOptions: ReplayModeOptions = {
      recordingPath: '/test/recordings',
      strictMatching: false,
      fallbackMode: 'error'
    };

    replayClient = new ReplayHttpClient(DEFAULT_HTTP_OPTIONS, replayOptions, mockLogger);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('constructor', () => {
    it('should create replay client with configuration', () => {
      expect(replayClient).toBeDefined();
    });    it('should use default configuration when not provided', () => {
      const defaultReplayClient = new ReplayHttpClient(DEFAULT_HTTP_OPTIONS, { recordingPath: './recordings', fallbackMode: 'error', strictMatching: false }, mockLogger);
      expect(defaultReplayClient).toBeDefined();
    });
  });

  describe('loadRecordingsAsync', () => {
    it('should load recordings from directory in FIFO order', async () => {
      const recording1 = {
        request: { method: 'GET', url: '/api/users/1' },
        response: { statusCode: 200, body: '{"id": 1}', headers: {} },
        timestamp: '2024-01-01T10:00:00.000Z'
      };

      const recording2 = {
        request: { method: 'GET', url: '/api/users/2' },
        response: { statusCode: 200, body: '{"id": 2}', headers: {} },
        timestamp: '2024-01-01T10:01:00.000Z'
      };

      const recording3 = {
        request: { method: 'POST', url: '/api/users' },
        response: { statusCode: 201, body: '{"id": 3}', headers: {} },
        timestamp: '2024-01-01T10:02:00.000Z'
      };

      // Mock file listing with stats for sorting by creation time
      mockFs.readdir.mockResolvedValue([
        'recording3.json',
        'recording1.json', 
        'recording2.json'
      ] as any);      mockFs.stat.mockImplementation((filePath: any) => {
        const filename = path.basename(filePath.toString());
        if (filename === 'recording1.json') {
          return Promise.resolve({ birthtime: new Date('2024-01-01T10:00:00.000Z') } as any);
        } else if (filename === 'recording2.json') {
          return Promise.resolve({ birthtime: new Date('2024-01-01T10:01:00.000Z') } as any);
        } else if (filename === 'recording3.json') {
          return Promise.resolve({ birthtime: new Date('2024-01-01T10:02:00.000Z') } as any);
        }
        return Promise.reject(new Error('File not found'));
      });      mockFs.readFile.mockImplementation((filePath: any) => {
        const filename = path.basename(filePath.toString());
        if (filename === 'recording1.json') {
          return Promise.resolve(JSON.stringify(recording1));
        } else if (filename === 'recording2.json') {
          return Promise.resolve(JSON.stringify(recording2));
        } else if (filename === 'recording3.json') {
          return Promise.resolve(JSON.stringify(recording3));
        }
        return Promise.reject(new Error('File not found'));
      });

      await (replayClient as any).loadRecordingsAsync();

      // Verify recordings are loaded in FIFO order (oldest first)
      const recordings = (replayClient as any).recordings;
      expect(recordings).toHaveLength(3);
      expect(recordings[0].request.url).toBe('/api/users/1'); // Oldest
      expect(recordings[1].request.url).toBe('/api/users/2');
      expect(recordings[2].request.url).toBe('/api/users'); // Newest
    });

    it('should handle empty recordings directory', async () => {
      mockFs.readdir.mockResolvedValue([]);

      await (replayClient as any).loadRecordingsAsync();

      const recordings = (replayClient as any).recordings;
      expect(recordings).toHaveLength(0);
    });

    it('should skip invalid recording files', async () => {
      mockFs.readdir.mockResolvedValue(['valid.json', 'invalid.json', 'another.json'] as any);
      
      mockFs.stat.mockResolvedValue({ birthtime: new Date() } as any);      mockFs.readFile.mockImplementation((filePath: any) => {
        const filename = path.basename(filePath.toString());
        if (filename === 'valid.json') {
          return Promise.resolve(JSON.stringify({
            request: { method: 'GET', url: '/api/test' },
            response: { statusCode: 200, body: 'success', headers: {} }
          }));
        } else if (filename === 'invalid.json') {
          return Promise.resolve('invalid json content');
        } else if (filename === 'another.json') {
          return Promise.resolve(JSON.stringify({ invalid: 'structure' }));
        }
        return Promise.reject(new Error('File not found'));
      });

      await (replayClient as any).loadRecordingsAsync();

      const recordings = (replayClient as any).recordings;
      expect(recordings).toHaveLength(1); // Only valid recording loaded
      expect(recordings[0].request.url).toBe('/api/test');

      // Should log warnings for invalid files
      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.stringContaining('Failed to parse recording file'),
        expect.any(String)
      );
    });

    it('should handle directory read errors', async () => {
      mockFs.readdir.mockRejectedValue(new Error('Permission denied'));

      await (replayClient as any).loadRecordingsAsync();

      const recordings = (replayClient as any).recordings;
      expect(recordings).toHaveLength(0);

      expect(mockLogger.error).toHaveBeenCalledWith(
        expect.stringContaining('Failed to load recordings'),
        expect.any(Error)
      );
    });
  });

  describe('sendAsync', () => {
    beforeEach(async () => {
      // Setup some recordings for testing
      const recording1 = {
        request: { method: 'GET', url: '/api/users/1', headers: {} },
        response: { statusCode: 200, body: '{"id": 1, "name": "John"}', headers: { 'Content-Type': 'application/json' } }
      };

      const recording2 = {
        request: { method: 'POST', url: '/api/users', headers: { 'Content-Type': 'application/json' }, body: '{"name": "Jane"}' },
        response: { statusCode: 201, body: '{"id": 2, "name": "Jane"}', headers: { 'Content-Type': 'application/json' } }
      };

      mockFs.readdir.mockResolvedValue(['rec1.json', 'rec2.json'] as any);
      mockFs.stat.mockResolvedValue({ birthtime: new Date() } as any);      mockFs.readFile.mockImplementation((filePath: any) => {
        const filename = path.basename(filePath.toString());
        if (filename === 'rec1.json') {
          return Promise.resolve(JSON.stringify(recording1));
        } else if (filename === 'rec2.json') {
          return Promise.resolve(JSON.stringify(recording2));
        }
        return Promise.reject(new Error('File not found'));
      });

      await (replayClient as any).loadRecordingsAsync();
    });

    it('should replay recordings in FIFO order', async () => {
      // First request should get first recording
      const request1: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/users/1'
      };

      const response1 = await replayClient.sendAsync(request1);
      expect(response1.statusCode).toBe(200);
      expect(response1.body).toBe('{"id": 1, "name": "John"}');

      // Second request should get second recording
      const request2: HttpRequest = {
        method: HttpMethod.POST,
        url: '/api/users',
        body: '{"name": "Jane"}'
      };

      const response2 = await replayClient.sendAsync(request2);
      expect(response2.statusCode).toBe(201);
      expect(response2.body).toBe('{"id": 2, "name": "Jane"}');
    });

    it('should return fallback response when no more recordings', async () => {
      // Consume all recordings
      await replayClient.sendAsync({ method: HttpMethod.GET, url: '/api/users/1' });
      await replayClient.sendAsync({ method: HttpMethod.POST, url: '/api/users' });

      // Third request should get fallback
      const request3: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/users/3'
      };

      const response3 = await replayClient.sendAsync(request3);
      expect(response3.statusCode).toBe(404);
      expect(response3.body).toBe('Recording not found');
      expect(response3.headers['Content-Type']).toBe('text/plain');
    });

    it('should handle strict matching mode', async () => {
      const strictConfig: ReplayHttpConfig = {
        recordingDirectory: '/test/recordings',
        strictMatching: true,
        fallbackResponse: {
          statusCode: 400,
          body: 'No matching recording found',
          headers: {}
        }
      };

      const strictClient = new ReplayHttpClient(strictConfig, mockLogger);
      
      // Mock the same recordings
      mockFs.readdir.mockResolvedValue(['rec1.json'] as any);
      mockFs.stat.mockResolvedValue({ birthtime: new Date() } as any);
      mockFs.readFile.mockResolvedValue(JSON.stringify({
        request: { method: 'GET', url: '/api/users/1', headers: { 'Authorization': 'Bearer token' } },
        response: { statusCode: 200, body: 'success', headers: {} }
      }));

      await (strictClient as any).loadRecordingsAsync();

      // Request without matching headers should get fallback in strict mode
      const mismatchRequest: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/users/1',
        headers: { 'Authorization': 'Bearer different-token' }
      };

      const response = await strictClient.sendAsync(mismatchRequest);
      expect(response.statusCode).toBe(400);
      expect(response.body).toBe('No matching recording found');
    });

    it('should use default fallback when not configured', async () => {
      const clientWithoutFallback = new ReplayHttpClient({
        recordingDirectory: '/test/recordings'
      }, mockLogger);

      // No recordings loaded
      mockFs.readdir.mockResolvedValue([]);
      await (clientWithoutFallback as any).loadRecordingsAsync();

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/test'
      };      const response = await clientWithoutFallback.sendAsync(request);
      expect(response.statusCode).toBe(404);
      expect(response.body).toContain('Recording not found');
    });

    it('should match requests ignoring case and whitespace in non-strict mode', async () => {
      // Setup recording with specific format
      mockFs.readdir.mockResolvedValue(['test.json'] as any);
      mockFs.stat.mockResolvedValue({ birthtime: new Date() } as any);
      mockFs.readFile.mockResolvedValue(JSON.stringify({
        request: { method: 'get', url: '/api/Users/1' },
        response: { statusCode: 200, body: 'found', headers: {} }
      }));

      const flexibleClient = new ReplayHttpClient({
        recordingDirectory: '/test/recordings',
        strictMatching: false
      }, mockLogger);

      await (flexibleClient as any).loadRecordingsAsync();

      // Request with different case should still match
      const request: HttpRequest = {
        method: HttpMethod.GET, // Uppercase
        url: '/api/users/1' // Lowercase
      };

      const response = await flexibleClient.sendAsync(request);
      expect(response.statusCode).toBe(200);
      expect(response.body).toBe('found');
    });
  });

  describe('dispose', () => {
    it('should dispose without error', async () => {
      await expect(replayClient.dispose()).resolves.not.toThrow();
    });

    it('should clear recordings on dispose', async () => {
      // Load some recordings first
      mockFs.readdir.mockResolvedValue(['test.json'] as any);
      mockFs.stat.mockResolvedValue({ birthtime: new Date() } as any);
      mockFs.readFile.mockResolvedValue(JSON.stringify({
        request: { method: 'GET', url: '/test' },
        response: { statusCode: 200, body: 'test', headers: {} }
      }));

      await (replayClient as any).loadRecordingsAsync();
      expect((replayClient as any).recordings).toHaveLength(1);

      await replayClient.dispose();
      expect((replayClient as any).recordings).toHaveLength(0);
    });
  });
});
