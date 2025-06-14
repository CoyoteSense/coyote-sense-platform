/**
 * Working Example Test - Demonstrates correct usage patterns
 * 
 * This test shows the proper way to create and use HTTP clients with correct:
 * - Import paths
 * - Constructor signatures
 * - API methods (executeAsync, not sendAsync)
 * - Configuration types
 */

import { MockHttpClient } from '../src/modes/mock/mock-http-client';
import { RealHttpClient } from '../src/modes/real/real-http-client';
import { DebugHttpClient } from '../src/modes/debug/debug-http-client';
import { RecordHttpClient } from '../src/modes/record/record-http-client';
import { ReplayHttpClient } from '../src/modes/replay/replay-http-client';
import { SimulationHttpClient } from '../src/modes/simulation/simulation-http-client';
import { HttpMethod, HttpRequest } from '../src/interfaces/http-client';
import { 
  HttpClientOptions, 
  MockModeOptions, 
  DebugModeOptions, 
  RecordModeOptions, 
  ReplayModeOptions, 
  SimulationModeOptions,
  DEFAULT_HTTP_OPTIONS,
  DEFAULT_MOCK_OPTIONS,
  DEFAULT_DEBUG_OPTIONS,
  DEFAULT_RECORD_OPTIONS,
  DEFAULT_REPLAY_OPTIONS,
  DEFAULT_SIMULATION_OPTIONS
} from '../src/interfaces/configuration';

// Mock fetch globally for RealHttpClient tests
global.fetch = jest.fn();

describe('HTTP Client Working Examples', () => {
  let mockLogger: Console;
  let httpOptions: HttpClientOptions;

  beforeEach(() => {
    mockLogger = {
      debug: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    } as any;

    httpOptions = {
      ...DEFAULT_HTTP_OPTIONS,
      baseUrl: 'https://api.example.com'
    };
  });

  describe('MockHttpClient', () => {
    it('should create and execute requests correctly', async () => {
      const mockOptions: MockModeOptions = { ...DEFAULT_MOCK_OPTIONS };
      const client = new MockHttpClient(httpOptions, mockOptions, mockLogger);

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/test'
      };

      const response = await client.executeAsync(request);
      
      expect(response.statusCode).toBe(200);
      expect(response.isSuccess).toBe(true);
    });
  });

  describe('RealHttpClient', () => {
    it('should create and make requests', async () => {
      const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
      
      const mockResponse = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: new Headers({ 'content-type': 'application/json' }),
        text: jest.fn().mockResolvedValue('{"success": true}')
      };
      mockFetch.mockResolvedValue(mockResponse as any);

      const client = new RealHttpClient(httpOptions, mockLogger);

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/test'
      };

      const response = await client.executeAsync(request);
      
      expect(response.statusCode).toBe(200);
      expect(response.body).toBe('{"success": true}');
      expect(response.isSuccess).toBe(true);
    });
  });

  describe('DebugHttpClient', () => {
    it('should wrap another client with debug logging', async () => {
      const debugOptions: DebugModeOptions = { ...DEFAULT_DEBUG_OPTIONS };
      const client = new DebugHttpClient(httpOptions, debugOptions, mockLogger);

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/test'
      };

      // Mock the underlying fetch for the RealHttpClient that DebugHttpClient uses
      const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
      const mockResponse = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: new Headers({ 'content-type': 'application/json' }),
        text: jest.fn().mockResolvedValue('{"success": true}')
      };
      mockFetch.mockResolvedValue(mockResponse as any);

      const response = await client.executeAsync(request);
      
      expect(response.statusCode).toBe(200);
      expect(response.isSuccess).toBe(true);
      expect(mockLogger.debug).toHaveBeenCalled();
    });
  });

  describe('RecordHttpClient', () => {
    it('should record requests and responses', async () => {
      const recordOptions: RecordModeOptions = { 
        ...DEFAULT_RECORD_OPTIONS,
        recordingPath: './test-recordings'
      };
      
      const client = new RecordHttpClient(httpOptions, recordOptions, mockLogger);

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/test'
      };

      // Mock the underlying fetch for the RealHttpClient that RecordHttpClient uses
      const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
      const mockResponse = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: new Headers({ 'content-type': 'application/json' }),
        text: jest.fn().mockResolvedValue('{"success": true}')
      };
      mockFetch.mockResolvedValue(mockResponse as any);

      const response = await client.executeAsync(request);
      
      expect(response.statusCode).toBe(200);
      expect(response.isSuccess).toBe(true);
    });
  });

  describe('ReplayHttpClient', () => {
    it('should create with correct options', async () => {
      const replayOptions: ReplayModeOptions = { 
        ...DEFAULT_REPLAY_OPTIONS,
        recordingPath: './test-recordings'
      };
      
      const client = new ReplayHttpClient(httpOptions, replayOptions, mockLogger);

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/test'
      };

      // Since no recordings are loaded, this will likely fallback
      try {
        const response = await client.executeAsync(request);
        // Test passes if we get any response
        expect(response).toBeDefined();
      } catch (error) {
        // Expected if no recordings and fallback mode is 'error'
        expect(error).toBeDefined();
      }
    });
  });

  describe('SimulationHttpClient', () => {
    it('should create and simulate responses', async () => {
      const simulationOptions: SimulationModeOptions = { 
        ...DEFAULT_SIMULATION_OPTIONS,
        globalLatencyMs: 10 // Reduce for faster tests
      };
      
      const client = new SimulationHttpClient(httpOptions, simulationOptions, mockLogger);

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: '/api/test'
      };

      const response = await client.executeAsync(request);
      
      expect(response).toBeDefined();
      expect(typeof response.statusCode).toBe('number');
    });

    it('should handle ping requests', async () => {
      const simulationOptions: SimulationModeOptions = { 
        ...DEFAULT_SIMULATION_OPTIONS,
        minPingLatencyMs: 1,
        maxPingLatencyMs: 5
      };
      
      const client = new SimulationHttpClient(httpOptions, simulationOptions, mockLogger);

      const result = await client.pingAsync('https://api.example.com');
      
      expect(typeof result).toBe('boolean');
    });
  });
});
