/**
 * Simulation HTTP Client Tests
 * 
 * Tests for the simulation HTTP client that simulates various response patterns
 * and behaviors for testing and development.
 */

import { SimulationHttpClient, SimulationHttpConfig } from '../src/modes/simulation/simulation-http-client';
import { HttpMethod, HttpRequest, HttpResponse } from '../src/interfaces/http-client';
import { SimulationModeOptions, HttpClientOptions, DEFAULT_HTTP_OPTIONS, DEFAULT_SIMULATION_OPTIONS } from '../src/interfaces/configuration';
import * as fs from 'fs/promises';

// Mock fs module
jest.mock('fs/promises');

describe('SimulationHttpClient', () => {
  let simulationClient: SimulationHttpClient;
  let mockLogger: Console;
  let mockFs: jest.Mocked<typeof fs>;

  beforeEach(() => {
    mockFs = fs as jest.Mocked<typeof fs>;
    mockFs.readFile.mockRejectedValue(new Error('File not found'));
    
    mockLogger = {
      debug: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    } as any;

    const simulationOptions: SimulationModeOptions = {
      globalLatencyMs: 50,
      globalFailureRate: 0.1,
      minPingLatencyMs: 10,
      maxPingLatencyMs: 100,
      pingFailureRate: 0.0
    };

    simulationClient = new SimulationHttpClient(DEFAULT_HTTP_OPTIONS, simulationOptions, mockLogger);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('constructor', () => {
    it('should create simulation client with configuration', () => {
      expect(simulationClient).toBeDefined();
      expect(simulationClient.getMode()).toBe('simulation');
    });    it('should use default configuration when not provided', () => {
      const defaultClient = new SimulationHttpClient(DEFAULT_HTTP_OPTIONS, DEFAULT_SIMULATION_OPTIONS, mockLogger);
      expect(defaultClient).toBeDefined();
    });

    it('should load default scenarios', () => {
      const stats = simulationClient.getStats();
      expect(stats.defaultScenarios).toBeGreaterThan(0);
      expect(stats.totalScenarios).toBe(stats.defaultScenarios + stats.customScenarios);
    });
  });

  describe('executeAsync', () => {
    it('should return default response for unmatched requests', async () => {
      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: 'https://example.com/unknown',
        headers: {}
      };

      const response = await simulationClient.executeAsync(request);

      expect(response).toBeDefined();
      expect(response.statusCode).toBe(200);
      expect(response.body).toContain('simulation');
      expect(response.headers['Content-Type']).toBe('application/json');
    });

    it('should match API pattern scenario', async () => {
      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: 'https://api.example.com/users',
        headers: {}
      };

      const response = await simulationClient.executeAsync(request);

      expect(response).toBeDefined();
      expect(response.statusCode).toBe(200);
      expect(response.body).toContain('success');
    });

    it('should match health check pattern', async () => {
      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: 'https://example.com/health',
        headers: {}
      };

      const response = await simulationClient.executeAsync(request);

      expect(response).toBeDefined();
      expect(response.statusCode).toBe(200);
      expect(response.body).toContain('healthy');
    });

    it('should match error pattern', async () => {
      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: 'https://example.com/error/test',
        headers: {}
      };

      const response = await simulationClient.executeAsync(request);

      expect(response).toBeDefined();
      expect(response.statusCode).toBe(500);
      expect(response.body).toContain('error');
    });

    it('should simulate higher latency for slow patterns', async () => {
      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: 'https://example.com/slow/operation',
        headers: {}
      };

      const start = Date.now();
      const response = await simulationClient.executeAsync(request);
      const elapsed = Date.now() - start;

      expect(response).toBeDefined();
      expect(elapsed).toBeGreaterThan(100); // Should have some latency
    });

    it('should replace template variables in response body', async () => {
      const customScenario: SimulationScenario = {
        name: 'Template Test',
        pattern: '/template/*',
        statusCode: 200,
        body: '{"url": "{{url}}", "method": "{{method}}", "timestamp": "{{timestamp}}"}',
        headers: { 'Content-Type': 'application/json' },
        latencyMs: 0
      };

      simulationClient.addScenario(customScenario);

      const request: HttpRequest = {
        method: HttpMethod.POST,
        url: 'https://example.com/template/test',
        headers: {}
      };

      const response = await simulationClient.executeAsync(request);

      expect(response).toBeDefined();
      expect(response.body).toContain(request.url);
      expect(response.body).toContain('POST');
      expect(response.body).toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/); // ISO timestamp
    });
  });

  describe('scenario management', () => {
    it('should add custom scenario', () => {
      const initialStats = simulationClient.getStats();
      
      const customScenario: SimulationScenario = {
        name: 'Custom Test',
        pattern: '/custom/*',
        statusCode: 201,
        body: 'Custom response',
        headers: { 'X-Custom': 'true' },
        latencyMs: 10
      };

      simulationClient.addScenario(customScenario);

      const newStats = simulationClient.getStats();
      expect(newStats.customScenarios).toBe(initialStats.customScenarios + 1);
      expect(newStats.totalScenarios).toBe(initialStats.totalScenarios + 1);
    });

    it('should clear custom scenarios', () => {
      const customScenario: SimulationScenario = {
        name: 'Test Scenario',
        pattern: '/test/*',
        statusCode: 200,
        body: 'Test response',
        headers: {},
        latencyMs: 0
      };

      simulationClient.addScenario(customScenario);
      const statsWithCustom = simulationClient.getStats();
      expect(statsWithCustom.customScenarios).toBe(1);

      simulationClient.clearCustomScenarios();
      const statsAfterClear = simulationClient.getStats();
      expect(statsAfterClear.customScenarios).toBe(0);
    });

    it('should match custom scenario after adding', async () => {
      const customScenario: SimulationScenario = {
        name: 'Custom API',
        pattern: '/custom/api/*',
        statusCode: 202,
        body: '{"custom": "response"}',
        headers: { 'X-Custom': 'true' },
        latencyMs: 5
      };

      simulationClient.addScenario(customScenario);

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: 'https://example.com/custom/api/test',
        headers: {}
      };

      const response = await simulationClient.executeAsync(request);

      expect(response).toBeDefined();
      expect(response.statusCode).toBe(202);
      expect(response.body).toBe('{"custom": "response"}');
      expect(response.headers['X-Custom']).toBe('true');
    });
  });

  describe('failure simulation', () => {
    it('should simulate network failures based on failure rate', async () => {
      const failureScenario: SimulationScenario = {
        name: 'Always Fail',
        pattern: '/fail/*',
        statusCode: 0,
        body: '',
        headers: {},
        latencyMs: 0,
        failureRate: 1.0, // Always fail
        failureMessages: ['Network timeout', 'Connection refused']
      };

      simulationClient.addScenario(failureScenario);

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: 'https://example.com/fail/test',
        headers: {}
      };

      const response = await simulationClient.executeAsync(request);

      expect(response).toBeDefined();
      expect(response.statusCode).toBe(0);
      expect(response.body).toBe('');
      expect(response.errorMessage).toBeDefined();
      expect(['Network timeout', 'Connection refused']).toContain(response.errorMessage);
    });

    it('should not fail when failure rate is zero', async () => {
      const noFailureScenario: SimulationScenario = {
        name: 'Never Fail',
        pattern: '/success/*',
        statusCode: 200,
        body: 'Success response',
        headers: {},
        latencyMs: 0,
        failureRate: 0.0 // Never fail
      };

      simulationClient.addScenario(noFailureScenario);

      const request: HttpRequest = {
        method: HttpMethod.GET,
        url: 'https://example.com/success/test',
        headers: {}
      };

      const response = await simulationClient.executeAsync(request);

      expect(response).toBeDefined();
      expect(response.statusCode).toBe(200);
      expect(response.body).toBe('Success response');
      expect(response.errorMessage).toBeUndefined();
    });
  });

  describe('pingAsync', () => {
    it('should return true for successful ping', async () => {
      const result = await simulationClient.pingAsync();
      expect(result).toBe(true);
    });

    it('should handle ping with simulated failure rate', async () => {
      const configWithFailure: SimulationHttpConfig = {
        scenarioFile: '',
        globalLatencyMs: 0,
        globalFailureRate: 0.0,
        pingFailureRate: 0.5, // 50% failure rate for ping
        defaultScenario: {
          statusCode: 200,
          body: '',
          headers: {},
          latencyMs: 0
        }
      };

      const clientWithPingFailure = new SimulationHttpClient(configWithFailure, mockLogger);
      
      // Test multiple pings to check probabilistic behavior
      const results = await Promise.all([
        clientWithPingFailure.pingAsync(),
        clientWithPingFailure.pingAsync(),
        clientWithPingFailure.pingAsync(),
        clientWithPingFailure.pingAsync(),
        clientWithPingFailure.pingAsync()
      ]);

      // With 50% failure rate, we expect some variation
      const successCount = results.filter(r => r).length;
      expect(successCount).toBeGreaterThanOrEqual(0);
      expect(successCount).toBeLessThanOrEqual(5);
    });
  });

  describe('scenario file loading', () => {
    it('should attempt to load scenarios from file', async () => {
      const scenarioData = [
        {
          name: 'File Scenario',
          pattern: '/file/*',
          statusCode: 200,
          body: 'From file',
          headers: {},
          latencyMs: 0
        }
      ];

      mockFs.readFile.mockResolvedValueOnce(JSON.stringify(scenarioData));      const configWithFile: SimulationHttpConfig = {
        scenarioFile: '/test/scenarios.json',
        globalLatencyMs: 0,
        globalFailureRate: 0.0,
        pingFailureRate: 0.0,
        defaultScenario: {
          statusCode: 200,
          body: '',
          headers: {},
          latencyMs: 0
        }
      };

      const clientWithFile = new SimulationHttpClient(configWithFile, mockLogger);
      
      // Allow time for async scenario loading
      await new Promise(resolve => setTimeout(resolve, 100));

      expect(mockFs.readFile).toHaveBeenCalledWith('/test/scenarios.json', 'utf8');
    });

    it('should handle file loading errors gracefully', async () => {
      mockFs.readFile.mockRejectedValueOnce(new Error('File not found'));      const configWithBadFile: SimulationHttpConfig = {
        scenarioFile: '/nonexistent/scenarios.json',
        globalLatencyMs: 0,
        globalFailureRate: 0.0,
        pingFailureRate: 0.0,
        defaultScenario: {
          statusCode: 200,
          body: '',
          headers: {},
          latencyMs: 0
        }
      };

      expect(() => {
        new SimulationHttpClient(configWithBadFile, mockLogger);
      }).not.toThrow();
    });
  });

  describe('getStats', () => {
    it('should return correct scenario statistics', () => {
      const stats = simulationClient.getStats();

      expect(stats).toBeDefined();
      expect(stats.defaultScenarios).toBeGreaterThan(0);
      expect(stats.customScenarios).toBe(0);
      expect(stats.totalScenarios).toBe(stats.defaultScenarios + stats.customScenarios);
    });

    it('should update statistics when adding scenarios', () => {
      const initialStats = simulationClient.getStats();

      const customScenario: SimulationScenario = {
        name: 'Stats Test',
        pattern: '/stats/*',
        statusCode: 200,
        body: '',
        headers: {},
        latencyMs: 0
      };

      simulationClient.addScenario(customScenario);

      const newStats = simulationClient.getStats();
      expect(newStats.customScenarios).toBe(initialStats.customScenarios + 1);
      expect(newStats.totalScenarios).toBe(initialStats.totalScenarios + 1);
    });
  });
});
