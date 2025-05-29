/**
 * HTTP Client Factory Tests
 * 
 * Tests for the HTTP client factory functionality including mode detection,
 * client creation, and dependency injection container.
 */

import { HttpClientFactory, HttpClientContainer, createHttpClient, createHttpClientContainer } from '../src/factory/http-client-factory';
import { RuntimeMode, HttpClientConfig, DEFAULT_HTTP_OPTIONS } from '../src/interfaces/configuration';
import { RealHttpClient } from '../src/modes/real/real-http-client';
import { MockHttpClient } from '../src/modes/mock/mock-http-client';
import { DebugHttpClient } from '../src/modes/debug/debug-http-client';
import { RecordHttpClient } from '../src/modes/record/record-http-client';
import { ReplayHttpClient } from '../src/modes/replay/replay-http-client';
import { SimulationHttpClient } from '../src/modes/simulation/simulation-http-client';

describe('HttpClientFactory', () => {
  let factory: HttpClientFactory;
  let mockLogger: Console;

  beforeEach(() => {
    mockLogger = {
      debug: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    } as any;
    
    // Clear environment variables
    delete process.env.COYOTE_RUNTIME_MODE;
    delete process.env.MODE;
    delete process.env.NODE_ENV;
  });

  describe('constructor', () => {
    it('should create factory with default configuration', () => {
      factory = new HttpClientFactory(undefined, mockLogger);
      
      expect(factory).toBeDefined();
      expect(factory.getCurrentMode()).toBe(RuntimeMode.REAL);
    });

    it('should create factory with custom configuration', () => {
      const config: Partial<HttpClientConfig> = {
        mode: {
          mode: RuntimeMode.TESTING,
          mock: {
            defaultStatusCode: 201,
            defaultBody: 'custom body',
            defaultHeaders: { 'Custom': 'header' },
            simulateLatencyMs: 200,
          },
        } as any,
      };

      factory = new HttpClientFactory(config, mockLogger);
      
      expect(factory.getCurrentMode()).toBe(RuntimeMode.TESTING);
    });
  });

  describe('createHttpClientForMode', () => {
    beforeEach(() => {
      factory = new HttpClientFactory(undefined, mockLogger);
    });

    it('should create RealHttpClient for REAL mode', () => {
      const client = factory.createHttpClientForMode(RuntimeMode.REAL);
      expect(client).toBeInstanceOf(RealHttpClient);
    });

    it('should create RealHttpClient for PRODUCTION mode', () => {
      const client = factory.createHttpClientForMode(RuntimeMode.PRODUCTION);
      expect(client).toBeInstanceOf(RealHttpClient);
    });

    it('should create MockHttpClient for MOCK mode', () => {
      const client = factory.createHttpClientForMode(RuntimeMode.MOCK);
      expect(client).toBeInstanceOf(MockHttpClient);
    });

    it('should create MockHttpClient for TESTING mode', () => {
      const client = factory.createHttpClientForMode(RuntimeMode.TESTING);
      expect(client).toBeInstanceOf(MockHttpClient);
    });

    it('should create DebugHttpClient for DEBUG mode', () => {
      const client = factory.createHttpClientForMode(RuntimeMode.DEBUG);
      expect(client).toBeInstanceOf(DebugHttpClient);
    });

    it('should create RecordHttpClient for RECORD mode', () => {
      const client = factory.createHttpClientForMode(RuntimeMode.RECORD);
      expect(client).toBeInstanceOf(RecordHttpClient);
    });

    it('should create ReplayHttpClient for REPLAY mode', () => {
      const client = factory.createHttpClientForMode(RuntimeMode.REPLAY);
      expect(client).toBeInstanceOf(ReplayHttpClient);
    });

    it('should create SimulationHttpClient for SIMULATION mode', () => {
      const client = factory.createHttpClientForMode(RuntimeMode.SIMULATION);
      expect(client).toBeInstanceOf(SimulationHttpClient);
    });

    it('should fallback to RealHttpClient for unknown mode', () => {
      const client = factory.createHttpClientForMode('unknown' as RuntimeMode);
      expect(client).toBeInstanceOf(RealHttpClient);
      expect(mockLogger.warn).toHaveBeenCalledWith(
        'Unknown mode unknown, falling back to RealHttpClient'
      );
    });

    it('should log debug message when creating client', () => {
      factory.createHttpClientForMode(RuntimeMode.MOCK);
      expect(mockLogger.debug).toHaveBeenCalledWith('Creating HTTP client for mode: mock');
    });
  });

  describe('getCurrentMode', () => {
    beforeEach(() => {
      factory = new HttpClientFactory(undefined, mockLogger);
    });

    it('should return configured mode when no environment variables', () => {
      const config: Partial<HttpClientConfig> = {
        mode: { mode: RuntimeMode.DEBUG } as any,
      };
      
      factory = new HttpClientFactory(config, mockLogger);
      expect(factory.getCurrentMode()).toBe(RuntimeMode.DEBUG);
    });

    it('should prioritize COYOTE_RUNTIME_MODE environment variable', () => {
      process.env.COYOTE_RUNTIME_MODE = 'testing';
      expect(factory.getCurrentMode()).toBe(RuntimeMode.TESTING);
    });

    it('should use MODE environment variable as fallback', () => {
      process.env.MODE = 'simulation';
      expect(factory.getCurrentMode()).toBe(RuntimeMode.SIMULATION);
    });

    it('should use NODE_ENV environment variable as last resort', () => {
      process.env.NODE_ENV = 'production';
      expect(factory.getCurrentMode()).toBe(RuntimeMode.PRODUCTION);
    });

    it('should normalize common environment values', () => {
      process.env.NODE_ENV = 'development';
      expect(factory.getCurrentMode()).toBe(RuntimeMode.DEBUG);

      process.env.NODE_ENV = 'test';
      expect(factory.getCurrentMode()).toBe(RuntimeMode.TESTING);

      process.env.NODE_ENV = 'prod';
      expect(factory.getCurrentMode()).toBe(RuntimeMode.PRODUCTION);
    });

    it('should fallback to configured mode for invalid environment value', () => {
      process.env.COYOTE_RUNTIME_MODE = 'invalid-mode';
      
      const config: Partial<HttpClientConfig> = {
        mode: { mode: RuntimeMode.MOCK } as any,
      };
      
      factory = new HttpClientFactory(config, mockLogger);
      expect(factory.getCurrentMode()).toBe(RuntimeMode.MOCK);
    });
  });

  describe('createHttpClient', () => {
    it('should create client using current mode', () => {
      const config: Partial<HttpClientConfig> = {
        mode: { mode: RuntimeMode.TESTING } as any,
      };
      
      factory = new HttpClientFactory(config, mockLogger);
      const client = factory.createHttpClient();
      
      expect(client).toBeInstanceOf(MockHttpClient);
    });
  });
});

describe('HttpClientContainer', () => {
  let container: HttpClientContainer;
  let mockLogger: Console;

  beforeEach(() => {
    mockLogger = {
      debug: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    } as any;
  });

  describe('constructor', () => {
    it('should create container with default configuration', () => {
      container = new HttpClientContainer(undefined, mockLogger);
      expect(container).toBeDefined();
    });

    it('should create container with custom configuration', () => {
      const config: Partial<HttpClientConfig> = {
        mode: { mode: RuntimeMode.SIMULATION } as any,
      };
      
      container = new HttpClientContainer(config, mockLogger);
      expect(container).toBeDefined();
    });
  });

  describe('methods', () => {
    beforeEach(() => {
      container = new HttpClientContainer(undefined, mockLogger);
    });

    it('should return factory instance', () => {
      const factory = container.getFactory();
      expect(factory).toBeDefined();
      expect(typeof factory.createHttpClient).toBe('function');
    });

    it('should return HTTP client instance', () => {
      const client = container.getHttpClient();
      expect(client).toBeDefined();
      expect(typeof client.executeAsync).toBe('function');
    });

    it('should return HTTP client for specific mode', () => {
      const client = container.getHttpClientForMode(RuntimeMode.MOCK);
      expect(client).toBeInstanceOf(MockHttpClient);
    });
  });
});

describe('Convenience functions', () => {
  let mockLogger: Console;

  beforeEach(() => {
    mockLogger = {
      debug: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    } as any;
  });

  describe('createHttpClientContainer', () => {
    it('should create container with default configuration', () => {
      const container = createHttpClientContainer(undefined, mockLogger);
      expect(container).toBeInstanceOf(HttpClientContainer);
    });    it('should create container with custom configuration', () => {
      const config: Partial<HttpClientConfig> = {
        http: { 
          ...DEFAULT_HTTP_OPTIONS,
          defaultTimeoutMs: 5000 
        },
      };
      
      const container = createHttpClientContainer(config, mockLogger);
      expect(container).toBeInstanceOf(HttpClientContainer);
    });
  });

  describe('createHttpClient', () => {
    it('should create client with default mode (REAL)', () => {
      const client = createHttpClient(undefined, mockLogger);
      expect(client).toBeInstanceOf(RealHttpClient);
    });

    it('should create client with specified mode', () => {
      const client = createHttpClient(RuntimeMode.MOCK, mockLogger);
      expect(client).toBeInstanceOf(MockHttpClient);
    });
  });
});
