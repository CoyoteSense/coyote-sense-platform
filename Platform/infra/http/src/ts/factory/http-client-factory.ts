/**
 * HTTP Client Factory for TypeScript
 * 
 * This module provides a factory for creating HTTP clients based on runtime mode
 * with dependency injection support.
 */

import { HttpClient, CoyoteHttpClient } from '../interfaces/http-client.js';
import { 
  RuntimeMode, 
  HttpClientConfig, 
  HttpClientOptions, 
  HttpClientModeOptions,
  DEFAULT_HTTP_OPTIONS,
  DEFAULT_MOCK_OPTIONS,
  DEFAULT_RECORD_OPTIONS,
  DEFAULT_REPLAY_OPTIONS,
  DEFAULT_SIMULATION_OPTIONS,
  DEFAULT_DEBUG_OPTIONS
} from '../interfaces/configuration.js';

import { RealHttpClient } from '../modes/real/real-http-client.js';
import { MockHttpClient } from '../modes/mock/mock-http-client.js';
import { DebugHttpClient } from '../modes/debug/debug-http-client.js';
import { RecordHttpClient } from '../modes/record/record-http-client.js';
import { ReplayHttpClient } from '../modes/replay/replay-http-client.js';
import { SimulationHttpClient } from '../modes/simulation/simulation-http-client.js';

/**
 * Factory interface for creating HTTP clients
 */
export interface IHttpClientFactory {
  /**
   * Create HTTP client using current configured mode
   */
  createClient(): CoyoteHttpClient;

  /**
   * Create HTTP client for specific mode
   */
  createHttpClientForMode(mode: RuntimeMode): CoyoteHttpClient;

  /**
   * Get the current runtime mode
   */
  getCurrentMode(): RuntimeMode;
}

/**
 * Default implementation of HTTP client factory
 */
export class HttpClientFactory implements IHttpClientFactory {
  private readonly httpOptions: HttpClientOptions;
  private readonly modeOptions: HttpClientModeOptions;
  private readonly logger: Console;

  constructor(config?: Partial<HttpClientConfig>, logger?: Console) {
    this.logger = logger || console;
    
    // Merge provided config with defaults
    this.httpOptions = { ...DEFAULT_HTTP_OPTIONS, ...config?.http };
    this.modeOptions = {
      mode: config?.mode?.mode || RuntimeMode.REAL,
      mock: { ...DEFAULT_MOCK_OPTIONS, ...config?.mode?.mock },
      record: { ...DEFAULT_RECORD_OPTIONS, ...config?.mode?.record },
      replay: { ...DEFAULT_REPLAY_OPTIONS, ...config?.mode?.replay },
      simulation: { ...DEFAULT_SIMULATION_OPTIONS, ...config?.mode?.simulation },
      debug: { ...DEFAULT_DEBUG_OPTIONS, ...config?.mode?.debug },
    };
  }

  createClient(): CoyoteHttpClient {
    return this.createHttpClientForMode(this.getCurrentMode());
  }

  createHttpClientForMode(mode: RuntimeMode): CoyoteHttpClient {
    this.logger.debug?.(`Creating HTTP client for mode: ${mode}`);
    
    switch (mode) {
      case RuntimeMode.REAL:
      case RuntimeMode.PRODUCTION:
        return new RealHttpClient(this.httpOptions, this.logger);

      case RuntimeMode.MOCK:
      case RuntimeMode.TESTING:
        return new MockHttpClient(this.httpOptions, this.modeOptions.mock, this.logger);

      case RuntimeMode.DEBUG:
        return new DebugHttpClient(this.httpOptions, this.modeOptions.debug, this.logger);

      case RuntimeMode.RECORD:
        return new RecordHttpClient(this.httpOptions, this.modeOptions.record, this.logger);

      case RuntimeMode.REPLAY:
        return new ReplayHttpClient(this.httpOptions, this.modeOptions.replay, this.logger);

      case RuntimeMode.SIMULATION:
        return new SimulationHttpClient(this.httpOptions, this.modeOptions.simulation, this.logger);

      default:
        this.logger.warn?.(`Unknown mode ${mode}, falling back to RealHttpClient`);
        return new RealHttpClient(this.httpOptions, this.logger);
    }
  }

  getCurrentMode(): RuntimeMode {
    // Check environment variables first
    const envMode = process.env.COYOTE_RUNTIME_MODE || process.env.MODE || process.env.NODE_ENV;
    
    if (envMode) {
      // Map common Node.js environment values
      const normalizedMode = this.normalizeEnvironmentMode(envMode);
      if (Object.values(RuntimeMode).includes(normalizedMode as RuntimeMode)) {
        return normalizedMode as RuntimeMode;
      }
    }

    // Fall back to configuration
    return this.modeOptions.mode;
  }

  private normalizeEnvironmentMode(envMode: string): string {
    const mode = envMode.toLowerCase();
    
    // Map common environment values to runtime modes
    switch (mode) {
      case 'prod':
      case 'production':
        return RuntimeMode.PRODUCTION;
      case 'dev':
      case 'development':
        return RuntimeMode.DEBUG;
      case 'test':
      case 'testing':
        return RuntimeMode.TESTING;
      default:
        return mode;
    }
  }
}

/**
 * Dependency injection container for HTTP client infrastructure
 */
export class HttpClientContainer {
  private readonly factory: IHttpClientFactory;
  private readonly logger: Console;

  constructor(config?: Partial<HttpClientConfig>, logger?: Console) {
    this.logger = logger || console;
    this.factory = new HttpClientFactory(config, this.logger);
  }

  /**
   * Get the HTTP client factory
   */
  getFactory(): IHttpClientFactory {
    return this.factory;
  }

  /**
   * Get a configured HTTP client instance
   */
  getHttpClient(): CoyoteHttpClient {
    return this.factory.createClient();
  }

  /**
   * Get HTTP client for specific mode
   */
  getHttpClientForMode(mode: RuntimeMode): CoyoteHttpClient {
    return this.factory.createHttpClientForMode(mode);
  }
}

/**
 * Create a pre-configured HTTP client container
 */
export function createHttpClientContainer(config?: Partial<HttpClientConfig>, logger?: Console): HttpClientContainer {
  return new HttpClientContainer(config, logger);
}

/**
 * Create a simple HTTP client with minimal configuration
 */
export function createClient(mode: RuntimeMode = RuntimeMode.REAL, logger?: Console): CoyoteHttpClient {
  const config: Partial<HttpClientConfig> = {
    mode: { mode } as HttpClientModeOptions
  };
  
  const container = createHttpClientContainer(config, logger);
  return container.getHttpClient();
}
