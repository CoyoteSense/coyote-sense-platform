/**
 * Coyote HTTP Client Infrastructure for TypeScript
 * 
 * Main entry point for the HTTP client library providing mode-based HTTP clients
 * with dependency injection, configuration support, and comprehensive testing capabilities.
 */

// Core interfaces and types
export * from './src/interfaces/http-client.js';
export * from './src/interfaces/configuration.js';
export * from './src/interfaces/base-http-client.js';

// Factory and container
export { 
  IHttpClientFactory, 
  HttpClientFactory, 
  HttpClientContainer, 
  createHttpClientContainer, 
  createHttpClient 
} from './src/factory/http-client-factory';

// Mode implementations
export { RealHttpClient } from './src/modes/real/real-http-client';
export { MockHttpClient } from './src/modes/mock/mock-http-client';
export { DebugHttpClient } from './src/modes/debug/debug-http-client';
export { RecordHttpClient } from './src/modes/record/record-http-client';
export { ReplayHttpClient } from './src/modes/replay/replay-http-client';
export { SimulationHttpClient } from './src/modes/simulation/simulation-http-client';
