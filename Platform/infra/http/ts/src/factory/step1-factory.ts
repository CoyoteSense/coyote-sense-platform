/**
 * HTTP Client Factory for TypeScript - Step 1: Interfaces only
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

/**
 * Factory interface for creating HTTP clients
 */
export interface IHttpClientFactory {
  /**
   * Create HTTP client using current configured mode
   */
  createHttpClient(): CoyoteHttpClient;

  /**
   * Create HTTP client for specific mode
   */
  createHttpClientForMode(mode: RuntimeMode): CoyoteHttpClient;

  /**
   * Get the current runtime mode
   */
  getCurrentMode(): RuntimeMode;
}

export function createHttpClient(mode: RuntimeMode = RuntimeMode.REAL): CoyoteHttpClient {
  throw new Error('Not implemented yet');
}
