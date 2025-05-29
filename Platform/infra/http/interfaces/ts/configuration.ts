/**
 * Configuration interfaces for HTTP client
 */

export enum RuntimeMode {
  PRODUCTION = 'production',
  REAL = 'real',
  TESTING = 'testing',
  MOCK = 'mock',
  DEBUG = 'debug',
  RECORD = 'record',
  REPLAY = 'replay',
  SIMULATION = 'simulation'
}

export interface HttpClientOptions {
  /** Default timeout in milliseconds */
  defaultTimeoutMs: number;
  /** User agent string */
  userAgent: string;
  /** Default headers to include in all requests */
  defaultHeaders: Record<string, string>;
  /** Maximum number of retries */
  maxRetries: number;
  /** Base URL for relative requests */
  baseUrl?: string;
}

export interface MockModeOptions {
  /** Default status code for mock responses */
  defaultStatusCode: number;
  /** Default response body */
  defaultBody: string;
  /** Default response headers */
  defaultHeaders: Record<string, string>;
  /** Simulate network latency in milliseconds */
  simulateLatencyMs: number;
}

export interface RecordModeOptions {
  /** Directory to store recorded responses */
  recordingPath: string;
  /** Whether to overwrite existing recordings */
  overwriteExisting: boolean;
  /** Include request headers in recordings */
  includeHeaders: boolean;
}

export interface ReplayModeOptions {
  /** Directory containing recorded responses */
  recordingPath: string;
  /** Behavior when no recording is found */
  fallbackMode: 'error' | 'passthrough' | 'mock';
  /** Whether to enforce strict URL matching */
  strictMatching: boolean;
}

export interface SimulationModeOptions {
  /** Path to simulation scenarios file */
  scenarioPath?: string;
  /** Global latency in milliseconds */
  globalLatencyMs: number;
  /** Global failure rate (0.0 to 1.0) */
  globalFailureRate: number;
  /** Minimum ping latency in milliseconds */
  minPingLatencyMs: number;
  /** Maximum ping latency in milliseconds */
  maxPingLatencyMs: number;
  /** Ping failure rate (0.0 to 1.0) */
  pingFailureRate: number;
}

export interface DebugModeOptions {
  /** Enable verbose logging */
  verboseLogging: boolean;
  /** Log request/response bodies */
  logBodies: boolean;
  /** Log headers */
  logHeaders: boolean;
}

export interface HttpClientModeOptions {
  /** Current runtime mode */
  mode: RuntimeMode;
  /** Mock mode configuration */
  mock: MockModeOptions;
  /** Record mode configuration */
  record: RecordModeOptions;
  /** Replay mode configuration */
  replay: ReplayModeOptions;
  /** Simulation mode configuration */
  simulation: SimulationModeOptions;
  /** Debug mode configuration */
  debug: DebugModeOptions;
}

export interface HttpClientConfig {
  /** HTTP client options */
  http: HttpClientOptions;
  /** Mode-specific options */
  mode: HttpClientModeOptions;
}

/**
 * Default configuration values
 */
export const DEFAULT_HTTP_OPTIONS: HttpClientOptions = {
  defaultTimeoutMs: 30000,
  userAgent: 'Coyote-HTTP-Client/1.0',
  defaultHeaders: {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  },
  maxRetries: 3
};

export const DEFAULT_MOCK_OPTIONS: MockModeOptions = {
  defaultStatusCode: 200,
  defaultBody: '{"message": "Mock response"}',
  defaultHeaders: {
    'Content-Type': 'application/json'
  },
  simulateLatencyMs: 100
};

export const DEFAULT_RECORD_OPTIONS: RecordModeOptions = {
  recordingPath: './recordings',
  overwriteExisting: false,
  includeHeaders: true
};

export const DEFAULT_REPLAY_OPTIONS: ReplayModeOptions = {
  recordingPath: './recordings',
  fallbackMode: 'error',
  strictMatching: true
};

export const DEFAULT_SIMULATION_OPTIONS: SimulationModeOptions = {
  globalLatencyMs: 100,
  globalFailureRate: 0.0,
  minPingLatencyMs: 10,
  maxPingLatencyMs: 100,
  pingFailureRate: 0.0
};

export const DEFAULT_DEBUG_OPTIONS: DebugModeOptions = {
  verboseLogging: true,
  logBodies: true,
  logHeaders: true
};
