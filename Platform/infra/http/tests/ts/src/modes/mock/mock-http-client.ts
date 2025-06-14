/**
 * Mock HTTP Client Implementation for Testing
 * 
 * This module provides a mock HTTP client for testing purposes with configurable responses.
 */

import { HttpRequest, HttpResponse } from '../../interfaces/http-client';
import { HttpClientOptions, MockModeOptions, MockHttpConfig, DEFAULT_HTTP_OPTIONS, DEFAULT_MOCK_OPTIONS } from '../../interfaces/configuration';
import { BaseHttpClient, HttpResponseImpl } from '../../interfaces/base-http-client';

interface MockResponse {
  statusCode: number;
  body: string;
  headers: Record<string, string>;
  delayMs: number;
}

/**
 * Mock HTTP client implementation for testing
 */
export class MockHttpClient extends BaseHttpClient {
  private readonly mockOptions: MockModeOptions;
  private readonly logger?: Console;
  private readonly predefinedResponses: Map<string, MockResponse> = new Map();

  // Constructor overloads
  constructor(options: HttpClientOptions, mockOptions: MockModeOptions, logger?: Console);
  constructor(config: MockHttpConfig, logger?: Console);
  constructor(
    optionsOrConfig: HttpClientOptions | MockHttpConfig,
    mockOptionsOrLogger?: MockModeOptions | Console,
    logger?: Console
  ) {
    // Determine which constructor overload was used
    if ((optionsOrConfig as HttpClientOptions).defaultTimeoutMs !== undefined && 
        (mockOptionsOrLogger as MockModeOptions)?.defaultStatusCode !== undefined) {
      // First overload: (options, mockOptions, logger?)
      super(optionsOrConfig as HttpClientOptions);
      this.mockOptions = { ...(mockOptionsOrLogger as MockModeOptions) };
      this.logger = logger || console;
    } else {
      // Second overload: (config, logger?)
      const config = optionsOrConfig as MockHttpConfig;
      super({
        defaultTimeoutMs: config.defaultTimeoutMs || DEFAULT_HTTP_OPTIONS.defaultTimeoutMs,
        userAgent: config.userAgent || DEFAULT_HTTP_OPTIONS.userAgent,
        defaultHeaders: config.defaultHeaders || DEFAULT_HTTP_OPTIONS.defaultHeaders,
        maxRetries: config.maxRetries || DEFAULT_HTTP_OPTIONS.maxRetries,
        ...(config.baseUrl && { baseUrl: config.baseUrl })
      });
      this.mockOptions = {
        defaultStatusCode: config.defaultStatusCode || config.mock?.defaultStatusCode || DEFAULT_MOCK_OPTIONS.defaultStatusCode,
        defaultBody: config.defaultBody || config.mock?.defaultBody || DEFAULT_MOCK_OPTIONS.defaultBody,
        defaultHeaders: config.defaultHeaders || config.mock?.defaultHeaders || DEFAULT_MOCK_OPTIONS.defaultHeaders,
        simulateLatencyMs: config.simulateLatencyMs || config.mock?.simulateLatencyMs || DEFAULT_MOCK_OPTIONS.simulateLatencyMs,
      };
      this.logger = (mockOptionsOrLogger as Console) || console;
    }
  }

  async executeAsync(request: HttpRequest): Promise<HttpResponse> {
    this.logger?.debug?.(`Mock HTTP client executing ${request.method} request to ${request.url}`);

    // Check for predefined responses first
    let response = this.getPredefinedResponse(request.url);
    
    if (!response) {
      // Use default response
      response = {
        statusCode: this.mockOptions.defaultStatusCode,
        body: this.mockOptions.defaultBody,
        headers: { ...this.mockOptions.defaultHeaders },
        delayMs: this.mockOptions.simulateLatencyMs,
      };
    }

    // Simulate network delay
    if (response.delayMs > 0) {
      await this.delay(response.delayMs);
    }

    this.logger?.debug?.(
      `Mock HTTP client returning status ${response.statusCode} for ${request.url}`
    );

    return new HttpResponseImpl({
      statusCode: response.statusCode,
      body: response.body,
      headers: response.headers,
      errorMessage: response.statusCode >= 400 ? `Mock error response ${response.statusCode}` : undefined,
    });
  }

  // Alias for executeAsync to match expected interface
  async sendAsync(request: HttpRequest): Promise<HttpResponse> {
    return this.executeAsync(request);
  }

  async pingAsync(url: string): Promise<boolean> {
    this.logger?.debug?.(`Mock HTTP client ping to ${url}`);
    
    // Simulate small delay
    await this.delay(10);
    
    // Always return true for mock ping
    return true;
  }

  /**
   * Configure a predefined response for a specific URL
   */
  setPredefinedResponse(
    url: string, 
    statusCode: number, 
    body: string, 
    headers?: Record<string, string>, 
    delayMs: number = 0
  ): void {
    this.predefinedResponses.set(url, {
      statusCode,
      body,
      headers: headers || {},
      delayMs,
    });
  }

  /**
   * Configure a predefined response for a specific URL with JSON body
   */
  setPredefinedJsonResponse<T>(
    url: string, 
    content: T, 
    statusCode: number = 200, 
    headers?: Record<string, string>, 
    delayMs: number = 0
  ): void {
    const responseHeaders = headers || {};
    responseHeaders['Content-Type'] = 'application/json';

    this.setPredefinedResponse(url, statusCode, JSON.stringify(content), responseHeaders, delayMs);
  }

  /**
   * Configure default response for all requests
   */
  setDefaultResponse(
    statusCode: number, 
    body: string, 
    headers?: Record<string, string>, 
    delayMs: number = 0
  ): void {
    this.mockOptions.defaultStatusCode = statusCode;
    this.mockOptions.defaultBody = body;
    this.mockOptions.simulateLatencyMs = delayMs;
    
    if (headers) {
      this.mockOptions.defaultHeaders = { ...headers };
    }
  }

  /**
   * Clear all predefined responses
   */
  clearPredefinedResponses(): void {
    this.predefinedResponses.clear();
  }

  /**
   * Get all configured URLs with predefined responses
   */
  getConfiguredUrls(): string[] {
    return Array.from(this.predefinedResponses.keys());
  }

  private getPredefinedResponse(url: string): MockResponse | undefined {
    // Exact match first
    const exactMatch = this.predefinedResponses.get(url);
    if (exactMatch) {
      return exactMatch;
    }

    // Try pattern matching (simple contains check and wildcard)
    for (const [pattern, response] of Array.from(this.predefinedResponses.entries())) {
      if (url.includes(pattern) || (pattern.includes('*') && this.matchesWildcard(url, pattern))) {
        return response;
      }
    }

    return undefined;
  }

  private matchesWildcard(url: string, pattern: string): boolean {
    // Simple wildcard matching - replace * with .*
    const regexPattern = '^' + pattern.replace(/\*/g, '.*') + '$';
    return new RegExp(regexPattern, 'i').test(url);
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  protected override async onDispose(): Promise<void> {
    // Mock HTTP client doesn't need special cleanup
    await super.onDispose();
  }
}
