/**
 * Mock HTTP Client Implementation for Testing
 * 
 * This module provides a mock HTTP client for testing purposes with configurable responses.
 */

import { HttpRequest, HttpResponse } from '../../interfaces/http-client';
import { HttpClientOptions, MockModeOptions } from '../../interfaces/configuration';
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

  constructor(options: HttpClientOptions, mockOptions: MockModeOptions, logger?: Console) {
    super(options);
    this.mockOptions = { ...mockOptions };
    this.logger = logger || console;
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
    );    return new HttpResponseImpl({
      statusCode: response.statusCode,
      body: response.body,
      headers: response.headers,
      errorMessage: response.statusCode >= 400 ? `Mock error response ${response.statusCode}` : undefined,
    });
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
}
