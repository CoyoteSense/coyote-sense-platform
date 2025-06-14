/**
 * Real HTTP Client Implementation using Node.js fetch
 * 
 * This module provides the production HTTP client implementation using the native fetch API.
 */

import { HttpRequest, HttpResponse } from '../../interfaces/http-client';
import { HttpClientOptions } from '../../interfaces/configuration';
import { BaseHttpClient, HttpResponseImpl } from '../../interfaces/base-http-client';

/**
 * Real HTTP client implementation using native fetch
 */
export class RealHttpClient extends BaseHttpClient {
  private readonly logger?: Console;

  constructor(options: HttpClientOptions, logger?: Console) {
    super(options);
    this.logger = logger || console;
  }

  async executeAsync(request: HttpRequest): Promise<HttpResponse> {
    const url = this.createUrl(request.url);
    
    try {
      this.logger?.debug?.(`Executing ${request.method} request to ${url}`);

      const controller = new AbortController();
      const timeoutId = request.timeout 
        ? setTimeout(() => controller.abort(), request.timeout)
        : null;

      const fetchOptions: RequestInit = {
        method: request.method,
        headers: request.headers || {},
        signal: controller.signal,
      };

      // Add body for POST, PUT, PATCH requests
      if (request.body && ['POST', 'PUT', 'PATCH'].includes(request.method)) {
        fetchOptions.body = request.body;
      }

      const response = await fetch(url, fetchOptions);

      if (timeoutId) {
        clearTimeout(timeoutId);
      }

      const responseBody = await response.text();
      const responseHeaders = this.createResponseHeaders(response.headers);

      this.logger?.debug?.(
        `Received response with status ${response.status} from ${url}`
      );      return new HttpResponseImpl({
        statusCode: response.status,
        body: responseBody,
        headers: responseHeaders,
        errorMessage: !response.ok ? `HTTP ${response.status} ${response.statusText}` : undefined,
      });

    } catch (error: any) {
      this.logger?.error?.(`HTTP request failed for ${request.method} ${url}:`, error);      return new HttpResponseImpl({
        statusCode: 0,
        body: '',
        headers: {},
        errorMessage: error.message || 'Request failed',
      });
    }
  }

  async pingAsync(url: string): Promise<boolean> {
    try {
      const fullUrl = this.createUrl(url);
      this.logger?.debug?.(`Pinging ${fullUrl}`);

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout for ping

      const response = await fetch(fullUrl, {
        method: 'HEAD',
        signal: controller.signal,
      });

      clearTimeout(timeoutId);
      
      const success = response.ok;
      this.logger?.debug?.(`Ping result for ${fullUrl}: ${success}`);
      
      return success;
    } catch (error) {
      this.logger?.debug?.(`Ping failed for ${url}:`, error);
      return false;
    }
  }

  /**
   * Alias for executeAsync to match test expectations
   */
  async sendAsync(request: HttpRequest): Promise<HttpResponse> {
    return this.executeAsync(request);
  }

  protected override async onDispose(): Promise<void> {
    // Real HTTP client doesn't need special cleanup
    await super.onDispose();
  }
}
