/**
 * Base HTTP Client Implementation for TypeScript
 * 
 * This module provides the abstract base class for all HTTP client implementations,
 * following the same patterns as the C# version.
 */

import { HttpClient, HttpRequest, HttpResponse, HttpMethod, CoyoteHttpClient } from './http-client.js';
import { HttpClientOptions } from './configuration.js';

/**
 * HTTP request implementation
 */
export class HttpRequestImpl implements HttpRequest {
  url: string = '';
  method: HttpMethod = HttpMethod.GET;
  headers?: Record<string, string> = {};
  body?: string;
  timeout?: number;

  constructor(options?: Partial<HttpRequest>) {
    if (options) {
      Object.assign(this, options);
    }
  }

  setJsonBody<T>(content: T): void {
    this.body = JSON.stringify(content);
    this.setHeader('Content-Type', 'application/json');
  }

  setHeader(name: string, value: string): void {
    if (!this.headers) {
      this.headers = {};
    }
    this.headers[name] = value;
  }
}

/**
 * HTTP response implementation
 */
export class HttpResponseImpl implements HttpResponse {
  statusCode: number = 0;
  body: string = '';
  headers: Record<string, string> = {};
  errorMessage?: string;

  get isSuccess(): boolean {
    return this.statusCode >= 200 && this.statusCode < 300;
  }

  constructor(options?: Partial<HttpResponse>) {
    if (options) {
      Object.assign(this, options);
    }
  }
}

/**
 * Base HTTP client implementation with common functionality
 */
export abstract class BaseHttpClient implements CoyoteHttpClient {
  protected readonly options: HttpClientOptions;
  protected disposed: boolean = false;

  constructor(options: HttpClientOptions) {
    this.options = { ...options };
  }

  abstract executeAsync(request: HttpRequest): Promise<HttpResponse>;
  abstract pingAsync(url: string): Promise<boolean>;

  async getAsync(url: string, headers?: Record<string, string>): Promise<HttpResponse> {
    const request = this.createRequest();
    request.url = url;
    request.method = HttpMethod.GET;
    
    if (headers) {
      Object.assign(request.headers || {}, headers);
    }

    return this.executeAsync(request);
  }

  async postJsonAsync(url: string, data: any, headers?: Record<string, string>): Promise<HttpResponse> {
    const request = this.createRequest();
    request.url = url;
    request.method = HttpMethod.POST;
    request.body = JSON.stringify(data);
    
    const requestHeaders = request.headers || {};
    requestHeaders['Content-Type'] = 'application/json';
    
    if (headers) {
      Object.assign(requestHeaders, headers);
    }
    
    request.headers = requestHeaders;

    return this.executeAsync(request);
  }

  async putJsonAsync(url: string, data: any, headers?: Record<string, string>): Promise<HttpResponse> {
    const request = this.createRequest();
    request.url = url;
    request.method = HttpMethod.PUT;
    request.body = JSON.stringify(data);
    
    const requestHeaders = request.headers || {};
    requestHeaders['Content-Type'] = 'application/json';
    
    if (headers) {
      Object.assign(requestHeaders, headers);
    }
    
    request.headers = requestHeaders;

    return this.executeAsync(request);
  }

  async deleteAsync(url: string, headers?: Record<string, string>): Promise<HttpResponse> {
    const request = this.createRequest();
    request.url = url;
    request.method = HttpMethod.DELETE;
    
    if (headers) {
      Object.assign(request.headers || {}, headers);
    }

    return this.executeAsync(request);
  }

  getContent<T>(response: HttpResponse): T | null {
    if (!response.body) {
      return null;
    }

    try {
      return JSON.parse(response.body) as T;
    } catch (error) {
      console.warn('Failed to parse response body as JSON:', error);
      return null;
    }
  }

  setDefaultTimeout(timeoutMs: number): void {
    this.options.defaultTimeoutMs = timeoutMs;
  }

  setDefaultHeaders(headers: Record<string, string>): void {
    this.options.defaultHeaders = { ...headers };
  }

  setUserAgent(userAgent: string): void {
    this.options.userAgent = userAgent;
  }

  setBaseUrl(baseUrl: string): void {
    this.options.baseUrl = baseUrl;
  }

  createRequest(): HttpRequestImpl {
    const request = new HttpRequestImpl();
    request.timeout = this.options.defaultTimeoutMs;
    request.headers = { ...this.options.defaultHeaders };

    return request;
  }

  protected createUrl(url: string): string {
    if (url.startsWith('http://') || url.startsWith('https://')) {
      return url;
    }

    if (this.options.baseUrl) {
      const baseUrl = this.options.baseUrl.endsWith('/') 
        ? this.options.baseUrl.slice(0, -1) 
        : this.options.baseUrl;
      const path = url.startsWith('/') ? url : `/${url}`;
      return `${baseUrl}${path}`;
    }

    return url;
  }

  protected createResponseHeaders(headers: any): Record<string, string> {
    const result: Record<string, string> = {};
    
    if (headers) {
      // Handle different header formats (Node.js, fetch, etc.)
      if (typeof headers.entries === 'function') {
        // Headers object with entries method
        for (const [name, value] of headers.entries()) {
          result[name.toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value);
        }
      } else if (typeof headers === 'object') {
        // Plain object
        for (const [name, value] of Object.entries(headers)) {
          if (value !== undefined) {
            result[name.toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value);
          }
        }
      }
    }

    return result;
  }

  dispose(): void {
    if (!this.disposed) {
      this.disposed = true;
      this.onDispose();
    }
  }

  protected onDispose(): void {
    // Override in derived classes for cleanup
  }
}
