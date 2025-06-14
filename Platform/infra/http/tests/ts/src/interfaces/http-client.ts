/**
 * HTTP Client Interfaces for TypeScript
 * 
 * This module defines the core interfaces for HTTP client functionality,
 * providing a contract for different HTTP client implementations.
 */

export enum HttpMethod {
  GET = 'GET',
  POST = 'POST',
  PUT = 'PUT',
  DELETE = 'DELETE',
  PATCH = 'PATCH',
  HEAD = 'HEAD',
  OPTIONS = 'OPTIONS'
}

export interface HttpRequest {
  /** The URL to make the request to */
  url: string;
  /** HTTP method to use */
  method: HttpMethod;
  /** Request headers */
  headers?: Record<string, string>;
  /** Request body (for POST, PUT, PATCH) */
  body?: string;
  /** Request timeout in milliseconds */
  timeout?: number;
}

export interface HttpResponse {
  /** HTTP status code */
  statusCode: number;
  /** Response body as string */
  body: string;
  /** Response headers */
  headers: Record<string, string>;
  /** Error message if request failed */
  errorMessage?: string;
  /** Whether the request was successful (status 200-299) */
  isSuccess: boolean;
}

export interface HttpClient {
  /**
   * Execute an HTTP request
   * @param request The HTTP request to execute
   * @returns Promise resolving to HTTP response
   */
  executeAsync(request: HttpRequest): Promise<HttpResponse>;

  /**
   * Ping a URL to check connectivity
   * @param url The URL to ping
   * @returns Promise resolving to true if successful
   */
  pingAsync(url: string): Promise<boolean>;

  /**
   * Perform a GET request
   * @param url The URL to request
   * @param headers Optional headers
   * @returns Promise resolving to HTTP response
   */
  getAsync(url: string, headers?: Record<string, string>): Promise<HttpResponse>;

  /**
   * Perform a POST request with JSON body
   * @param url The URL to request
   * @param data The data to send as JSON
   * @param headers Optional headers
   * @returns Promise resolving to HTTP response
   */
  postJsonAsync(url: string, data: any, headers?: Record<string, string>): Promise<HttpResponse>;

  /**
   * Perform a PUT request with JSON body
   * @param url The URL to request
   * @param data The data to send as JSON
   * @param headers Optional headers
   * @returns Promise resolving to HTTP response
   */
  putJsonAsync(url: string, data: any, headers?: Record<string, string>): Promise<HttpResponse>;

  /**
   * Perform a DELETE request
   * @param url The URL to request
   * @param headers Optional headers
   * @returns Promise resolving to HTTP response
   */
  deleteAsync(url: string, headers?: Record<string, string>): Promise<HttpResponse>;
  /**
   * Dispose of resources
   */
  dispose(): Promise<void>;
}

export interface CoyoteHttpClient extends HttpClient {
  /**
   * Get typed JSON content from response
   * @param response The HTTP response
   * @returns Parsed JSON content
   */
  getContent<T>(response: HttpResponse): T | null;
}
