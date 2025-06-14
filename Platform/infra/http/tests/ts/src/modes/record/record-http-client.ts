/**
 * Record HTTP Client Implementation
 * 
 * This module provides a recording HTTP client that captures requests/responses
 * for later replay in testing scenarios.
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { HttpRequest, HttpResponse, HttpClient } from '../../interfaces/http-client';
import { HttpClientOptions, RecordModeOptions, RecordHttpConfig, DEFAULT_HTTP_OPTIONS, DEFAULT_RECORD_OPTIONS } from '../../interfaces/configuration';
import { BaseHttpClient } from '../../interfaces/base-http-client';
import { RealHttpClient } from '../real/real-http-client';

interface RecordedInteraction {
  request: {
    url: string;
    method: string;
    headers?: Record<string, string>;
    body?: string;
  };
  response: {
    statusCode: number;
    headers?: Record<string, string>;
    body: string;
    errorMessage?: string;
  };
  timestamp?: string;
  duration: number;
}

/**
 * Recording HTTP client implementation that captures requests/responses
 */
export class RecordHttpClient extends BaseHttpClient {
  private readonly innerClient: HttpClient;
  private readonly recordOptions: RecordModeOptions;
  private readonly filenameTemplate: string;
  private readonly prettyPrint: boolean;
  private readonly includeTimestamp: boolean;
  private readonly logger: Console;

  // Constructor overloads
  constructor(options: HttpClientOptions, recordOptions: RecordModeOptions, logger?: Console);
  constructor(innerClient: HttpClient, recordConfig: RecordHttpConfig, logger?: Console);
  constructor(
    optionsOrInnerClient: HttpClientOptions | HttpClient,
    recordOptionsOrConfig?: RecordModeOptions | RecordHttpConfig,
    logger?: Console
  ) {
    // Determine which constructor overload was used
    if ((optionsOrInnerClient as HttpClientOptions).defaultTimeoutMs !== undefined && 
        (recordOptionsOrConfig as RecordModeOptions)?.recordingPath !== undefined) {
      // First overload: (options, recordOptions, logger?)
      super(optionsOrInnerClient as HttpClientOptions);
      this.recordOptions = { ...(recordOptionsOrConfig as RecordModeOptions) };
      this.filenameTemplate = 'recording_{timestamp}_{method}_{url}.json';
      this.prettyPrint = true;
      this.includeTimestamp = true;
      this.logger = logger || console;
      
      // Use real client for actual requests
      this.innerClient = new RealHttpClient(optionsOrInnerClient as HttpClientOptions, this.logger);
    } else {
      // Second overload: (innerClient, recordConfig, logger?)
      const config = recordOptionsOrConfig as RecordHttpConfig;
      const httpOptions = {
        defaultTimeoutMs: config?.defaultTimeoutMs || DEFAULT_HTTP_OPTIONS.defaultTimeoutMs,
        userAgent: config?.userAgent || DEFAULT_HTTP_OPTIONS.userAgent,
        defaultHeaders: config?.defaultHeaders || DEFAULT_HTTP_OPTIONS.defaultHeaders,
        maxRetries: config?.maxRetries || DEFAULT_HTTP_OPTIONS.maxRetries,
        ...(config?.baseUrl && { baseUrl: config.baseUrl })
      };
      super(httpOptions);
      this.recordOptions = {
        recordingPath: config?.recordingDirectory || config?.record?.recordingPath || DEFAULT_RECORD_OPTIONS.recordingPath,
        overwriteExisting: config?.overwriteExisting ?? config?.record?.overwriteExisting ?? DEFAULT_RECORD_OPTIONS.overwriteExisting,
        includeHeaders: config?.includeHeaders ?? config?.record?.includeHeaders ?? DEFAULT_RECORD_OPTIONS.includeHeaders,
      };
      this.filenameTemplate = config?.filenameTemplate || 'recording_{timestamp}_{method}_{url}.json';
      this.prettyPrint = config?.prettyPrint ?? true;
      this.includeTimestamp = config?.includeTimestamp ?? true;
      this.logger = logger || console;
      
      // Use the provided inner client for actual requests
      this.innerClient = optionsOrInnerClient as HttpClient;
    }
    
    // Ensure recording directory exists
    this.ensureRecordingDirectory();
  }

  /**
   * Get the current mode of this client
   */
  getMode(): string {
    return 'record';
  }  async executeAsync(request: HttpRequest): Promise<HttpResponse> {
    const startTime = Date.now();
    const response = await this.innerClient.executeAsync(request);
    const duration = Date.now() - startTime;

    // Record the request/response pair
    await this.recordInteraction(request, response, duration);

    return response;
  }

  async pingAsync(url: string): Promise<boolean> {
    // Forward ping to inner client (don't record ping requests)
    return this.innerClient.pingAsync(url);
  }

  /**
   * Alias for executeAsync to match test expectations
   */
  async sendAsync(request: HttpRequest): Promise<HttpResponse> {
    return this.executeAsync(request);
  }  private async recordInteraction(request: HttpRequest, response: HttpResponse, duration: number): Promise<void> {
    try {
      const interaction: RecordedInteraction = {
        request: {
          url: request.url,
          method: request.method,
          ...(this.recordOptions.includeHeaders && request.headers && { headers: request.headers }),
          ...(request.body && { body: request.body }),
        },
        response: {
          statusCode: response.statusCode,
          ...(this.recordOptions.includeHeaders && { headers: response.headers }),
          body: response.body,
          ...(response.errorMessage && { errorMessage: response.errorMessage }),
        },
        ...(this.includeTimestamp && { timestamp: new Date().toISOString() }),
        duration,
      };

      const filename = this.generateFilename(request);
      const filepath = path.join(this.recordOptions.recordingPath, filename);

      // Check if file exists and overwrite setting
      if (!this.recordOptions.overwriteExisting) {
        try {
          await fs.access(filepath);
          this.logger.debug?.(`Recording already exists for ${request.url}, skipping due to overwriteExisting=false`);
          return;
        } catch {
          // File doesn't exist, proceed with recording
        }
      }

      const jsonContent = this.prettyPrint 
        ? JSON.stringify(interaction, null, 2)
        : JSON.stringify(interaction);

      await fs.writeFile(filepath, jsonContent, 'utf8');
      
      this.logger.debug?.(`Recorded interaction: ${request.method} ${request.url} -> ${filepath}`);    } catch (error) {
      this.logger.error?.('Failed to record HTTP request:', error);
    }
  }

  private generateFilename(request: HttpRequest): string {
    const timestamp = Date.now();
    const method = request.method.toUpperCase();
    
    // Sanitize URL for filename
    let url = request.url;
    // Remove leading slash
    if (url.startsWith('/')) {
      url = url.substring(1);
    }
    // Replace special characters with underscores
    url = url.replace(/[^a-zA-Z0-9]/g, '_');
    // Remove consecutive underscores
    url = url.replace(/_+/g, '_');
    // Remove trailing underscore
    if (url.endsWith('_')) {
      url = url.substring(0, url.length - 1);
    }
    
    // Apply filename template
    return this.filenameTemplate
      .replace('{timestamp}', timestamp.toString())
      .replace('{method}', method)
      .replace('{url}', url);
  }

  private async ensureRecordingDirectory(): Promise<void> {
    try {
      await fs.mkdir(this.recordOptions.recordingPath, { recursive: true });
    } catch (error) {
      this.logger.error?.(`Failed to create recording directory ${this.recordOptions.recordingPath}:`, error);
    }
  }  protected override async onDispose(): Promise<void> {
    try {
      await this.innerClient.dispose();
    } catch (error) {
      this.logger.error?.('Error disposing inner client:', error);
      // Don't rethrow - allow dispose to complete gracefully
    }
    await super.onDispose();
  }
}
