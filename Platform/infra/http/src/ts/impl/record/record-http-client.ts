/**
 * Record HTTP Client Implementation
 * 
 * This module provides a recording HTTP client that captures requests/responses
 * for later replay in testing scenarios.
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { HttpRequest, HttpResponse } from '../../interfaces/http-client.js';
import { HttpClientOptions, RecordModeOptions } from '../../interfaces/configuration.js';
import { BaseHttpClient } from '../../interfaces/base-http-client.js';
import { RealHttpClient } from '../real/real-http-client.js';

interface RecordedInteraction {
  request: {
    url: string;
    method: string;
    headers: Record<string, string>;
    body?: string;
  };
  response: {
    statusCode: number;
    headers: Record<string, string>;
    body: string;
    errorMessage?: string;
  };
  timestamp: string;
  duration: number;
}

/**
 * Recording HTTP client implementation that captures requests/responses
 */
export class RecordHttpClient extends BaseHttpClient {
  private readonly realClient: RealHttpClient;
  private readonly recordOptions: RecordModeOptions;
  private readonly logger: Console;

  constructor(options: HttpClientOptions, recordOptions: RecordModeOptions, logger?: Console) {
    super(options);
    this.recordOptions = { ...recordOptions };
    this.logger = logger || console;
    
    // Use real client for actual requests
    this.realClient = new RealHttpClient(options, this.logger);
    
    // Ensure recording directory exists
    this.ensureRecordingDirectory();
  }

  async executeAsync(request: HttpRequest): Promise<HttpResponse> {
    const startTime = Date.now();
    const response = await this.realClient.executeAsync(request);
    const duration = Date.now() - startTime;

    // Record the request/response pair
    await this.recordInteraction(request, response, duration);

    return response;
  }

  async pingAsync(url: string): Promise<boolean> {
    // Forward ping to real client (don't record ping requests)
    return this.realClient.pingAsync(url);
  }

  private async recordInteraction(request: HttpRequest, response: HttpResponse, duration: number): Promise<void> {
    try {
      const interaction: RecordedInteraction = {
        request: {
          url: request.url,
          method: request.method,
          headers: this.recordOptions.includeHeaders ? (request.headers || {}) : {},
          body: request.body,
        },
        response: {
          statusCode: response.statusCode,
          headers: this.recordOptions.includeHeaders ? response.headers : {},
          body: response.body,
          errorMessage: response.errorMessage,
        },
        timestamp: new Date().toISOString(),
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

      await fs.writeFile(filepath, JSON.stringify(interaction, null, 2), 'utf8');
      
      this.logger.debug?.(`Recorded interaction: ${request.method} ${request.url} -> ${filepath}`);
    } catch (error) {
      this.logger.error?.('Failed to record HTTP interaction:', error);
    }
  }

  private generateFilename(request: HttpRequest): string {
    // Create a safe filename based on the request
    const url = new URL(request.url);
    const hostname = url.hostname.replace(/[^a-zA-Z0-9]/g, '_');
    const pathname = url.pathname.replace(/[^a-zA-Z0-9]/g, '_');
    const method = request.method.toLowerCase();
    const timestamp = Date.now();
    
    return `${method}_${hostname}${pathname}_${timestamp}.json`;
  }

  private async ensureRecordingDirectory(): Promise<void> {
    try {
      await fs.mkdir(this.recordOptions.recordingPath, { recursive: true });
    } catch (error) {
      this.logger.error?.(`Failed to create recording directory ${this.recordOptions.recordingPath}:`, error);
    }
  }

  protected onDispose(): void {
    this.realClient.dispose();
    super.onDispose();
  }
}
