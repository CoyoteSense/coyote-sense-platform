/**
 * Replay HTTP Client Implementation
 * 
 * This module provides a replay HTTP client that serves recorded responses
 * in FIFO order for deterministic testing.
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { HttpRequest, HttpResponse } from '../../interfaces/http-client';
import { HttpClientOptions, ReplayModeOptions, ReplayHttpConfig } from '../../interfaces/configuration';
import { BaseHttpClient, HttpResponseImpl } from '../../interfaces/base-http-client';
import { RealHttpClient } from '../real/real-http-client';
import { MockHttpClient } from '../mock/mock-http-client';

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
 * Replay HTTP client implementation that serves recorded responses in FIFO order
 */
export class ReplayHttpClient extends BaseHttpClient {
  private readonly replayOptions: ReplayModeOptions;
  private readonly logger: Console;
  private recordingQueue: RecordedInteraction[] = [];
  private currentIndex: number = 0;
  private fallbackClient?: RealHttpClient | MockHttpClient;
  private fallbackResponse?: { statusCode: number; body: string; headers: Record<string, string> } | undefined;
  // Constructor overloads
  constructor(options: HttpClientOptions, replayOptions: ReplayModeOptions, logger?: Console);
  constructor(config: ReplayHttpConfig, logger?: Console);  constructor(
    optionsOrConfig: HttpClientOptions | ReplayHttpConfig,
    replayOptionsOrLogger?: ReplayModeOptions | Console,
    logger?: Console
  ) {
    let httpOptions: HttpClientOptions;
    
    // Determine which constructor overload was used
    if ((optionsOrConfig as HttpClientOptions).defaultTimeoutMs !== undefined && 
        (replayOptionsOrLogger as ReplayModeOptions)?.recordingPath !== undefined) {
      // First overload: (options, replayOptions, logger?)
      httpOptions = optionsOrConfig as HttpClientOptions;
      super(httpOptions);
      this.replayOptions = { ...(replayOptionsOrLogger as ReplayModeOptions) };
      this.logger = logger || console;
    } else {
      // Second overload: (config, logger?)
      const config = optionsOrConfig as ReplayHttpConfig;
      httpOptions = {
        defaultTimeoutMs: config.defaultTimeoutMs || 30000,
        userAgent: config.userAgent || 'CoyoteHttp/1.0',
        defaultHeaders: config.defaultHeaders || {},
        maxRetries: config.maxRetries || 3,
        ...(config.baseUrl && { baseUrl: config.baseUrl })
      };
      super(httpOptions);      this.replayOptions = {
        recordingPath: config.recordingDirectory || config.replay?.recordingPath || './recordings',
        fallbackMode: config.replay?.fallbackMode || 'error',
        strictMatching: config.strictMatching ?? config.replay?.strictMatching ?? false
      };
      this.fallbackResponse = config.fallbackResponse;
      this.logger = (replayOptionsOrLogger as Console) || console;
    }
    
    // Create fallback client based on mode
    if (this.replayOptions.fallbackMode === 'passthrough') {
      this.fallbackClient = new RealHttpClient(httpOptions, this.logger);
    } else if (this.replayOptions.fallbackMode === 'mock') {      // Use default mock options for fallback
      const mockOptions = {
        defaultStatusCode: 200,
        defaultBody: '{"message":"Fallback mock response"}',
        defaultHeaders: { 'Content-Type': 'application/json' },
        simulateLatencyMs: 100,
      };
      this.fallbackClient = new MockHttpClient(httpOptions, mockOptions, this.logger);
    }
      // Load recordings asynchronously
    this.loadRecordingsAsync();
  }

  /**
   * Get the recordings array (for test access)
   */
  get recordings(): RecordedInteraction[] {
    return this.recordingQueue;
  }

  async executeAsync(request: HttpRequest): Promise<HttpResponse> {
    this.logger.debug?.(`Replay HTTP client executing ${request.method} request to ${request.url}`);

    // Find next matching recording in FIFO order
    const recording = this.getNextMatchingRecording(request);
    
    if (recording) {
      this.logger.debug?.(`Replaying recorded response for ${request.url}`);
        return new HttpResponseImpl({
        statusCode: recording.response.statusCode,
        body: recording.response.body,
        headers: recording.response.headers,
        errorMessage: recording.response.errorMessage,
      });
    }

    // No recording found, use fallback strategy
    return this.handleNoRecording(request);
  }

  async pingAsync(url: string): Promise<boolean> {
    this.logger.debug?.(`Replay HTTP client ping to ${url}`);
    
    // For ping, always return true in replay mode
    // Real pings would have been recorded if they were part of the test scenario
    return true;
  }

  /**
   * Alias for executeAsync to match test expectations
   */
  async sendAsync(request: HttpRequest): Promise<HttpResponse> {
    return this.executeAsync(request);
  }

  /**
   * Reset the replay queue to start from the beginning
   */
  resetQueue(): void {
    this.currentIndex = 0;
    this.logger.debug?.('Replay queue reset to beginning');
  }

  /**
   * Get the number of remaining recordings in the queue
   */
  getRemainingCount(): number {
    return Math.max(0, this.recordingQueue.length - this.currentIndex);
  }

  /**
   * Get the total number of loaded recordings
   */
  getTotalCount(): number {
    return this.recordingQueue.length;
  }
  private getNextMatchingRecording(request: HttpRequest): RecordedInteraction | undefined {
    while (this.currentIndex < this.recordingQueue.length) {
      const recording = this.recordingQueue[this.currentIndex];
      this.currentIndex++;

      if (recording && this.matchesRequest(recording.request, request)) {
        return recording;
      }

      if (this.replayOptions.strictMatching && recording) {
        this.logger.warn?.(
          `Strict matching enabled: skipping non-matching recording for ${recording.request.method} ${recording.request.url}`
        );
      }
    }

    return undefined;
  }  private matchesRequest(recorded: RecordedInteraction['request'], current: HttpRequest): boolean {
    if (this.replayOptions.strictMatching) {
      // Strict matching: URL, method, and headers must match exactly
      const methodMatch = recorded.method === current.method;
      const urlMatch = recorded.url === current.url;
      
      // Check headers if they exist
      let headerMatch = true;
      if (recorded.headers && current.headers) {
        const recordedKeys = Object.keys(recorded.headers);
        const currentKeys = Object.keys(current.headers);
        
        // All recorded headers must be present and match in current request
        headerMatch = recordedKeys.every(key => 
          current.headers![key] === recorded.headers[key]
        );
      } else if (recorded.headers || current.headers) {
        // One has headers and the other doesn't
        headerMatch = false;
      }
      
      return methodMatch && urlMatch && headerMatch;
    } else {
      // Loose matching: method must match (case-insensitive), URL can be subset (case-insensitive)
      const recordedMethod = recorded.method.toUpperCase();
      const currentMethod = current.method.toUpperCase();
      const recordedUrl = recorded.url.toLowerCase();
      const currentUrl = current.url.toLowerCase();
      
      return recordedMethod === currentMethod && (
        recordedUrl === currentUrl || 
        currentUrl.includes(recordedUrl) ||
        recordedUrl.includes(currentUrl)
      );
    }
  }
  private async handleNoRecording(request: HttpRequest): Promise<HttpResponse> {
    switch (this.replayOptions.fallbackMode) {
      case 'passthrough':
        this.logger.debug?.(`No recording found for ${request.url}, using passthrough`);
        return this.fallbackClient!.executeAsync(request);

      case 'mock':
        this.logger.debug?.(`No recording found for ${request.url}, using mock fallback`);
        return this.fallbackClient!.executeAsync(request);

      case 'error':
      default:
        // Use configured fallback response if available
        if (this.fallbackResponse) {
          this.logger.debug?.(`No recording found for ${request.url}, using configured fallback response`);
          return new HttpResponseImpl({
            statusCode: this.fallbackResponse.statusCode,
            body: this.fallbackResponse.body,
            headers: this.fallbackResponse.headers,
          });
        }        const errorMessage = `No recording found for ${request.method} ${request.url}`;
        this.logger.error?.(errorMessage);
        return new HttpResponseImpl({
          statusCode: 404,
          body: 'Recording not found',
          headers: { 'Content-Type': 'text/plain' },
          errorMessage,
        });
    }
  }
  private async loadRecordingsAsync(): Promise<void> {
    try {
      this.logger.debug?.(`Loading recordings from ${this.replayOptions.recordingPath}`);
      
      // Clear existing recordings first
      this.recordingQueue.length = 0;
      this.currentIndex = 0;
      
      const files = await fs.readdir(this.replayOptions.recordingPath);
      const jsonFiles = files.filter(file => file.endsWith('.json'));

      // Get file stats to sort by creation time (FIFO order)
      const fileStats = await Promise.all(
        jsonFiles.map(async file => {
          const filepath = path.join(this.replayOptions.recordingPath, file);
          const stats = await fs.stat(filepath);
          return { file, filepath, birthtime: stats.birthtime };
        })
      );

      // Sort by creation time (oldest first for FIFO)
      fileStats.sort((a, b) => a.birthtime.getTime() - b.birthtime.getTime());

      // Load recordings in order
      for (const { filepath } of fileStats) {
        try {
          const content = await fs.readFile(filepath, 'utf8');
          const recording: RecordedInteraction = JSON.parse(content);
            // Validate recording structure
          if (recording.request && recording.response && 
              recording.request.method && recording.request.url) {
            this.recordingQueue.push(recording);
          } else {
            this.logger.warn?.(`Failed to parse recording file ${filepath}`, 'Invalid structure');
          }
        } catch (error) {
          this.logger.warn?.(`Failed to parse recording file ${filepath}:`, error);
        }
      }

      this.logger.debug?.(`Loaded ${this.recordingQueue.length} recordings`);
    } catch (error) {
      this.logger.error?.(`Failed to load recordings from ${this.replayOptions.recordingPath}:`, error);
    }
  }protected override async onDispose(): Promise<void> {
    // Clear recordings
    this.recordingQueue.length = 0;
    this.currentIndex = 0;
    
    if (this.fallbackClient) {
      await this.fallbackClient.dispose();
    }
    await super.onDispose();
  }
}
