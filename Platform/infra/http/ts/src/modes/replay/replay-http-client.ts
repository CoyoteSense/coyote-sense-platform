/**
 * Replay HTTP Client Implementation
 * 
 * This module provides a replay HTTP client that serves recorded responses
 * in FIFO order for deterministic testing.
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { HttpRequest, HttpResponse } from '../../interfaces/http-client';
import { HttpClientOptions, ReplayModeOptions } from '../../interfaces/configuration';
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
  private readonly recordingQueue: RecordedInteraction[] = [];
  private currentIndex: number = 0;
  private fallbackClient?: RealHttpClient | MockHttpClient;

  constructor(options: HttpClientOptions, replayOptions: ReplayModeOptions, logger?: Console) {
    super(options);
    this.replayOptions = { ...replayOptions };
    this.logger = logger || console;
    
    // Create fallback client based on mode
    if (this.replayOptions.fallbackMode === 'passthrough') {
      this.fallbackClient = new RealHttpClient(options, this.logger);
    } else if (this.replayOptions.fallbackMode === 'mock') {
      // Use default mock options for fallback
      const mockOptions = {
        defaultStatusCode: 200,
        defaultBody: '{"message": "Fallback mock response"}',
        defaultHeaders: { 'Content-Type': 'application/json' },
        simulateLatencyMs: 100,
      };
      this.fallbackClient = new MockHttpClient(options, mockOptions, this.logger);
    }
    
    // Load recordings asynchronously
    this.loadRecordingsAsync();
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
  }

  private matchesRequest(recorded: RecordedInteraction['request'], current: HttpRequest): boolean {
    if (this.replayOptions.strictMatching) {
      // Strict matching: URL and method must match exactly
      return recorded.url === current.url && recorded.method === current.method;
    } else {
      // Loose matching: method must match, URL can be subset
      return recorded.method === current.method && (
        recorded.url === current.url || 
        current.url.includes(recorded.url) ||
        recorded.url.includes(current.url)
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
        const errorMessage = `No recording found for ${request.method} ${request.url}`;
        this.logger.error?.(errorMessage);        return new HttpResponseImpl({
          statusCode: 404,
          body: JSON.stringify({ error: errorMessage }),
          headers: { 'Content-Type': 'application/json' },
          errorMessage,
        });
    }
  }

  private async loadRecordingsAsync(): Promise<void> {
    try {
      this.logger.debug?.(`Loading recordings from ${this.replayOptions.recordingPath}`);
      
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
          this.recordingQueue.push(recording);
        } catch (error) {
          this.logger.warn?.(`Failed to load recording from ${filepath}:`, error);
        }
      }

      this.logger.debug?.(`Loaded ${this.recordingQueue.length} recordings`);
    } catch (error) {
      this.logger.error?.(`Failed to load recordings from ${this.replayOptions.recordingPath}:`, error);
    }
  }
  protected override onDispose(): void {
    this.fallbackClient?.dispose();
    super.onDispose();
  }
}
