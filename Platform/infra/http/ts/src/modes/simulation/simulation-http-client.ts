/**
 * Simulation HTTP Client Implementation
 * 
 * This module provides a simulation HTTP client with configurable behavior patterns
 * for testing various network conditions and failure scenarios.
 */

import * as fs from 'fs/promises';
import { HttpRequest, HttpResponse } from '../../interfaces/http-client';
import { HttpClientOptions, SimulationModeOptions } from '../../interfaces/configuration';
import { BaseHttpClient, HttpResponseImpl } from '../../interfaces/base-http-client';

// Update SimulationScenario to match test definitions
interface SimulationScenario {
  name?: string;
  pattern: string;
  statusCode: number;
  body: string;
  headers: Record<string, string>;
  latencyMs: number;
  failureRate?: number;
  failureMessages?: string[];
}

/**
 * Simulation HTTP client implementation with configurable behavior patterns
 */
export class SimulationHttpClient extends BaseHttpClient {
  private readonly simulationOptions: SimulationModeOptions;
  private readonly logger: Console;
  private readonly scenarios: SimulationScenario[] = [];
  private readonly defaultScenarios: Map<string, SimulationScenario> = new Map();

  constructor(options: HttpClientOptions, simulationOptions: SimulationModeOptions, logger?: Console) {
    super(options);
    this.simulationOptions = { ...simulationOptions };
    this.logger = logger || console;

    this.initializeDefaultScenarios();
    this.loadScenariosAsync();
  }

  async executeAsync(request: HttpRequest): Promise<HttpResponse> {
    this.logger.debug?.(`Simulation HTTP client executing ${request.method} request to ${request.url}`);

    const scenario = this.findMatchingScenario(request);
    
    // Simulate latency
    const latency = this.calculateLatency(scenario);
    if (latency > 0) {
      await this.delay(latency);
    }

    // Check for simulated failure
    if (this.shouldSimulateFailure(scenario)) {
      const errorMessage = this.getRandomFailureMessage(scenario);
      this.logger.debug?.(`Simulation HTTP client simulating failure for ${request.url}: ${errorMessage}`);
        return new HttpResponseImpl({
        statusCode: 0,
        body: '',
        headers: {},
        errorMessage,
      });
    }

    // Apply global simulation effects
    const globalLatency = this.calculateGlobalLatency();
    if (globalLatency > 0) {
      await this.delay(globalLatency);
    }

    this.logger.debug?.(`Simulation HTTP client returning status ${scenario.statusCode} for ${request.url}`);    return new HttpResponseImpl({
      statusCode: scenario.statusCode,
      body: this.processResponseBody(scenario.body, request),
      headers: { ...scenario.headers },
      errorMessage: scenario.statusCode >= 400 ? `Simulated error ${scenario.statusCode}` : undefined,
    });
  }

  async pingAsync(url?: string): Promise<boolean> {
    const pingUrl = url || '';
    this.logger.debug?.(`Simulation HTTP client ping to ${pingUrl}`);
    
    // Simulate ping latency
    const latency = this.randomBetween(
      this.simulationOptions.minPingLatencyMs, 
      this.simulationOptions.maxPingLatencyMs
    );
    await this.delay(latency);
    
    // Simulate ping failures
    if (Math.random() < this.simulationOptions.pingFailureRate) {
      this.logger.debug?.(`Simulation HTTP client simulating ping failure for ${url}`);
      return false;
    }
    
    return true;
  }

  /** Return the mode identifier */
  public getMode(): string {
    return 'simulation';
  }

  /** Return statistics on scenarios */
  public getStats(): { defaultScenarios: number; customScenarios: number; totalScenarios: number } {
    const defaultCount = this.defaultScenarios.size;
    const customCount = this.scenarios.length;
    return { defaultScenarios: defaultCount, customScenarios: customCount, totalScenarios: defaultCount + customCount };
  }

  /** Clear all custom scenarios */
  public clearCustomScenarios(): void {
    this.clearScenarios();
  }

  /**
   * Add a custom simulation scenario
   */
  addScenario(scenario: SimulationScenario): void {
    this.scenarios.push(scenario);
    this.logger.debug?.(`Added custom simulation scenario for pattern: ${scenario.pattern}`);
  }

  /**
   * Clear all custom scenarios
   */
  clearScenarios(): void {
    this.scenarios.length = 0;
    this.logger.debug?.('Cleared all custom simulation scenarios');
  }

  /**
   * Get all configured scenarios
   */
  getScenarios(): SimulationScenario[] {
    return [...this.scenarios];
  }

  private findMatchingScenario(request: HttpRequest): SimulationScenario {
    // Check custom scenarios first
    for (const scenario of this.scenarios) {
      if (this.matchesPattern(request.url, scenario.pattern)) {
        return scenario;
      }
    }

    // Check default scenarios, ordered by specificity (longest pattern first)
    const orderedScenarios = Array.from(this.defaultScenarios.values())
      .filter(s => s.pattern !== '*')
      .sort((a, b) => b.pattern.length - a.pattern.length);

    for (const scenario of orderedScenarios) {
      if (this.matchesPattern(request.url, scenario.pattern)) {
        return scenario;
      }
    }

    // Return catch-all default scenario
    return this.defaultScenarios.get('*')!;
  }

  private matchesPattern(url: string, pattern: string): boolean {
    if (pattern === '*') return true;
      // Handle patterns that start with /
    if (pattern.startsWith('/')) {
      // Handle relative URLs by extracting the path portion
      let path: string;
      try {
        const urlObj = new URL(url);
        path = urlObj.pathname;
      } catch {
        // If URL parsing fails (e.g., for relative URLs), treat the url as the path
        path = url.startsWith('/') ? url : '/' + url;
      }
      
      if (pattern.includes('*')) {
        // Convert glob pattern to regex
        const regexPattern = '^' + pattern.replace(/\*/g, '.*') + '.*$';
        return new RegExp(regexPattern, 'i').test(path);
      } else {
        return path.includes(pattern);
      }
    }
    
    // Handle full URL patterns
    if (pattern.includes('*')) {
      const regexPattern = '^' + pattern.replace(/\*/g, '.*') + '.*$';
      return new RegExp(regexPattern, 'i').test(url);
    }
    
    return url.includes(pattern);
  }

  private calculateLatency(scenario: SimulationScenario): number {
    const baseLatency = scenario.latencyMs || 0;
    // Add some randomness (±20%)
    const variance = baseLatency * 0.2;
    return Math.max(0, baseLatency + (Math.random() - 0.5) * 2 * variance);
  }

  private calculateGlobalLatency(): number {
    const baseLatency = this.simulationOptions.globalLatencyMs || 0;
    // Add some randomness (±30%)
    const variance = baseLatency * 0.3;
    return Math.max(0, baseLatency + (Math.random() - 0.5) * 2 * variance);
  }

  private shouldSimulateFailure(scenario: SimulationScenario): boolean {
    const globalFail = Math.random() < this.simulationOptions.globalFailureRate;
    const scenarioFail = Math.random() < (scenario.failureRate ?? 0);
    return globalFail || scenarioFail;
  }

  private getRandomFailureMessage(scenario: SimulationScenario): string {
    const messages: string[] = scenario.failureMessages ?? [];
    if (messages.length > 0) {
      const index = Math.floor(Math.random() * messages.length);
      return messages[index];
    }
    return 'Simulated network failure';
  }

  private processResponseBody(body: string, request: HttpRequest): string {
    return body
      .replace(/\{\{url\}\}/g, request.url)
      .replace(/\{\{method\}\}/g, request.method.toUpperCase())
      .replace(/\{\{timestamp\}\}/g, new Date().toISOString());
  }

  private initializeDefaultScenarios(): void {
    // Success for GET /users
    this.defaultScenarios.set('/users', {
      name: 'Users API',
      pattern: '/users',
      statusCode: 200,
      body: JSON.stringify({ message: 'success' }),
      headers: { 'Content-Type': 'application/json' },
      latencyMs: 50
    });

    // Health check
    this.defaultScenarios.set('/health', {
      name: 'Health check',
      pattern: '/health',
      statusCode: 200,
      body: JSON.stringify({ status: 'healthy', timestamp: '{{timestamp}}' }),
      headers: { 'Content-Type': 'application/json' },
      latencyMs: 10
    });

    // Error for /error/*
    this.defaultScenarios.set('/error/*', {
      name: 'Error pattern',
      pattern: '/error/*',
      statusCode: 500,
      body: JSON.stringify({ error: 'Simulated server error', method: '{{method}}' }),
      headers: { 'Content-Type': 'application/json' },
      latencyMs: 100
    });

    // Slow scenarios
    this.defaultScenarios.set('/slow/*', {
      pattern: '/slow/*',
      statusCode: 200,
      body: JSON.stringify({ message: 'This was slow', url: '{{url}}' }),
      headers: { 'Content-Type': 'application/json' },
      latencyMs: 2000,
      failureRate: 0.1,
      failureMessages: ['Slow service timeout', 'Processing timeout']
    });

    // Custom scenarios
    this.defaultScenarios.set('/custom/*', {
       pattern: '/custom/*',
       statusCode: 201,
       body: JSON.stringify({ message: 'Custom response', timestamp: '{{timestamp}}' }),
       headers: { 'Content-Type': 'application/json', 'X-Custom-Header': 'simulation' },
       latencyMs: 150,
       failureRate: 0.2,
       failureMessages: ['Custom service error']
     });

    // Catch-all default
    this.defaultScenarios.set('*', {
      pattern: '*',
      statusCode: 200,
      body: JSON.stringify({ message: 'Default simulation response', url: '{{url}}', method: '{{method}}' }),
      headers: { 'Content-Type': 'application/json' },
      latencyMs: 100,
      failureRate: 0.05,
      failureMessages: ['Generic network error', 'Connection timeout']
    });
  }
  
  private async loadScenariosAsync(): Promise<void> {
    if (!this.simulationOptions.scenarioPath) {
      return;
    }

    try {
      const content = await fs.readFile(this.simulationOptions.scenarioPath, 'utf8');
      const scenarioData = JSON.parse(content);
      
      if (Array.isArray(scenarioData.scenarios)) {
        for (const scenario of scenarioData.scenarios) {
          this.addScenario(scenario);
        }
        this.logger.debug?.(`Loaded ${scenarioData.scenarios.length} scenarios from ${this.simulationOptions.scenarioPath}`);
      }
    } catch (error) {
      this.logger.error?.(`Failed to load simulation scenarios from ${this.simulationOptions.scenarioPath}:`, error);
    }
  }

  private randomBetween(min: number, max: number): number {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
