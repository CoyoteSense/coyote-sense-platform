/**
 * Simulation HTTP Client Implementation
 * 
 * This module provides a simulation HTTP client with configurable behavior patterns
 * for testing various network conditions and failure scenarios.
 */

import * as fs from 'fs/promises';
import { HttpRequest, HttpResponse } from '../../interfaces/http-client.js';
import { HttpClientOptions, SimulationModeOptions } from '../../interfaces/configuration.js';
import { BaseHttpClient, HttpResponseImpl } from '../../interfaces/base-http-client.js';

/** Quick config overload for simple usage */
export interface SimulationHttpConfig {
  scenarioFile?: string;
  globalLatencyMs: number;
  globalFailureRate?: number;
  pingFailureRate: number;
  defaultScenario?: { statusCode: number; body: string; headers: Record<string,string>; latencyMs: number };
}

interface Scenario {
  pattern: string;
  statusCode: number;
  body: string;
  headers: Record<string,string>;
  latencyMs: number;
  failureRate?: number;
  failureMessages?: string[];
}

/**
 * Simulation HTTP client implementation with configurable behavior patterns
 */
export class SimulationHttpClient extends BaseHttpClient {
  private scenarios: Scenario[] = [];
  private defaultScenarios: Scenario[] = [];
  private opts: SimulationModeOptions;
  private logger: Console;

  // Overloads
  constructor(options: HttpClientOptions, opts: SimulationModeOptions, logger?: Console);
  constructor(cfg: SimulationHttpConfig, logger?: Console);
  constructor(a: HttpClientOptions|SimulationHttpConfig, b?: SimulationModeOptions|Console, c?: Console) {
    if ((a as HttpClientOptions).defaultTimeoutMs !== undefined) {
      super(a as HttpClientOptions);
      this.opts = b as SimulationModeOptions;
      this.logger = c || console;
    } else {
      super({ defaultTimeoutMs: 0, userAgent:'', defaultHeaders:{}, maxRetries:0 });
      const cfg = a as SimulationHttpConfig;
      this.opts = {
        scenarioPath: cfg.scenarioFile ?? '',
        globalLatencyMs: cfg.globalLatencyMs,
        globalFailureRate: cfg.globalFailureRate ?? 0,
        minPingLatencyMs: cfg.defaultScenario?.latencyMs ?? 0,
        maxPingLatencyMs: cfg.defaultScenario?.latencyMs ?? 0,
        pingFailureRate: cfg.pingFailureRate
      };
      this.logger = (b as Console) || console;
    }
    this.initDefaults();
    this.loadScenarios();
  }

  public getMode(): string { return 'simulation'; }

  public getStats() {
    return {
      defaultScenarios: this.defaultScenarios.length,
      customScenarios: this.scenarios.length,
      totalScenarios: this.defaultScenarios.length + this.scenarios.length
    };
  }

  public addScenario(s: Scenario): void {
    this.scenarios.push(s);
    this.logger.debug?.(`Added custom simulation scenario for pattern: ${s.pattern}`);
  }

  public clearCustomScenarios(): void {
    this.scenarios = [];
    this.logger.debug?.('Cleared all custom simulation scenarios');
  }

  public async executeAsync(request: HttpRequest): Promise<HttpResponse> {
    this.logger.debug?.(`Simulation HTTP client executing ${request.method} request to ${request.url}`);
    const sc = this.findScenario(request.url);
    const lat = sc.latencyMs;
    if (lat > 0) await this.delay(lat);
    if (Math.random() < (sc.failureRate ?? 0)) {
      const msgs = sc.failureMessages ?? [];
      const err = msgs.length ? msgs[Math.floor(Math.random()*msgs.length)] : 'Simulated network failure';
      this.logger.debug?.(`Simulation HTTP client simulating failure for ${request.url}: ${err}`);
      return new HttpResponseImpl({ statusCode:0, body:'', headers:{}, errorMessage:err });
    }
    const gl = this.opts.globalLatencyMs;
    if (gl > 0) await this.delay(gl);
    this.logger.debug?.(`Simulation HTTP client returning status ${sc.statusCode} for ${request.url}`);
    const body = sc.body.replace(/\{\{url\}\}/g, request.url)
                       .replace(/\{\{method\}\}/g, request.method.toUpperCase())
                       .replace(/\{\{timestamp\}\}/g, new Date().toISOString());
    return new HttpResponseImpl({ statusCode: sc.statusCode, body, headers:{...sc.headers}, errorMessage: sc.statusCode>=400?`Simulated error ${sc.statusCode}`:undefined });
  }

  public async pingAsync(url?: string): Promise<boolean> {
    const u = url ?? '';
    this.logger.debug?.(`Simulation HTTP client ping to ${u}`);
    const lat = this.randomBetween(this.opts.minPingLatencyMs, this.opts.maxPingLatencyMs);
    if (lat>0) await this.delay(lat);
    return Math.random() >= this.opts.pingFailureRate;
  }

  private initDefaults(): void {
    this.defaultScenarios = [
      { pattern:'/users', statusCode:200, body:JSON.stringify({message:'success'}), headers:{'Content-Type':'application/json'}, latencyMs:50 },
      { pattern:'/health', statusCode:200, body:JSON.stringify({status:'healthy',timestamp:'{{timestamp}}'}), headers:{'Content-Type':'application/json'}, latencyMs:10 },
      { pattern:'/slow/*', statusCode:200, body:JSON.stringify({message:'This was slow',url:'{{url}}'}), headers:{'Content-Type':'application/json'}, latencyMs:2000 },
      { pattern:'/error/*', statusCode:500, body:JSON.stringify({error:'Simulated server error',method:'{{method}}'}), headers:{'Content-Type':'application/json'}, latencyMs:100 },
      { pattern:'/custom/*', statusCode:201, body:JSON.stringify({message:'Custom response',timestamp:'{{timestamp}}'}), headers:{'Content-Type':'application/json','X-Custom-Header':'simulation'}, latencyMs:150 },
      { pattern:'*', statusCode:200, body:JSON.stringify({message:'Default simulation response',url:'{{url}}',method:'{{method}}'}), headers:{'Content-Type':'application/json'}, latencyMs:100 }
    ];
  }

  private findScenario(url: string): Scenario {
    for (const s of this.scenarios) if (this.match(url,s.pattern)) return s;
    const defs = [...this.defaultScenarios].sort((a,b)=>b.pattern.length-a.pattern.length);
    for (const s of defs) if (this.match(url,s.pattern)) return s;
    return this.defaultScenarios.find(s=>s.pattern==='*')!;
  }

  private match(url:string,pat:string):boolean {
    if (pat==='*') return true;
    let tgt = url;
    if (pat.startsWith('/')) {
      try { tgt = new URL(url).pathname; } catch { tgt = url.startsWith('/')?url:'/'.concat(url);}      
    }
    if (pat.includes('*')) { const rx=new RegExp('^'+pat.replace(/\*/g,'.*')+'$','i'); return rx.test(tgt);}    
    return tgt.includes(pat);
  }

  private randomBetween(min:number,max:number): number { return Math.floor(Math.random()*(max-min+1))+min; }
  private delay(ms:number): Promise<void> { return new Promise(r=>setTimeout(r,ms)); }

  private async loadScenarios(): Promise<void> {
    const p = (this.opts as any).scenarioPath;
    if (!p) return;
    try {
      const txt = await fs.readFile(p,'utf8');
      const data = JSON.parse(txt);
      const arr = Array.isArray(data)?data:data.scenarios||[];
      this.scenarios.push(...arr as Scenario[]);
      this.logger.debug?.(`Loaded ${this.scenarios.length} scenarios from ${p}`);
    } catch (e) {
      this.logger.error?.(`Failed to load simulation scenarios from ${p}:`,e);
    }
  }
}
