// Jest setup file for OAuth2 client tests
import { jest } from '@jest/globals';

// Global test configuration
jest.setTimeout(30000);

// Mock global fetch if not available
if (!global.fetch) {
  global.fetch = jest.fn();
}

// Mock console methods to reduce noise during testing
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn()
};

// Mock timers for auto-refresh tests
beforeEach(() => {
  jest.clearAllTimers();
  jest.useFakeTimers();
});

afterEach(() => {
  jest.runOnlyPendingTimers();
  jest.useRealTimers();
  jest.clearAllMocks();
});

// Global test helpers
declare global {
  namespace jest {
    interface Matchers<R> {
      toBeValidURL(): R;
      toBeValidJWT(): R;
    }
  }
}

// Custom Jest matchers
expect.extend({
  toBeValidURL(received: string) {
    try {
      new URL(received);
      return {
        message: () => `expected ${received} not to be a valid URL`,
        pass: true
      };
    } catch {
      return {
        message: () => `expected ${received} to be a valid URL`,
        pass: false
      };
    }
  },

  toBeValidJWT(received: string) {
    const parts = received.split('.');
    if (parts.length !== 3) {
      return {
        message: () => `expected ${received} to be a valid JWT (should have 3 parts)`,
        pass: false
      };
    }

    try {
      // Validate base64url encoding of header and payload
      JSON.parse(Buffer.from(parts[0], 'base64url').toString());
      JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      return {
        message: () => `expected ${received} not to be a valid JWT`,
        pass: true
      };
    } catch {
      return {
        message: () => `expected ${received} to be a valid JWT (invalid base64url encoding)`,
        pass: false
      };
    }
  }
});

// Test utilities
export class TestUtils {
  static async waitFor(conditionFn: () => boolean | Promise<boolean>, timeoutMs: number = 5000): Promise<void> {
    const startTime = Date.now();
    while (Date.now() - startTime < timeoutMs) {
      if (await conditionFn()) {
        return;
      }
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    throw new Error(`Condition not met within ${timeoutMs}ms`);
  }

  static createMockResponse(data: any, status: number = 200, headers: Record<string, string> = {}): Response {
    return {
      ok: status >= 200 && status < 300,
      status,
      statusText: status === 200 ? 'OK' : 'Error',
      headers: new Headers(headers),
      json: async () => data,
      text: async () => JSON.stringify(data),
      clone: () => TestUtils.createMockResponse(data, status, headers)
    } as Response;
  }

  static randomString(length: number = 32): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  static async simulateNetworkDelay(ms: number = 100): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Export commonly used types for tests
export type MockFunction<T extends (...args: any[]) => any> = jest.MockedFunction<T>;
