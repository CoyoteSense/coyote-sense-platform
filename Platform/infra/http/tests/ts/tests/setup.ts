/**
 * Jest Test Setup
 * 
 * Global setup and configuration for Jest tests.
 */

// Mock global fetch for testing
global.fetch = jest.fn();

// Mock console methods to avoid noise in tests
global.console = {
  ...console,
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

beforeEach(() => {
  jest.clearAllMocks();
});

// Extend Jest matchers if needed
declare global {
  namespace jest {
    interface Matchers<R> {
      // Add custom matchers here if needed
    }
  }
}

export {};
