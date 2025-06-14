import { RealHttpClient } from '../src/modes/real/real-http-client';
import { DEFAULT_HTTP_OPTIONS } from '../src/interfaces/configuration';

describe('RealHttpClient', () => {
  test('should create instance', () => {
    const client = new RealHttpClient(DEFAULT_HTTP_OPTIONS);
    expect(client).toBeDefined();
  });

  test('should have required methods', () => {
    const client = new RealHttpClient(DEFAULT_HTTP_OPTIONS);
    expect(typeof client.executeAsync).toBe('function');
    expect(typeof client.dispose).toBe('function');
  });
});
