import { MockHttpClient, DEFAULT_HTTP_OPTIONS, DEFAULT_MOCK_OPTIONS, HttpMethod } from './dist/index.js';

async function simpleDemonstration() {
  console.log('🚀 TypeScript HTTP Client - Simple Demo');
  
  try {
    // Test that our built library works
    const client = new MockHttpClient(DEFAULT_HTTP_OPTIONS, DEFAULT_MOCK_OPTIONS);
    
    const request = {
      method: HttpMethod.GET,
      url: 'https://api.example.com/test',
      headers: {},
      body: ''
    };
    
    const response = await client.executeAsync(request);
    
    console.log('✅ Mock client works!');
    console.log(`   Status: ${response.statusCode}`);
    console.log(`   Success: ${response.isSuccess}`);
    console.log(`   Body: ${response.body.substring(0, 100)}...`);
    
  } catch (error) {
    console.error('❌ Error:', error.message);
    console.error(error.stack);
  }
}

simpleDemonstration();
