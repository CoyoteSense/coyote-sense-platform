import { 
  MockHttpClient, 
  DebugHttpClient, 
  RealHttpClient,
  RecordHttpClient,
  ReplayHttpClient,
  SimulationHttpClient,
  createHttpClient,
  HttpMethod,
  HttpRequest,
  DEFAULT_HTTP_OPTIONS,
  DEFAULT_MOCK_OPTIONS,
  DEFAULT_DEBUG_OPTIONS,
  RuntimeMode
} from '../index';

async function demonstrateHttpClients() {
  console.log('🚀 TypeScript HTTP Client Infrastructure Demo\n');

  // 1. Mock Client
  console.log('1️⃣ Mock HTTP Client');
  const mockClient = new MockHttpClient(DEFAULT_HTTP_OPTIONS, DEFAULT_MOCK_OPTIONS);
  
  const testRequest: HttpRequest = {
    method: HttpMethod.GET,
    url: 'https://api.example.com/users',
    headers: { 'Authorization': 'Bearer token123' },
    body: ''
  };

  const mockResponse = await mockClient.executeAsync(testRequest);
  console.log(`   Status: ${mockResponse.statusCode}, Body: ${mockResponse.body.substring(0, 50)}...`);

  // 2. Debug Client (wrapping Mock)
  console.log('\n2️⃣ Debug HTTP Client (wrapping Mock)');
  const debugClient = new DebugHttpClient(DEFAULT_HTTP_OPTIONS, DEFAULT_DEBUG_OPTIONS, mockClient);
  
  const debugResponse = await debugClient.executeAsync(testRequest);
  console.log(`   Status: ${debugResponse.statusCode}, Success: ${debugResponse.isSuccess}`);

  // 3. Real Client (with actual network request)
  console.log('\n3️⃣ Real HTTP Client');
  const realClient = new RealHttpClient(DEFAULT_HTTP_OPTIONS);
  
  try {
    const pingRequest: HttpRequest = {
      method: HttpMethod.GET,
      url: 'https://httpbin.org/get',
      headers: {},
      body: ''
    };
    
    const realResponse = await realClient.executeAsync(pingRequest);
    console.log(`   Status: ${realResponse.statusCode}, Success: ${realResponse.isSuccess}`);
  } catch (error) {
    console.log(`   Network request failed (expected in some environments): ${error}`);
  }

  // 4. Record Client
  console.log('\n4️⃣ Record HTTP Client');
  const recordClient = new RecordHttpClient(
    DEFAULT_HTTP_OPTIONS, 
    { recordingDirectory: './recordings' }, 
    mockClient
  );
  
  const recordResponse = await recordClient.executeAsync(testRequest);
  console.log(`   Status: ${recordResponse.statusCode}, Recording enabled`);

  // 5. Replay Client
  console.log('\n5️⃣ Replay HTTP Client');
  const replayClient = new ReplayHttpClient(
    DEFAULT_HTTP_OPTIONS,
    { recordingDirectory: './recordings' }
  );
  
  try {
    const replayResponse = await replayClient.executeAsync(testRequest);
    console.log(`   Status: ${replayResponse.statusCode}, Replaying from recordings`);
  } catch (error) {
    console.log(`   No recordings found (expected): ${error}`);
  }

  // 6. Simulation Client
  console.log('\n6️⃣ Simulation HTTP Client');
  const simulationClient = new SimulationHttpClient(
    DEFAULT_HTTP_OPTIONS,
    { 
      scenarios: [
        {
          urlPattern: /.*users.*/,
          responseStatusCode: 200,
          responseBody: '{"simulation": "user_data"}',
          responseHeaders: { 'Content-Type': 'application/json' },
          delayMs: 100
        }
      ]
    }
  );
  
  const simulationResponse = await simulationClient.executeAsync(testRequest);
  console.log(`   Status: ${simulationResponse.statusCode}, Body: ${simulationResponse.body}`);

  // 7. Factory Pattern
  console.log('\n7️⃣ Factory Pattern - Creating Mock Client');
  const factoryClient = createHttpClient({
    mode: {
      mock: DEFAULT_MOCK_OPTIONS,
      debug: DEFAULT_DEBUG_OPTIONS,
      record: { recordingDirectory: './recordings' },
      replay: { recordingDirectory: './recordings' },
      simulation: { scenarios: [] }
    },
    options: DEFAULT_HTTP_OPTIONS,
    runtimeMode: RuntimeMode.TESTING
  });
  
  const factoryResponse = await factoryClient.executeAsync(testRequest);
  console.log(`   Status: ${factoryResponse.statusCode}, Created via factory`);

  console.log('\n✅ All HTTP client modes demonstrated successfully!');
}

// Run the demonstration
demonstrateHttpClients().catch(console.error);
