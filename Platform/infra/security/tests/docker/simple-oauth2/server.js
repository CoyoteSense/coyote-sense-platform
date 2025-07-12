const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = 8080;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// OAuth2 configuration
const OAUTH2_CONFIG = {
  issuer: 'http://localhost:8081',
  authorization_endpoint: 'http://localhost:8081/oauth/authorize',
  token_endpoint: 'http://localhost:8081/token',
  userinfo_endpoint: 'http://localhost:8081/userinfo',
  introspection_endpoint: 'http://localhost:8081/introspect',
  revocation_endpoint: 'http://localhost:8081/revoke',
  jwks_uri: 'http://localhost:8081/.well-known/jwks.json',
  response_types_supported: ['code', 'token'],
  subject_types_supported: ['public'],
  id_token_signing_alg_values_supported: ['RS256'],
  scopes_supported: ['openid', 'profile', 'email', 'api.read', 'api.write'],
  token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
  claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'name', 'email']
};

// Test clients
const CLIENTS = {
  'test-client-id': {
    client_id: 'test-client-id',
    client_secret: 'test-client-secret',
    scopes: ['openid', 'profile', 'email', 'api.read', 'api.write']
  },
  'integration-test-client': {
    client_id: 'integration-test-client',
    client_secret: 'integration-test-secret',
    scopes: ['api.read', 'api.write']
  }
};

// Token storage
const tokens = new Map();

// Helper functions
function generateToken() {
  return 'mock-access-token-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
}

function validateClient(clientId, clientSecret) {
  const client = CLIENTS[clientId];
  return client && client.client_secret === clientSecret;
}

function parseBasicAuth(authHeader) {
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return null;
  }
  
  try {
    const base64Credentials = authHeader.slice(6);
    const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
    const [clientId, clientSecret] = credentials.split(':');
    return { clientId, clientSecret };
  } catch (error) {
    return null;
  }
}

// OAuth2 Discovery endpoint
app.get('/.well-known/oauth2', (req, res) => {
  res.json(OAUTH2_CONFIG);
});

// Token endpoint
app.post('/token', (req, res) => {
  console.log('Token request:', req.body);
  
  let clientId, clientSecret;
  
  // Check for client credentials in Authorization header (Basic auth)
  if (req.headers.authorization) {
    const auth = parseBasicAuth(req.headers.authorization);
    if (auth) {
      clientId = auth.clientId;
      clientSecret = auth.clientSecret;
    }
  }
  
  // Check for client credentials in request body
  if (!clientId) {
    clientId = req.body.client_id;
    clientSecret = req.body.client_secret;
  }
  
  if (!validateClient(clientId, clientSecret)) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Invalid client credentials'
    });
  }
  
  const grantType = req.body.grant_type;
  
  if (grantType === 'client_credentials') {
    const accessToken = generateToken();
    const tokenData = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: req.body.scope || 'api.read api.write',
      client_id: clientId,
      created_at: Date.now()
    };
    
    tokens.set(accessToken, tokenData);
    
    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: tokenData.scope
    });
  } else {
    res.status(400).json({
      error: 'unsupported_grant_type',
      error_description: 'Grant type not supported'
    });
  }
});

// Introspection endpoint
app.post('/introspect', (req, res) => {
  console.log('Introspection request:', req.body);
  
  const token = req.body.token;
  if (!token) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Missing token parameter'
    });
  }
  
  const tokenData = tokens.get(token);
  if (!tokenData) {
    return res.json({ active: false });
  }
  
  // Check if token is expired
  const now = Date.now();
  const expiresAt = tokenData.created_at + (tokenData.expires_in * 1000);
  if (now >= expiresAt) {
    tokens.delete(token);
    return res.json({ active: false });
  }
  
  res.json({
    active: true,
    client_id: tokenData.client_id,
    scope: tokenData.scope,
    exp: Math.floor(expiresAt / 1000),
    iat: Math.floor(tokenData.created_at / 1000)
  });
});

// Revocation endpoint
app.post('/revoke', (req, res) => {
  console.log('Revocation request:', req.body);
  
  const token = req.body.token;
  if (token && tokens.has(token)) {
    tokens.delete(token);
  }
  
  res.status(200).send();
});

// UserInfo endpoint
app.get('/userinfo', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Missing or invalid access token'
    });
  }
  
  const token = authHeader.slice(7);
  const tokenData = tokens.get(token);
  
  if (!tokenData) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Token not found or expired'
    });
  }
  
  res.json({
    sub: '1234567890',
    name: 'Test User',
    email: 'test@example.com',
    email_verified: true
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`OAuth2 Mock Server running on port ${PORT}`);
  console.log(`Discovery endpoint: http://localhost:${PORT}/.well-known/oauth2`);
  console.log('Available clients:');
  Object.values(CLIENTS).forEach(client => {
    console.log(`  - ${client.client_id} (scopes: ${client.scopes.join(', ')})`);
  });
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down OAuth2 Mock Server...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\nShutting down OAuth2 Mock Server...');
  process.exit(0);
});
