# OAuth2 Factory Usage Examples

This document demonstrates how to use the OAuth2 authentication factories across different programming languages in the CoyoteSense platform.

## TypeScript/JavaScript Factory Usage

### TypeScript Example

```typescript
import { AuthClientFactory, AuthMode } from '../factory/ts/oauth2-client-factory';
import { CoyoteHttpClient } from '../../http/ts';

// Create client using factory methods
const httpClient = new CoyoteHttpClient();

// Client Credentials flow
const clientCredsClient = AuthClientFactory.createClientCredentials(
  'https://auth.example.com',
  'my-client-id',
  'my-client-secret',
  ['read', 'write'],
  httpClient
);

// mTLS flow
const mtlsClient = AuthClientFactory.createClientCredentialsMtls(
  'https://auth.example.com',
  'my-client-id',
  '/path/to/client.crt',
  '/path/to/client.key',
  '/path/to/ca.crt',
  ['read', 'write'],
  httpClient
);

// JWT Bearer flow
const jwtClient = AuthClientFactory.createJwtBearer(
  'https://auth.example.com',
  'my-client-id',
  '/path/to/signing.key',
  'my-issuer',
  'my-audience',
  'RS256',
  ['read', 'write'],
  httpClient
);

// Authorization Code flow
const authCodeClient = AuthClientFactory.createAuthorizationCode(
  'https://auth.example.com',
  'my-client-id',
  'https://my-app.com/callback',
  ['read', 'write'],
  httpClient
);

// Authorization Code with PKCE flow
const pkceClient = AuthClientFactory.createAuthorizationCodePkce(
  'https://auth.example.com',
  'my-client-id',
  'https://my-app.com/callback',
  ['read', 'write'],
  httpClient
);

// Using builder pattern for custom configuration
const customClient = AuthClientFactory.create()
  .serverUrl('https://auth.example.com')
  .clientCredentials('my-client-id', 'my-client-secret')
  .authMode(AuthMode.ClientCredentials)
  .defaultScopes(['read', 'write'])
  .timeout(60000)
  .autoRefresh(true, 300)
  .customHeaders({ 'User-Agent': 'CoyoteSense-Client/1.0' })
  .build(httpClient);
```

### JavaScript Example

```javascript
const { AuthClientFactory, AuthMode } = require('../factory/js/oauth2-client-factory');

// Create client using factory methods
const httpClient = new HttpClient(); // Your HTTP client implementation

// Client Credentials flow
const clientCredsClient = AuthClientFactory.createClientCredentials(
  'https://auth.example.com',
  'my-client-id',
  'my-client-secret',
  ['read', 'write'],
  httpClient
);

// Using builder pattern
const customClient = AuthClientFactory.create()
  .serverUrl('https://auth.example.com')
  .clientCredentials('my-client-id', 'my-client-secret')
  .authMode(AuthMode.CLIENT_CREDENTIALS)
  .defaultScopes(['read', 'write'])
  .timeout(60000)
  .build(httpClient);
```

## Python Factory Usage

```python
from infra.security.factory.py.oauth2_client_factory import AuthClientFactory, AuthMode
from infra.http.py.http_client import HttpClient

# Create HTTP client
http_client = HttpClient()

# Client Credentials flow
client_creds_client = AuthClientFactory.create_client_credentials(
    server_url='https://auth.example.com',
    client_id='my-client-id',
    client_secret='my-client-secret',
    scopes=['read', 'write'],
    http_client=http_client
)

# mTLS flow
mtls_client = AuthClientFactory.create_client_credentials_mtls(
    server_url='https://auth.example.com',
    client_id='my-client-id',
    client_cert_path='/path/to/client.crt',
    client_key_path='/path/to/client.key',
    ca_cert_path='/path/to/ca.crt',
    scopes=['read', 'write'],
    http_client=http_client
)

# JWT Bearer flow
jwt_client = AuthClientFactory.create_jwt_bearer(
    server_url='https://auth.example.com',
    client_id='my-client-id',
    jwt_signing_key_path='/path/to/signing.key',
    jwt_issuer='my-issuer',
    jwt_audience='my-audience',
    jwt_algorithm='RS256',
    scopes=['read', 'write'],
    http_client=http_client
)

# Authorization Code flow
auth_code_client = AuthClientFactory.create_authorization_code(
    server_url='https://auth.example.com',
    client_id='my-client-id',
    redirect_uri='https://my-app.com/callback',
    scopes=['read', 'write'],
    http_client=http_client
)

# Authorization Code with PKCE flow
pkce_client = AuthClientFactory.create_authorization_code_pkce(
    server_url='https://auth.example.com',
    client_id='my-client-id',
    redirect_uri='https://my-app.com/callback',
    scopes=['read', 'write'],
    http_client=http_client
)

# Using builder pattern for custom configuration
custom_client = (AuthClientFactory.create()
                .server_url('https://auth.example.com')
                .client_credentials('my-client-id', 'my-client-secret')
                .auth_mode(AuthMode.CLIENT_CREDENTIALS)
                .default_scopes(['read', 'write'])
                .timeout(60000)
                .auto_refresh(True, 300)
                .custom_headers({'User-Agent': 'CoyoteSense-Client/1.0'})
                .build(http_client))
```

## C# Factory Usage

```csharp
using CoyoteSense.Platform.Infra.Security.Factory.DotNet;
using CoyoteSense.Platform.Infra.Security.Interfaces.DotNet;
using CoyoteSense.Platform.Infra.Http;

// Create HTTP client
var httpClient = new CoyoteHttpClient();

// Client Credentials flow
var clientCredsClient = AuthClientFactory.CreateClientCredentialsClient(
    serverUrl: "https://auth.example.com",
    clientId: "my-client-id",
    clientSecret: "my-client-secret",
    scopes: new[] { "read", "write" },
    httpClient: httpClient
);

// mTLS flow
var mtlsClient = AuthClientFactory.CreateMtlsClient(
    serverUrl: "https://auth.example.com",
    clientId: "my-client-id",
    clientCertPath: "/path/to/client.crt",
    clientKeyPath: "/path/to/client.key",
    caCertPath: "/path/to/ca.crt",
    scopes: new[] { "read", "write" },
    httpClient: httpClient
);

// JWT Bearer flow
var jwtClient = AuthClientFactory.CreateJwtBearerClient(
    serverUrl: "https://auth.example.com",
    clientId: "my-client-id",
    jwtKeyPath: "/path/to/signing.key",
    jwtIssuer: "my-issuer",
    jwtAudience: "my-audience",
    scopes: new[] { "read", "write" },
    httpClient: httpClient
);

// Authorization Code flow
var authCodeClient = AuthClientFactory.CreateAuthorizationCodeClient(
    serverUrl: "https://auth.example.com",
    clientId: "my-client-id",
    redirectUri: "https://my-app.com/callback",
    scopes: new[] { "read", "write" },
    httpClient: httpClient
);
```

## Go Factory Usage

```go
package main

import (
    "github.com/coyotesense/platform/infra/security/factory/go"
    "github.com/coyotesense/platform/infra/http/go"
)

func main() {
    // Create HTTP client
    httpClient := http.NewHTTPClient()

    // Client Credentials flow
    clientCredsClientFunc := oauth2factory.CreateClientCredentials(
        "https://auth.example.com",
        "my-client-id",
        "my-client-secret",
        []string{"read", "write"},
    )
    clientCredsClient, err := clientCredsClientFunc(httpClient)
    if err != nil {
        panic(err)
    }

    // mTLS flow
    mtlsClientFunc := oauth2factory.CreateClientCredentialsMTLS(
        "https://auth.example.com",
        "my-client-id",
        "/path/to/client.crt",
        "/path/to/client.key",
        "/path/to/ca.crt",
        []string{"read", "write"},
    )
    mtlsClient, err := mtlsClientFunc(httpClient)
    if err != nil {
        panic(err)
    }

    // JWT Bearer flow
    jwtClientFunc := oauth2factory.CreateJWTBearer(
        "https://auth.example.com",
        "my-client-id",
        "/path/to/signing.key",
        "my-issuer",
        "my-audience",
        "RS256",
        []string{"read", "write"},
    )
    jwtClient, err := jwtClientFunc(httpClient)
    if err != nil {
        panic(err)
    }

    // Authorization Code flow
    authCodeClientFunc := oauth2factory.CreateAuthorizationCode(
        "https://auth.example.com",
        "my-client-id",
        "https://my-app.com/callback",
        []string{"read", "write"},
    )
    authCodeClient, err := authCodeClientFunc(httpClient)
    if err != nil {
        panic(err)
    }

    // Authorization Code with PKCE flow
    pkceClientFunc := oauth2factory.CreateAuthorizationCodePKCE(
        "https://auth.example.com",
        "my-client-id",
        "https://my-app.com/callback",
        []string{"read", "write"},
    )
    pkceClient, err := pkceClientFunc(httpClient)
    if err != nil {
        panic(err)
    }

    // Using builder pattern for custom configuration
    customClient, err := oauth2factory.Create().
        ServerURL("https://auth.example.com").
        ClientCredentials("my-client-id", "my-client-secret").
        AuthMode(oauth2.AuthModeClientCredentials).
        DefaultScopes([]string{"read", "write"}).
        Timeout(60000).
        AutoRefresh(true, 300).
        Build(httpClient)
    if err != nil {
        panic(err)
    }
}
```

## Common Patterns

### Error Handling

All factory methods include proper error handling and validation:

- Required parameters are validated
- Configuration consistency is checked based on authentication mode
- HTTP client must be provided
- Invalid configurations throw descriptive errors

### Builder Pattern Benefits

1. **Fluent Interface**: Chain method calls for readable configuration
2. **Default Values**: Sensible defaults for optional parameters
3. **Validation**: Built-in validation before client creation
4. **Flexibility**: Mix and match settings as needed

### Authentication Mode Validation

Each factory automatically validates that the provided configuration matches the selected authentication mode:

- **Client Credentials**: Requires client ID and secret
- **Client Credentials mTLS**: Requires client ID and certificate paths
- **JWT Bearer**: Requires client ID and JWT signing configuration
- **Authorization Code**: Requires client ID and redirect URI
- **Authorization Code PKCE**: Requires client ID, redirect URI, and enables PKCE

This ensures that clients are created with valid, complete configurations for their intended authentication flow.
