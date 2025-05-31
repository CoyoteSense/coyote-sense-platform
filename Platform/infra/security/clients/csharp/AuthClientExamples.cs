using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Coyote.Infra.Security.Auth;

namespace Coyote.Infra.Security.Auth.Examples;

/// <summary>
/// Examples demonstrating multi-standard authentication client usage
/// </summary>
public class AuthClientExamples
{
    private const string ServerUrl = "https://auth-service.coyotesense.local";
    private const string ClientId = "coyote-unit-service";

    /// <summary>
    /// Example: Client Credentials authentication
    /// </summary>
    public static async Task ClientCredentialsExample()
    {
        Console.WriteLine("=== Client Credentials Flow Example ===");

        // Create client using factory
        using var client = AuthClientFactory.CreateClientCredentialsClient(
            serverUrl: ServerUrl,
            clientId: ClientId,
            clientSecret: "your-client-secret",
            defaultScopes: new List<string> { "read", "write" },
            logger: new ConsoleAuthLogger("ClientCredentials")
        );

        // Test connection
        var connected = await client.TestConnectionAsync();
        if (!connected)
        {
            Console.WriteLine("Failed to connect to Auth server");
            return;
        }

        // Authenticate
        var result = await client.AuthenticateClientCredentialsAsync();
        
        if (result.IsSuccess)
        {
            Console.WriteLine($"Authentication successful!");
            Console.WriteLine($"Access Token: {result.Token!.AccessToken[..20]}...");
            Console.WriteLine($"Token Type: {result.Token.TokenType}");
            Console.WriteLine($"Expires At: {result.Token.ExpiresAt}");
            Console.WriteLine($"Scopes: {string.Join(", ", result.Token.Scopes)}");

            // Use token for API calls
            await UseTokenForApiCall(result.Token);
        }
        else
        {
            Console.WriteLine($"Authentication failed: {result.ErrorCode} - {result.ErrorDescription}");
        }
    }

    /// <summary>
    /// Example: mTLS authentication
    /// </summary>
    public static async Task MtlsExample()
    {
        Console.WriteLine("\n=== mTLS Flow Example ===");

        // Create client using factory
        using var client = AuthClientFactory.CreateMtlsClient(
            serverUrl: ServerUrl,
            clientId: ClientId,
            clientCertPath: "/opt/coyote/certs/client.crt",
            clientKeyPath: "/opt/coyote/certs/client.key",
            defaultScopes: new List<string> { "read", "write" },
            logger: new ConsoleAuthLogger("mTLS")
        );

        // Authenticate using Client Credentials with mTLS
        var result = await client.AuthenticateClientCredentialsAsync();
        
        if (result.IsSuccess)
        {
            Console.WriteLine($"mTLS authentication successful!");
            Console.WriteLine($"Access Token: {result.Token!.AccessToken[..20]}...");
        }
        else
        {
            Console.WriteLine($"mTLS authentication failed: {result.ErrorCode} - {result.ErrorDescription}");
        }
    }

    /// <summary>
    /// Example: JWT Bearer authentication
    /// </summary>
    public static async Task JwtBearerExample()
    {
        Console.WriteLine("\n=== JWT Bearer Flow Example ===");

        // Create client using factory
        using var client = AuthClientFactory.CreateJwtBearerClient(
            serverUrl: ServerUrl,
            clientId: ClientId,
            jwtSigningKeyPath: "/opt/coyote/keys/jwt-signing.key",
            jwtIssuer: "coyote-unit-service",
            jwtAudience: ServerUrl,
            defaultScopes: new List<string> { "read", "write" },
            logger: new ConsoleAuthLogger("JwtBearer")
        );

        // Authenticate using JWT Bearer
        var result = await client.AuthenticateJwtBearerAsync(subject: "service-account");
        
        if (result.IsSuccess)
        {
            Console.WriteLine($"JWT Bearer authentication successful!");
            Console.WriteLine($"Access Token: {result.Token!.AccessToken[..20]}...");
        }
        else
        {
            Console.WriteLine($"JWT Bearer authentication failed: {result.ErrorCode} - {result.ErrorDescription}");
        }
    }

    /// <summary>
    /// Example: Authorization Code + PKCE flow
    /// </summary>
    public static async Task AuthorizationCodeExample()
    {
        Console.WriteLine("\n=== Authorization Code + PKCE Flow Example ===");

        // Create client using factory
        using var client = AuthClientFactory.CreateAuthorizationCodeClient(
            serverUrl: ServerUrl,
            clientId: ClientId,
            defaultScopes: new List<string> { "read", "write", "profile" },
            logger: new ConsoleAuthLogger("AuthCode")
        );

        var redirectUri = "http://localhost:8080/callback";

        // Start authorization flow
        var (authUrl, codeVerifier, state) = await client.StartAuthorizationCodeFlowAsync(
            redirectUri: redirectUri,
            scopes: new List<string> { "read", "write", "profile" }
        );

        Console.WriteLine($"Please visit this URL to authorize the application:");
        Console.WriteLine(authUrl);
        Console.WriteLine();
        Console.WriteLine("After authorization, copy the 'code' parameter from the callback URL:");
        
        // In a real application, you would:
        // 1. Open a browser to the authorization URL
        // 2. User logs in and authorizes the application
        // 3. Browser redirects to your callback URL with an authorization code
        // 4. Extract the code from the callback URL
        
        Console.Write("Enter the authorization code: ");
        var authorizationCode = Console.ReadLine();
        
        if (!string.IsNullOrEmpty(authorizationCode))
        {
            // Exchange authorization code for tokens
            var result = await client.AuthenticateAuthorizationCodeAsync(
                authorizationCode: authorizationCode,
                redirectUri: redirectUri,
                codeVerifier: codeVerifier
            );
            
            if (result.IsSuccess)
            {
                Console.WriteLine($"Authorization Code authentication successful!");
                Console.WriteLine($"Access Token: {result.Token!.AccessToken[..20]}...");
                Console.WriteLine($"Refresh Token: {result.Token.RefreshToken?[..20]}...");
                
                // Test token refresh
                if (!string.IsNullOrEmpty(result.Token.RefreshToken))
                {
                    await TestTokenRefresh(client, result.Token.RefreshToken);
                }
            }
            else
            {
                Console.WriteLine($"Authorization Code authentication failed: {result.ErrorCode} - {result.ErrorDescription}");
            }
        }
    }

    /// <summary>
    /// Example: Using the fluent builder API
    /// </summary>
    public static async Task FluentBuilderExample()
    {
        Console.WriteLine("\n=== Fluent Builder API Example ===");

        // Create client using fluent builder
        using var client = AuthClientFactory.CreateBuilder(ServerUrl, ClientId)
            .WithClientSecret("your-client-secret")
            .WithDefaultScopes("read", "write", "admin")
            .WithAutoRefresh(enabled: true, bufferSeconds: 300)
            .WithTimeout(30000)
            .WithSslVerification(true)
            .WithLogger(new ConsoleAuthLogger("Builder"))
            .WithTokenStorage(new InMemoryTokenStorage())
            .Build();

        // Authenticate
        var result = await client.AuthenticateClientCredentialsAsync();
        
        if (result.IsSuccess)
        {
            Console.WriteLine($"Fluent builder authentication successful!");
            Console.WriteLine($"Access Token: {result.Token!.AccessToken[..20]}...");
            
            // Test automatic token refresh
            await TestAutomaticRefresh(client);
        }
        else
        {
            Console.WriteLine($"Fluent builder authentication failed: {result.ErrorCode} - {result.ErrorDescription}");
        }
    }

    /// <summary>
    /// Example: Token management operations
    /// </summary>
    public static async Task TokenManagementExample()
    {
        Console.WriteLine("\n=== Token Management Example ===");

        using var client = AuthClientFactory.CreateClientCredentialsClient(
            serverUrl: ServerUrl,
            clientId: ClientId,
            clientSecret: "your-client-secret",
            logger: new ConsoleAuthLogger("TokenMgmt")
        );

        // Authenticate
        var result = await client.AuthenticateClientCredentialsAsync();
        
        if (result.IsSuccess)
        {
            var token = result.Token!;
            Console.WriteLine($"Token acquired: {token.AccessToken[..20]}...");

            // Test token introspection
            var isActive = await client.IntrospectTokenAsync(token.AccessToken);
            Console.WriteLine($"Token introspection result: {(isActive ? "Active" : "Inactive")}");

            // Test getting valid token (should return current token)
            var validToken = await client.GetValidTokenAsync();
            Console.WriteLine($"Valid token check: {(validToken != null ? "Valid" : "Invalid")}");

            // Test token revocation
            var revoked = await client.RevokeTokenAsync(token.AccessToken);
            Console.WriteLine($"Token revocation result: {(revoked ? "Success" : "Failed")}");

            // Clear tokens
            client.ClearTokens();
            Console.WriteLine("Tokens cleared");
        }
    }

    /// <summary>
    /// Example: Server discovery
    /// </summary>
    public static async Task ServerDiscoveryExample()
    {
        Console.WriteLine("\n=== Server Discovery Example ===");

        using var client = AuthClientFactory.CreateClientCredentialsClient(
            serverUrl: ServerUrl,
            clientId: ClientId,
            clientSecret: "your-client-secret",
            logger: new ConsoleAuthLogger("Discovery")
        );

        // Get server information
        var serverInfo = await client.GetServerInfoAsync();
        
        if (serverInfo != null)
        {
            Console.WriteLine("Auth Server Information:");
            Console.WriteLine($"  Authorization Endpoint: {serverInfo.AuthorizationEndpoint}");
            Console.WriteLine($"  Token Endpoint: {serverInfo.TokenEndpoint}");
            Console.WriteLine($"  Introspection Endpoint: {serverInfo.IntrospectionEndpoint}");
            Console.WriteLine($"  Revocation Endpoint: {serverInfo.RevocationEndpoint}");
            Console.WriteLine($"  Supported Grant Types: {string.Join(", ", serverInfo.GrantTypesSupported)}");
            Console.WriteLine($"  Supported Scopes: {string.Join(", ", serverInfo.ScopesSupported)}");
        }
        else
        {
            Console.WriteLine("Failed to retrieve server information");
        }
    }

    private static async Task UseTokenForApiCall(AuthToken token)
    {
        // Simulate using the token for API calls
        Console.WriteLine($"Using token for API call: Authorization: {token.GetAuthorizationHeader()}");
        
        // In a real application, you would add the Authorization header to your HTTP requests:
        // httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);
        
        await Task.Delay(100); // Simulate API call
        Console.WriteLine("API call completed successfully");
    }

    private static async Task TestTokenRefresh(IAuthAuthClient client, string refreshToken)
    {
        Console.WriteLine("\nTesting token refresh...");
        
        var refreshResult = await client.RefreshTokenAsync(refreshToken);
        
        if (refreshResult.IsSuccess)
        {
            Console.WriteLine($"Token refresh successful!");
            Console.WriteLine($"New Access Token: {refreshResult.Token!.AccessToken[..20]}...");
        }
        else
        {
            Console.WriteLine($"Token refresh failed: {refreshResult.ErrorCode} - {refreshResult.ErrorDescription}");
        }
    }

    private static async Task TestAutomaticRefresh(IAuthAuthClient client)
    {
        Console.WriteLine("\nTesting automatic token refresh...");
        
        // Wait a bit to simulate token aging
        await Task.Delay(1000);
        
        // Get valid token (should trigger automatic refresh if needed)
        var validToken = await client.GetValidTokenAsync();
        
        if (validToken != null)
        {
            Console.WriteLine($"Automatic refresh check passed: {validToken.AccessToken[..20]}...");
        }
        else
        {
            Console.WriteLine("Automatic refresh check failed");
        }
    }

    /// <summary>
    /// Run all examples
    /// </summary>
    public static async Task RunAllExamples()
    {
        try
        {
            await ClientCredentialsExample();
            await MtlsExample();
            await JwtBearerExample();
            await AuthorizationCodeExample();
            await FluentBuilderExample();
            await TokenManagementExample();
            await ServerDiscoveryExample();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Example error: {ex.Message}");
        }
    }
}
