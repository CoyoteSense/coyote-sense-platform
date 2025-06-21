using System;
using System.Net.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Coyote.Infra.Security.Auth.Options;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Security.Auth.Modes.Real;
using Coyote.Infra.Http;

namespace Coyote.Infra.Security.Auth.Extensions;

/// <summary>
/// Extensions for auth client configuration
/// </summary>
public static class AuthClientExtensions
{    public static IAuthClient CreateFromOptions(this ICoyoteAuthClientFactory factory, MtlsOptions options)
    {
        if (options == null)
            throw new ArgumentNullException(nameof(options));

        var config = options.ToAuthClientConfig();
        var authOptions = config.ToAuthClientOptions();
          // Create the client directly since static factory is causing issues
        using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
        var logger = loggerFactory.CreateLogger<RealAuthClient>();
        
        return new RealAuthClient(authOptions, logger);
    }
}

/// <summary>
/// Simple HTTP client factory for extension usage
/// </summary>
internal class SimpleHttpClientFactory : IHttpClientFactory
{
    public HttpClient CreateClient(string name)
    {
        return new HttpClient();
    }
}
