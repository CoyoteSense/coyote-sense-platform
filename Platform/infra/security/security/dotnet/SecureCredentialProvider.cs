using System;
using System.Security;
using System.Runtime.InteropServices;

namespace Coyote.Infra.Security.Auth.Security;

/// <summary>
/// Secure credential provider for handling sensitive authentication data
/// </summary>
public class SecureCredentialProvider : IDisposable
{
    private SecureString? _clientSecret;
    private SecureString? _privateKey;
    private bool _disposed;

    /// <summary>
    /// Set client secret securely
    /// </summary>
    public void SetClientSecret(string clientSecret)
    {
        _clientSecret?.Dispose();
        _clientSecret = new SecureString();
        
        foreach (char c in clientSecret)
        {
            _clientSecret.AppendChar(c);
        }
        
        _clientSecret.MakeReadOnly();
    }

    /// <summary>
    /// Set private key securely
    /// </summary>
    public void SetPrivateKey(string privateKey)
    {
        _privateKey?.Dispose();
        _privateKey = new SecureString();
        
        foreach (char c in privateKey)
        {
            _privateKey.AppendChar(c);
        }
        
        _privateKey.MakeReadOnly();
    }

    /// <summary>
    /// Get client secret as plain text (use carefully and dispose quickly)
    /// </summary>
    public string? GetClientSecret()
    {
        if (_clientSecret == null) return null;
        
        IntPtr ptr = IntPtr.Zero;
        try
        {
            ptr = Marshal.SecureStringToGlobalAllocUnicode(_clientSecret);
            return Marshal.PtrToStringUni(ptr);
        }
        finally
        {
            if (ptr != IntPtr.Zero)
            {
                Marshal.ZeroFreeGlobalAllocUnicode(ptr);
            }
        }
    }

    /// <summary>
    /// Get private key as plain text (use carefully and dispose quickly)
    /// </summary>
    public string? GetPrivateKey()
    {
        if (_privateKey == null) return null;
        
        IntPtr ptr = IntPtr.Zero;
        try
        {
            ptr = Marshal.SecureStringToGlobalAllocUnicode(_privateKey);
            return Marshal.PtrToStringUni(ptr);
        }
        finally
        {
            if (ptr != IntPtr.Zero)
            {
                Marshal.ZeroFreeGlobalAllocUnicode(ptr);
            }
        }
    }

    /// <summary>
    /// Check if client secret is available
    /// </summary>
    public bool HasClientSecret => _clientSecret != null && _clientSecret.Length > 0;

    /// <summary>
    /// Check if private key is available
    /// </summary>
    public bool HasPrivateKey => _privateKey != null && _privateKey.Length > 0;

    public void Dispose()
    {
        if (!_disposed)
        {
            _clientSecret?.Dispose();
            _privateKey?.Dispose();
            _disposed = true;
        }
    }
}

/// <summary>
/// Credential source options for loading sensitive data
/// </summary>
public enum CredentialSource
{
    /// <summary>
    /// Load from environment variables
    /// </summary>
    Environment,
    
    /// <summary>
    /// Load from Azure Key Vault
    /// </summary>
    AzureKeyVault,
    
    /// <summary>
    /// Load from file system (least secure)
    /// </summary>
    FileSystem,
    
    /// <summary>
    /// Load from Windows Credential Manager
    /// </summary>
    WindowsCredentialManager,
    
    /// <summary>
    /// Provided directly in memory
    /// </summary>
    Memory
}

/// <summary>
/// Configuration for secure credential loading
/// </summary>
public class CredentialConfiguration
{
    public CredentialSource Source { get; set; } = CredentialSource.Environment;
    
    /// <summary>
    /// For Environment source: variable name
    /// For AzureKeyVault: secret name
    /// For FileSystem: file path
    /// For WindowsCredentialManager: credential name
    /// </summary>
    public string? ClientSecretReference { get; set; }
    
    /// <summary>
    /// For private key/certificate credentials
    /// </summary>
    public string? PrivateKeyReference { get; set; }
    
    /// <summary>
    /// Azure Key Vault URI (if using AzureKeyVault source)
    /// </summary>
    public string? KeyVaultUri { get; set; }
}
