#pragma once

#include "auth_interfaces.h"
#include "auth_types.h"

/**
 * @file auth_client.h
 * @brief Main include file for C++ Authentication Client
 * 
 * This file provides the main authentication client interface that matches 
 * the C# IAuthClient interface. It supports multiple authentication standards:
 * - OAuth2 Client Credentials (RFC 6749)
 * - OAuth2 Authorization Code (RFC 6749) 
 * - JWT Bearer Token (RFC 7523)
 * - Mutual TLS (RFC 8705)
 */

namespace coyote {
namespace infra {
namespace security {
namespace auth {

// Re-export the main interfaces for convenience
using AuthClientInterface = IAuthClient;
using TokenStorage = IAuthTokenStorage; 
using AuthLogger = IAuthLogger;

// Factory functions for creating auth components
std::shared_ptr<IAuthTokenStorage> create_memory_token_storage();
std::shared_ptr<IAuthLogger> create_console_logger(const std::string& prefix = "Auth");
std::shared_ptr<IAuthLogger> create_null_logger();

std::unique_ptr<IAuthClient> create_auth_client(
    const AuthClientOptions& options,
    std::shared_ptr<coyote::infra::IHttpClient> http_client = nullptr,
    std::shared_ptr<IAuthTokenStorage> token_storage = nullptr,
    std::shared_ptr<IAuthLogger> logger = nullptr
);

} // namespace auth
} // namespace security
} // namespace infra
} // namespace coyote
