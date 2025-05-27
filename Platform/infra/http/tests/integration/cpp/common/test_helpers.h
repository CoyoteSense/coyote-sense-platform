#pragma once

#include <string>

namespace test_helpers {

/**
 * Set an environment variable for testing
 * @param name The environment variable name
 * @param value The value to set
 */
void SetTestEnvironmentVariable(const std::string& name, const std::string& value);

/**
 * Get an environment variable with optional default value
 * @param name The environment variable name
 * @param default_value Default value if not found
 * @return The environment variable value or default
 */
std::string GetTestEnvironmentVariable(const std::string& name, const std::string& default_value = "");

/**
 * Remove an environment variable
 * @param name The environment variable name
 */
void UnsetEnvironmentVariable(const std::string& name);

/**
 * Wait for a TCP port to become available
 * @param host The hostname/IP to check
 * @param port The port number
 * @param timeout_seconds Maximum time to wait in seconds
 * @return true if port becomes available, false if timeout
 */
bool WaitForPort(const std::string& host, int port, int timeout_seconds = 30);

/**
 * Check if a TCP port is currently open/available
 * @param host The hostname/IP to check
 * @param port The port number
 * @return true if port is open, false otherwise
 */
bool IsPortOpen(const std::string& host, int port);

/**
 * Generate a random string for test data
 * @param length The desired length
 * @return A random string
 */
std::string GenerateRandomString(size_t length);

/**
 * Parse JSON string and extract a value
 * @param json_str The JSON string
 * @param key The key to extract
 * @return The extracted value or empty string if not found
 */
std::string ExtractJsonValue(const std::string& json_str, const std::string& key);

/**
 * URL encode a string
 * @param value The string to encode
 * @return URL encoded string
 */
std::string UrlEncode(const std::string& value);

}  // namespace test_helpers
