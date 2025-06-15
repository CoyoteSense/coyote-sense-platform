#pragma once

#include "../interfaces/http_client.h"
#include <memory>
#include <string>

namespace coyote {
namespace infra {

// Runtime mode enumeration
enum class RuntimeMode {
  kProduction,
  kRecording,
  kReplay,
  kSimulation,
  kDebug,
  kTesting
};

// Factory for creating HTTP clients based on runtime mode
class HttpClientFactory {
 public:
  // Create HTTP client based on current runtime mode
  static std::unique_ptr<HttpClient> CreateClient();
  
  // Create HTTP client for specific mode
  static std::unique_ptr<HttpClient> CreateClient(RuntimeMode mode);
  
  // Get current runtime mode from environment
  static RuntimeMode GetCurrentMode();
  
 private:
  static RuntimeMode ParseModeFromString(const std::string& mode_str);
};

// Convenience function for creating HTTP clients
std::unique_ptr<HttpClient> MakeHttpClient();

}  // namespace infra
}  // namespace coyote