#include "http_client_factory.h"
#include "../impl/real/http_client_real.h"
#include "../impl/mock/http_client_mock.h"
#include "../impl/debug/http_client_debug.h"
#include <cstdlib>
#include <algorithm>
#include <stdexcept>

namespace coyote {
namespace infra {

std::unique_ptr<HttpClient> HttpClientFactory::CreateClient() {
  return CreateClient(GetCurrentMode());
}

std::unique_ptr<HttpClient> HttpClientFactory::CreateClient(RuntimeMode mode) {
  switch (mode) {
    case RuntimeMode::kProduction:
    case RuntimeMode::kRecording:
    case RuntimeMode::kReplay:
    case RuntimeMode::kSimulation:
    case RuntimeMode::kDebug:
      return std::make_unique<HttpClientReal>();
      
    case RuntimeMode::kTesting:
      return std::make_unique<mocks::HttpClientMock>();
      
    default:
      throw std::invalid_argument("Unsupported runtime mode for HTTP client");
  }
}

RuntimeMode HttpClientFactory::GetCurrentMode() {
  const char* mode_env = std::getenv("MODE");
  if (mode_env == nullptr) {
    mode_env = std::getenv("COYOTE_RUNTIME_MODE");
  }
  
  if (mode_env == nullptr) {
    // Default to production mode if no environment variable is set
    return RuntimeMode::kProduction;
  }
  
  return ParseModeFromString(std::string(mode_env));
}

RuntimeMode HttpClientFactory::ParseModeFromString(const std::string& mode_str) {
  std::string lower_mode = mode_str;
  std::transform(lower_mode.begin(), lower_mode.end(), lower_mode.begin(), ::tolower);
  
  if (lower_mode == "production") {
    return RuntimeMode::kProduction;
  } else if (lower_mode == "recording") {
    return RuntimeMode::kRecording;
  } else if (lower_mode == "replay") {
    return RuntimeMode::kReplay;
  } else if (lower_mode == "simulation") {
    return RuntimeMode::kSimulation;
  } else if (lower_mode == "debug") {
    return RuntimeMode::kDebug;
  } else if (lower_mode == "testing") {
    return RuntimeMode::kTesting;
  } else {
    // Default to production for unknown modes
    return RuntimeMode::kProduction;
  }
}

std::unique_ptr<HttpClient> MakeHttpClient() {
  return HttpClientFactory::CreateClient();
}

}  // namespace infra
}  // namespace coyote