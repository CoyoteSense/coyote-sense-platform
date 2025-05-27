#pragma once

#include <thread>
#include <functional>
#include <string>
#include <map>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET socket_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
typedef int socket_t;
#endif

namespace test_helpers {

// Simple mock HTTP server for integration tests
class MockHttpServer {
public:
    // Constructor
    MockHttpServer(int port = 8080);
    
    // Destructor
    ~MockHttpServer();
    
    // Start the server
    bool Start();
    
    // Stop the server
    void Stop();
    
    // Add a route handler
    void AddRoute(const std::string& path, const std::string& method, 
                 const std::function<std::string(const std::string&)>& handler);
    
    // Get server port
    int GetPort() const { return port_; }
    
    // Check if server is running
    bool IsRunning() const { return running_; }
    
    // Record request for later verification
    void RecordRequest(const std::string& method, const std::string& path, const std::string& body);
    
    // Get recorded requests
    std::vector<std::tuple<std::string, std::string, std::string>> GetRecordedRequests();
    
    // Clear recorded requests
    void ClearRecordedRequests();

private:
    // Server thread function
    void ServerThread();
    
    // Handle client connection
    void HandleClient(socket_t client_socket);
    
    // Parse HTTP request
    bool ParseRequest(const std::string& request, std::string& method, 
                     std::string& path, std::map<std::string, std::string>& headers,
                     std::string& body);
    
    // Generate HTTP response
    std::string GenerateResponse(int status_code, const std::string& content_type, 
                               const std::string& body);
    
    int port_;
    socket_t server_socket_;
    std::atomic<bool> running_;
    std::unique_ptr<std::thread> server_thread_;
    
    std::map<std::pair<std::string, std::string>, 
             std::function<std::string(const std::string&)>> routes_;
    
    std::mutex requests_mutex_;
    std::vector<std::tuple<std::string, std::string, std::string>> recorded_requests_;
};

} // namespace test_helpers
