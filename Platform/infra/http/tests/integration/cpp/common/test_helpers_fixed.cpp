#include "test_helpers.h"
#include <cstdlib>
#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <thread>
#include <cctype>
#include <regex>

#ifdef _WIN32
// Windows-specific socket headers need specific order and defines
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
// Unix-specific headers
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#endif

namespace test_helpers {

void SetEnvironmentVariable(const std::string& name, const std::string& value) {
#ifdef _WIN32
    ::SetEnvironmentVariableA(name.c_str(), value.c_str());
#else
    setenv(name.c_str(), value.c_str(), 1);
#endif
}

std::string GetEnvironmentVariable(const std::string& name, const std::string& default_value) {
    const char* value = std::getenv(name.c_str());
    return value ? std::string(value) : default_value;
}

void UnsetEnvironmentVariable(const std::string& name) {
#ifdef _WIN32
    ::SetEnvironmentVariableA(name.c_str(), nullptr);
#else
    unsetenv(name.c_str());
#endif
}

bool IsPortOpen(const std::string& host, int port) {
#ifdef _WIN32
    // Initialize Winsock
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return false;
    }

    // Create socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(static_cast<u_short>(port));

    // Convert hostname to IP
    struct hostent* he = gethostbyname(host.c_str());
    if (he == nullptr) {
        closesocket(sock);
        WSACleanup();
        return false;
    }

    server_addr.sin_addr = *((struct in_addr*)he->h_addr);

    // Set socket to non-blocking mode for timeout
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    // Try to connect with timeout
    int result = connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    bool is_open = false;

    if (result == 0) {
        is_open = true;
    } else {
        int error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK || error == WSAEINPROGRESS) {
            // Connection in progress, use select to wait with timeout
            fd_set write_fds;
            FD_ZERO(&write_fds);
            FD_SET(sock, &write_fds);

            struct timeval timeout;
            timeout.tv_sec = 1;  // 1 second timeout
            timeout.tv_usec = 0;

            int select_result = select(0, nullptr, &write_fds, nullptr, &timeout);
            if (select_result > 0 && FD_ISSET(sock, &write_fds)) {
                int sock_error;
                socklen_t len = sizeof(sock_error);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&sock_error, &len);
                is_open = (sock_error == 0);
            }
        }
    }

    closesocket(sock);
    WSACleanup();
    return is_open;
#else
    // UNIX implementation
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return false;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // Convert hostname to IP
    struct hostent* he = gethostbyname(host.c_str());
    if (he == nullptr) {
        close(sock);
        return false;
    }

    server_addr.sin_addr = *((struct in_addr*)he->h_addr);

    // Set socket to non-blocking mode for timeout
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    int result = connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    bool is_open = false;

    if (result == 0) {
        is_open = true;
    } else {
        if (errno == EINPROGRESS) {
            // Connection in progress, use select to wait with timeout
            fd_set write_fds;
            FD_ZERO(&write_fds);
            FD_SET(sock, &write_fds);

            struct timeval timeout;
            timeout.tv_sec = 1;  // 1 second timeout
            timeout.tv_usec = 0;

            int select_result = select(sock + 1, nullptr, &write_fds, nullptr, &timeout);
            if (select_result > 0 && FD_ISSET(sock, &write_fds)) {
                int sock_error;
                socklen_t len = sizeof(sock_error);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&sock_error, &len);
                is_open = (sock_error == 0);
            }
        }
    }

    close(sock);
    return is_open;
#endif
}

bool WaitForPort(const std::string& host, int port, int timeout_seconds) {
    auto start_time = std::chrono::steady_clock::now();
    auto timeout = std::chrono::seconds(timeout_seconds);

    while (std::chrono::steady_clock::now() - start_time < timeout) {
        if (IsPortOpen(host, port)) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    return false;
}

std::string GenerateRandomString(size_t length) {
    const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(0, static_cast<int>(charset.size() - 1));

    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        result += charset[dis(gen)];
    }
    return result;
}

std::string ExtractJsonValue(const std::string& json_str, const std::string& key) {
    // Use regex for more reliable extraction
    std::regex pattern("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
    std::smatch match;
    
    if (std::regex_search(json_str, match, pattern) && match.size() > 1) {
        return match[1].str();
    }
    
    // Try non-string pattern (number, boolean, etc.)
    std::regex non_string_pattern("\"" + key + "\"\\s*:\\s*([^,}\\]]+)");
    if (std::regex_search(json_str, match, non_string_pattern) && match.size() > 1) {
        std::string result = match[1].str();
        // Trim whitespace
        result.erase(0, result.find_first_not_of(" \t\n\r\f\v"));
        result.erase(result.find_last_not_of(" \t\n\r\f\v") + 1);
        return result;
    }
    
    return "";
}

std::string UrlEncode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (char c : value) {
        // Keep alphanumeric and some special characters intact
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            // Percent-encode other characters
            escaped << '%' << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
        }
    }

    return escaped.str();
}

}  // namespace test_helpers
