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

// Windows-specific socket headers
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

namespace test_helpers {

void SetEnvironmentVariable(const std::string& name, const std::string& value) {
#ifdef _WIN32
    ::SetEnvironmentVariableA(name.c_str(), value.c_str());
#endif
}

std::string GetEnvironmentVariable(const std::string& name, const std::string& default_value) {
#ifdef _WIN32
    char buffer[1024];
    DWORD size = ::GetEnvironmentVariableA(name.c_str(), buffer, sizeof(buffer));
    if (size == 0 || size > sizeof(buffer)) {
        return default_value;
    }
    return std::string(buffer);
#else
    return default_value;
#endif
}

void UnsetEnvironmentVariable(const std::string& name) {
#ifdef _WIN32
    ::SetEnvironmentVariableA(name.c_str(), nullptr);
#endif
}

bool IsPortOpen(const std::string& host, int port) {
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
}

bool WaitForPort(const std::string& host, int port, int timeout_seconds) {
    auto start_time = std::chrono::steady_clock::now();
    auto end_time = start_time + std::chrono::seconds(timeout_seconds);
    
    while (std::chrono::steady_clock::now() < end_time) {
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
    // Simple JSON value extraction (not a full parser)
    std::string search_pattern = "\"" + key + "\"\\s*:\\s*\"([^\"]*)\"";
    std::regex pattern(search_pattern);
    std::smatch matches;
    
    if (std::regex_search(json_str, matches, pattern) && matches.size() > 1) {
        return matches[1].str();
    }
    
    // Try without quotes (for numbers, booleans)
    search_pattern = "\"" + key + "\"\\s*:\\s*([^,}\\s][^,}]*)";
    pattern = std::regex(search_pattern);
    
    if (std::regex_search(json_str, matches, pattern) && matches.size() > 1) {
        return matches[1].str();
    }
    
    return "";
}

std::string UrlEncode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (char c : value) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << '%' << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
        }
    }

    return escaped.str();
}

}  // namespace test_helpers
