#pragma once

#include "IHttpClient.h"
#include <queue>
#include <mutex>
#include <unordered_map>

namespace coyote {
namespace infra {
namespace mocks {

// Mock HTTP Response implementation
class MockHttpResponse : public IHttpResponse {
private:
    int status_code_;
    std::unordered_map<std::string, std::string> headers_;
    std::string body_;
    std::string error_message_;
    std::chrono::milliseconds duration_;

public:
    MockHttpResponse(int statusCode, const std::string& body, 
                    const std::unordered_map<std::string, std::string>& headers = {},
                    std::chrono::milliseconds duration = std::chrono::milliseconds(10))
        : status_code_(statusCode), headers_(headers), body_(body), duration_(duration) {}

    int getStatusCode() const override { return status_code_; }
    const std::unordered_map<std::string, std::string>& getHeaders() const override { return headers_; }
    std::string getHeader(const std::string& name) const override {
        auto it = headers_.find(name);
        return it != headers_.end() ? it->second : "";
    }
    const std::string& getBody() const override { return body_; }
    bool isSuccess() const override { return status_code_ >= 200 && status_code_ < 300; }
    const std::string& getErrorMessage() const override { return error_message_; }
    std::chrono::milliseconds getDuration() const override { return duration_; }

    void setStatusCode(int code) { status_code_ = code; }
    void setBody(const std::string& body) { body_ = body; }
    void setHeader(const std::string& name, const std::string& value) { headers_[name] = value; }
    void setErrorMessage(const std::string& error) { error_message_ = error; }
    void setDuration(std::chrono::milliseconds duration) { duration_ = duration; }
};

// Mock HTTP Request implementation
class MockHttpRequest : public IHttpRequest {
private:
    std::string url_;
    HttpMethod method_ = HttpMethod::GET;
    std::unordered_map<std::string, std::string> headers_;
    std::string body_;
    int timeout_seconds_ = 30;

public:
    void setUrl(const std::string& url) override { url_ = url; }
    void setMethod(HttpMethod method) override { method_ = method; }
    void addHeader(const std::string& name, const std::string& value) override { headers_[name] = value; }
    void setHeaders(const std::unordered_map<std::string, std::string>& headers) override { headers_ = headers; }
    void setBody(const std::string& body) override { body_ = body; }
    void setTimeout(int timeoutSeconds) override { timeout_seconds_ = timeoutSeconds; }

    const std::string& getUrl() const override { return url_; }
    HttpMethod getMethod() const override { return method_; }
    const std::unordered_map<std::string, std::string>& getHeaders() const override { return headers_; }
    std::string getHeader(const std::string& name) const override {
        auto it = headers_.find(name);
        return it != headers_.end() ? it->second : "";
    }
    const std::string& getBody() const override { return body_; }
    int getTimeout() const override { return timeout_seconds_; }
};

// Mock HTTP Client implementation
class MockHttpClient : public IHttpClient {
private:
    std::string user_agent_;
    std::unordered_map<std::string, std::string> default_headers_;
    mutable std::mutex request_mutex_;
    
    // Queue of pre-configured responses
    std::queue<std::unique_ptr<MockHttpResponse>> response_queue_;
    
    // Default response for when queue is empty
    std::unique_ptr<MockHttpResponse> default_response_;
    
    // Recording functionality
    std::vector<std::unique_ptr<IHttpRequest>> recorded_requests_;
    bool record_requests_ = false;
    
    // Failure simulation
    bool simulate_network_error_ = false;
    std::string network_error_message_ = "Mock network error";

public:
    MockHttpClient() : default_response_(std::make_unique<MockHttpResponse>(200, "{}")) {}

    std::unique_ptr<IHttpResponse> execute(const IHttpRequest& request) override {
        std::lock_guard<std::mutex> lock(request_mutex_);
        
        // Record request if enabled
        if (record_requests_) {
            auto recorded_request = std::make_unique<MockHttpRequest>();
            recorded_request->setUrl(request.getUrl());
            recorded_request->setMethod(request.getMethod());
            recorded_request->setHeaders(request.getHeaders());
            recorded_request->setBody(request.getBody());
            recorded_request->setTimeout(request.getTimeout());
            recorded_requests_.push_back(std::move(recorded_request));
        }
        
        // Simulate network error if configured
        if (simulate_network_error_) {
            auto error_response = std::make_unique<MockHttpResponse>(0, "");
            error_response->setErrorMessage(network_error_message_);
            return error_response;
        }
        
        // Return queued response or default
        if (!response_queue_.empty()) {
            auto response = std::move(response_queue_.front());
            response_queue_.pop();
            return response;
        }
        
        // Clone default response
        auto response = std::make_unique<MockHttpResponse>(
            default_response_->getStatusCode(),
            default_response_->getBody(),
            default_response_->getHeaders(),
            default_response_->getDuration()
        );
        return response;
    }

    void setUserAgent(const std::string& userAgent) override {
        user_agent_ = userAgent;
    }

    void setDefaultHeaders(const std::unordered_map<std::string, std::string>& headers) override {
        default_headers_ = headers;
    }

    // Mock-specific methods for testing
    
    // Add a response to the queue
    void addResponse(std::unique_ptr<MockHttpResponse> response) {
        std::lock_guard<std::mutex> lock(request_mutex_);
        response_queue_.push(std::move(response));
    }
    
    // Add multiple responses
    void addResponses(std::vector<std::unique_ptr<MockHttpResponse>> responses) {
        std::lock_guard<std::mutex> lock(request_mutex_);
        for (auto& response : responses) {
            response_queue_.push(std::move(response));
        }
    }
    
    // Set the default response when queue is empty
    void setDefaultResponse(std::unique_ptr<MockHttpResponse> response) {
        std::lock_guard<std::mutex> lock(request_mutex_);
        default_response_ = std::move(response);
    }
    
    // Request recording
    void enableRequestRecording(bool enable = true) {
        std::lock_guard<std::mutex> lock(request_mutex_);
        record_requests_ = enable;
        if (!enable) {
            recorded_requests_.clear();
        }
    }
    
    const std::vector<std::unique_ptr<IHttpRequest>>& getRecordedRequests() const {
        return recorded_requests_;
    }
    
    void clearRecordedRequests() {
        std::lock_guard<std::mutex> lock(request_mutex_);
        recorded_requests_.clear();
    }
    
    // Error simulation
    void simulateNetworkError(bool simulate = true, const std::string& errorMessage = "Mock network error") {
        std::lock_guard<std::mutex> lock(request_mutex_);
        simulate_network_error_ = simulate;
        network_error_message_ = errorMessage;
    }
    
    // Clear all queued responses
    void clearResponses() {
        std::lock_guard<std::mutex> lock(request_mutex_);
        while (!response_queue_.empty()) {
            response_queue_.pop();
        }
    }
    
    // Convenience methods for common responses
    void addJsonResponse(int statusCode, const std::string& jsonBody) {
        auto response = std::make_unique<MockHttpResponse>(statusCode, jsonBody);
        response->setHeader("Content-Type", "application/json");
        addResponse(std::move(response));
    }
    
    void addSuccessResponse(const std::string& body = "OK") {
        addResponse(std::make_unique<MockHttpResponse>(200, body));
    }
    
    void addErrorResponse(int statusCode, const std::string& errorBody = "Error") {
        addResponse(std::make_unique<MockHttpResponse>(statusCode, errorBody));
    }
    
    void addNotFoundResponse() {
        addErrorResponse(404, "Not Found");
    }
    
    void addServerErrorResponse() {
        addErrorResponse(500, "Internal Server Error");
    }
    
    void addUnauthorizedResponse() {
        addErrorResponse(401, "Unauthorized");
    }
    
    // Get mock state
    const std::string& getUserAgent() const { return user_agent_; }
    const std::unordered_map<std::string, std::string>& getDefaultHeaders() const { return default_headers_; }
    size_t getQueuedResponseCount() const {
        std::lock_guard<std::mutex> lock(request_mutex_);
        return response_queue_.size();
    }
    bool isRecordingRequests() const { return record_requests_; }
    bool isSimulatingNetworkError() const { return simulate_network_error_; }
};

// Mock HTTP Client Factory
class MockHttpClientFactory : public IHttpClientFactory {
public:
    std::unique_ptr<IHttpClient> create() override {
        return std::make_unique<MockHttpClient>();
    }

    std::unique_ptr<IHttpClient> createWithConfig(const std::unordered_map<std::string, std::string>& config) override {
        auto client = std::make_unique<MockHttpClient>();
        
        // Apply configuration if needed
        auto userAgentIt = config.find("user_agent");
        if (userAgentIt != config.end()) {
            client->setUserAgent(userAgentIt->second);
        }
        
        return client;
    }
};

} // namespace mocks
} // namespace infra
} // namespace coyote
