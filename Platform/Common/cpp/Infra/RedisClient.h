#pragma once

#include "IRedisClient.h"
#include <string>
#include <memory>
#include <functional>
#include <vector>
#include <unordered_map>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <queue>

// Forward declarations for Redis client
struct redisContext;
struct redisReply;

namespace coyote {
namespace infra {

using RedisMessageCallback = std::function<void(const std::string& channel, const std::string& message)>;

// RAII wrapper for redisContext
class RedisContextRAII {
public:
    explicit RedisContextRAII(redisContext* ctx = nullptr) : m_context(ctx) {}
    ~RedisContextRAII() { 
        if (m_context) {
            redisFree(m_context);
        }
    }
    
    // Move constructor
    RedisContextRAII(RedisContextRAII&& other) noexcept : m_context(other.m_context) {
        other.m_context = nullptr;
    }
    
    // Move assignment
    RedisContextRAII& operator=(RedisContextRAII&& other) noexcept {
        if (this != &other) {
            if (m_context) {
                redisFree(m_context);
            }
            m_context = other.m_context;
            other.m_context = nullptr;
        }
        return *this;
    }
    
    // Delete copy constructor and assignment
    RedisContextRAII(const RedisContextRAII&) = delete;
    RedisContextRAII& operator=(const RedisContextRAII&) = delete;
    
    redisContext* get() const { return m_context; }
    redisContext* release() { 
        redisContext* ctx = m_context;
        m_context = nullptr;
        return ctx;
    }
    void reset(redisContext* ctx = nullptr) {
        if (m_context) {
            redisFree(m_context);
        }
        m_context = ctx;
    }
    
    operator bool() const { return m_context != nullptr; }
    
private:
    redisContext* m_context;
};

// RAII wrapper for redisReply
class RedisReplyRAII {
public:
    explicit RedisReplyRAII(redisReply* reply = nullptr) : m_reply(reply) {}
    ~RedisReplyRAII() {
        if (m_reply) {
            freeReplyObject(m_reply);
        }
    }
    
    // Move constructor
    RedisReplyRAII(RedisReplyRAII&& other) noexcept : m_reply(other.m_reply) {
        other.m_reply = nullptr;
    }
    
    // Move assignment
    RedisReplyRAII& operator=(RedisReplyRAII&& other) noexcept {
        if (this != &other) {
            if (m_reply) {
                freeReplyObject(m_reply);
            }
            m_reply = other.m_reply;
            other.m_reply = nullptr;
        }
        return *this;
    }
    
    // Delete copy constructor and assignment
    RedisReplyRAII(const RedisReplyRAII&) = delete;
    RedisReplyRAII& operator=(const RedisReplyRAII&) = delete;
    
    redisReply* get() const { return m_reply; }
    redisReply* release() { 
        redisReply* reply = m_reply;
        m_reply = nullptr;
        return reply;
    }
    void reset(redisReply* reply = nullptr) {
        if (m_reply) {
            freeReplyObject(m_reply);
        }
        m_reply = reply;
    }
    
    operator bool() const { return m_reply != nullptr; }
    redisReply* operator->() const { return m_reply; }
    
private:
    redisReply* m_reply;
};

// Connection metrics implementation
class RedisMetrics : public IRedisMetrics {
public:
    std::atomic<uint64_t> commands_executed{0};
    std::atomic<uint64_t> commands_failed{0};
    std::atomic<uint64_t> reconnects{0};
    std::atomic<uint64_t> pub_messages{0};
    std::atomic<uint64_t> sub_messages{0};
    std::atomic<uint64_t> connection_errors{0};
    std::chrono::steady_clock::time_point last_command_time;
    
    // IRedisMetrics implementation
    uint64_t getCommandsExecuted() const override { return commands_executed.load(); }
    uint64_t getCommandsFailed() const override { return commands_failed.load(); }
    uint64_t getReconnects() const override { return reconnects.load(); }
    uint64_t getPubMessages() const override { return pub_messages.load(); }
    uint64_t getSubMessages() const override { return sub_messages.load(); }
    uint64_t getConnectionErrors() const override { return connection_errors.load(); }
    std::chrono::steady_clock::time_point getLastCommandTime() const override { return last_command_time; }
    
    void reset() override {
        commands_executed = 0;
        commands_failed = 0;
        reconnects = 0;
        pub_messages = 0;
        sub_messages = 0;
        connection_errors = 0;
        last_command_time = std::chrono::steady_clock::now();
    }
};

class RedisClient : public IRedisClient {
public:
    RedisClient(const std::string& host = "localhost", int port = 6379);
    ~RedisClient() override;

    // IRedisClient implementation
    bool connect() override;
    void disconnect() override;
    bool isConnected() const override;
    
    // Auto-reconnect configuration
    void setAutoReconnect(bool enable, int max_retries = 3, std::chrono::milliseconds retry_delay = std::chrono::milliseconds(1000)) override;
    
    // Connection health
    bool ping() override;
    std::unique_ptr<IRedisMetrics> getMetrics() const override;
    void resetMetrics() override;

    // Pub/Sub operations
    bool publish(const std::string& channel, const std::string& message) override;
    bool subscribe(const std::string& channel, RedisMessageCallback callback) override;
    bool unsubscribe(const std::string& channel) override;
    
    // Async pub/sub operations
    void publishAsync(const std::string& channel, const std::string& message) override;
    void setAsyncMode(bool enable) override;

    // Data operations (thread-safe)
    bool set(const std::string& key, const std::string& value, int ttl = -1) override;
    std::string get(const std::string& key) override;
    bool del(const std::string& key) override;
    bool exists(const std::string& key) override;

    // Hash operations (for structured data)
    bool hset(const std::string& key, const std::string& field, const std::string& value) override;
    std::string hget(const std::string& key, const std::string& field) override;
    std::unordered_map<std::string, std::string> hgetall(const std::string& key) override;
    bool hdel(const std::string& key, const std::string& field) override;

    // Set operations (for indexes)
    bool sadd(const std::string& key, const std::string& member) override;
    bool srem(const std::string& key, const std::string& member) override;
    std::vector<std::string> smembers(const std::string& key) override;

    // List operations (for event logs)
    bool lpush(const std::string& key, const std::string& value) override;
    bool rpush(const std::string& key, const std::string& value) override;
    std::string lpop(const std::string& key) override;
    std::string rpop(const std::string& key) override;
    std::vector<std::string> lrange(const std::string& key, int start, int stop) override;
    bool ltrim(const std::string& key, int start, int stop) override;

private:
    std::string m_host;
    int m_port;
    RedisContextRAII m_context;
    RedisContextRAII m_subscribe_context;
    
    // Threading
    std::thread m_subscriber_thread;
    std::atomic<bool> m_subscriber_running;
    mutable std::mutex m_callbacks_mutex;
    mutable std::mutex m_command_mutex;  // Thread safety for commands
    std::unordered_map<std::string, RedisMessageCallback> m_callbacks;
    
    // Auto-reconnect
    std::atomic<bool> m_auto_reconnect{false};
    int m_max_retries{3};
    std::chrono::milliseconds m_retry_delay{1000};
    
    // Async publishing
    std::atomic<bool> m_async_mode{false};
    std::thread m_async_publisher_thread;
    std::queue<std::pair<std::string, std::string>> m_async_queue;
    std::mutex m_async_queue_mutex;
    std::condition_variable m_async_queue_cv;
    std::atomic<bool> m_async_publisher_running{false};
    
    // Metrics
    mutable std::mutex m_metrics_mutex;
    RedisMetrics m_metrics;

    void subscriberLoop();
    void asyncPublisherLoop();
    RedisReplyRAII executeCommand(const char* format, ...);
    RedisReplyRAII executeCommandWithRetry(const char* format, ...);
    bool ensureConnection();
    bool reconnect();    void updateMetrics(bool success);
};

// Factory implementation for RedisClient
class RedisClientFactory : public IRedisClientFactory {
public:
    std::unique_ptr<IRedisClient> createClient(const std::string& host = "localhost", int port = 6379) override {
        return std::make_unique<RedisClient>(host, port);
    }
};

} // namespace infra
} // namespace coyote
