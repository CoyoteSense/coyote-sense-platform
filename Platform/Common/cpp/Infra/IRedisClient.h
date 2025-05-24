#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <chrono>
#include <atomic>

namespace coyote {
namespace infra {

using RedisMessageCallback = std::function<void(const std::string& channel, const std::string& message)>;

// Connection metrics interface
struct IRedisMetrics {
    virtual ~IRedisMetrics() = default;
    virtual uint64_t getCommandsExecuted() const = 0;
    virtual uint64_t getCommandsFailed() const = 0;
    virtual uint64_t getReconnects() const = 0;
    virtual uint64_t getPubMessages() const = 0;
    virtual uint64_t getSubMessages() const = 0;
    virtual uint64_t getConnectionErrors() const = 0;
    virtual std::chrono::steady_clock::time_point getLastCommandTime() const = 0;
    virtual void reset() = 0;
};

// Redis client interface
class IRedisClient {
public:
    virtual ~IRedisClient() = default;

    // Connection management
    virtual bool connect() = 0;
    virtual void disconnect() = 0;
    virtual bool isConnected() const = 0;
    
    // Auto-reconnect configuration
    virtual void setAutoReconnect(bool enable, int max_retries = 3, std::chrono::milliseconds retry_delay = std::chrono::milliseconds(1000)) = 0;
    
    // Connection health
    virtual bool ping() = 0;
    virtual std::unique_ptr<IRedisMetrics> getMetrics() const = 0;
    virtual void resetMetrics() = 0;

    // Pub/Sub operations
    virtual bool publish(const std::string& channel, const std::string& message) = 0;
    virtual bool subscribe(const std::string& channel, RedisMessageCallback callback) = 0;
    virtual bool unsubscribe(const std::string& channel) = 0;
    
    // Async pub/sub operations
    virtual void publishAsync(const std::string& channel, const std::string& message) = 0;
    virtual void setAsyncMode(bool enable) = 0;

    // Data operations
    virtual bool set(const std::string& key, const std::string& value, int ttl = -1) = 0;
    virtual std::string get(const std::string& key) = 0;
    virtual bool del(const std::string& key) = 0;
    virtual bool exists(const std::string& key) = 0;

    // Hash operations
    virtual bool hset(const std::string& key, const std::string& field, const std::string& value) = 0;
    virtual std::string hget(const std::string& key, const std::string& field) = 0;
    virtual std::unordered_map<std::string, std::string> hgetall(const std::string& key) = 0;
    virtual bool hdel(const std::string& key, const std::string& field) = 0;

    // Set operations
    virtual bool sadd(const std::string& key, const std::string& member) = 0;
    virtual bool srem(const std::string& key, const std::string& member) = 0;
    virtual std::vector<std::string> smembers(const std::string& key) = 0;

    // List operations
    virtual bool lpush(const std::string& key, const std::string& value) = 0;
    virtual bool rpush(const std::string& key, const std::string& value) = 0;
    virtual std::string lpop(const std::string& key) = 0;
    virtual std::string rpop(const std::string& key) = 0;
    virtual std::vector<std::string> lrange(const std::string& key, int start, int stop) = 0;
    virtual bool ltrim(const std::string& key, int start, int stop) = 0;
};

// Factory for creating Redis clients
class IRedisClientFactory {
public:
    virtual ~IRedisClientFactory() = default;
    virtual std::unique_ptr<IRedisClient> createClient(const std::string& host = "localhost", int port = 6379) = 0;
};

} // namespace infra
} // namespace coyote
