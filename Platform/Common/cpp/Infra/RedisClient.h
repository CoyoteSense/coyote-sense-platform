#pragma once

#include <string>
#include <memory>
#include <functional>
#include <vector>
#include <unordered_map>
#include <thread>
#include <atomic>
#include <mutex>

// Forward declarations for Redis client
struct redisContext;
struct redisReply;

namespace coyote {
namespace infra {

using RedisMessageCallback = std::function<void(const std::string& channel, const std::string& message)>;

class RedisClient {
public:
    RedisClient(const std::string& host = "localhost", int port = 6379);
    ~RedisClient();

    // Connection management
    bool connect();
    void disconnect();
    bool isConnected() const;

    // Pub/Sub operations
    bool publish(const std::string& channel, const std::string& message);
    bool subscribe(const std::string& channel, RedisMessageCallback callback);
    bool unsubscribe(const std::string& channel);

    // Data operations
    bool set(const std::string& key, const std::string& value, int ttl = -1);
    std::string get(const std::string& key);
    bool del(const std::string& key);
    bool exists(const std::string& key);

    // Hash operations (for structured data)
    bool hset(const std::string& key, const std::string& field, const std::string& value);
    std::string hget(const std::string& key, const std::string& field);
    std::unordered_map<std::string, std::string> hgetall(const std::string& key);
    bool hdel(const std::string& key, const std::string& field);

    // Set operations (for indexes)
    bool sadd(const std::string& key, const std::string& member);
    bool srem(const std::string& key, const std::string& member);
    std::vector<std::string> smembers(const std::string& key);

    // List operations (for event logs)
    bool lpush(const std::string& key, const std::string& value);
    bool rpush(const std::string& key, const std::string& value);
    std::string lpop(const std::string& key);
    std::string rpop(const std::string& key);
    std::vector<std::string> lrange(const std::string& key, int start, int stop);
    bool ltrim(const std::string& key, int start, int stop);

private:
    std::string m_host;
    int m_port;
    redisContext* m_context;
    redisContext* m_subscribe_context;
    
    std::thread m_subscriber_thread;
    std::atomic<bool> m_subscriber_running;
    std::mutex m_callbacks_mutex;
    std::unordered_map<std::string, RedisMessageCallback> m_callbacks;

    void subscriberLoop();
    redisReply* executeCommand(const char* format, ...);
    void freeReply(redisReply* reply);
};

} // namespace infra
} // namespace coyote
