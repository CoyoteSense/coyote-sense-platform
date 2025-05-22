#include "RedisClient.h"
#include <hiredis/hiredis.h>
#include <iostream>
#include <cstdarg>
#include <chrono>

namespace coyote {
namespace infra {

RedisClient::RedisClient(const std::string& host, int port)
    : m_host(host), m_port(port), m_context(nullptr), 
      m_subscribe_context(nullptr), m_subscriber_running(false) {
}

RedisClient::~RedisClient() {
    disconnect();
}

bool RedisClient::connect() {
    if (m_context) {
        disconnect();
    }

    // Main connection for commands
    m_context = redisConnect(m_host.c_str(), m_port);
    if (!m_context || m_context->err) {
        if (m_context) {
            std::cerr << "Redis connection error: " << m_context->errstr << std::endl;
            redisFree(m_context);
            m_context = nullptr;
        } else {
            std::cerr << "Redis connection error: can't allocate redis context" << std::endl;
        }
        return false;
    }

    // Separate connection for subscriptions
    m_subscribe_context = redisConnect(m_host.c_str(), m_port);
    if (!m_subscribe_context || m_subscribe_context->err) {
        if (m_subscribe_context) {
            std::cerr << "Redis subscribe connection error: " << m_subscribe_context->errstr << std::endl;
            redisFree(m_subscribe_context);
            m_subscribe_context = nullptr;
        }
        redisFree(m_context);
        m_context = nullptr;
        return false;
    }

    // Start subscriber thread
    m_subscriber_running = true;
    m_subscriber_thread = std::thread(&RedisClient::subscriberLoop, this);

    std::cout << "Connected to Redis at " << m_host << ":" << m_port << std::endl;
    return true;
}

void RedisClient::disconnect() {
    m_subscriber_running = false;
    
    if (m_subscriber_thread.joinable()) {
        m_subscriber_thread.join();
    }

    if (m_context) {
        redisFree(m_context);
        m_context = nullptr;
    }

    if (m_subscribe_context) {
        redisFree(m_subscribe_context);
        m_subscribe_context = nullptr;
    }

    std::lock_guard<std::mutex> lock(m_callbacks_mutex);
    m_callbacks.clear();
}

bool RedisClient::isConnected() const {
    return m_context != nullptr && m_subscribe_context != nullptr;
}

bool RedisClient::publish(const std::string& channel, const std::string& message) {
    if (!m_context) return false;

    redisReply* reply = static_cast<redisReply*>(redisCommand(m_context, "PUBLISH %s %s", 
                                                              channel.c_str(), message.c_str()));
    if (!reply) return false;

    bool success = reply->type != REDIS_REPLY_ERROR;
    freeReplyObject(reply);
    return success;
}

bool RedisClient::subscribe(const std::string& channel, RedisMessageCallback callback) {
    std::lock_guard<std::mutex> lock(m_callbacks_mutex);
    m_callbacks[channel] = callback;

    if (!m_subscribe_context) return false;

    redisReply* reply = static_cast<redisReply*>(redisCommand(m_subscribe_context, "SUBSCRIBE %s", 
                                                              channel.c_str()));
    if (!reply) return false;

    bool success = reply->type != REDIS_REPLY_ERROR;
    freeReplyObject(reply);
    return success;
}

bool RedisClient::unsubscribe(const std::string& channel) {
    {
        std::lock_guard<std::mutex> lock(m_callbacks_mutex);
        m_callbacks.erase(channel);
    }

    if (!m_subscribe_context) return false;

    redisReply* reply = static_cast<redisReply*>(redisCommand(m_subscribe_context, "UNSUBSCRIBE %s", 
                                                              channel.c_str()));
    if (!reply) return false;

    bool success = reply->type != REDIS_REPLY_ERROR;
    freeReplyObject(reply);
    return success;
}

bool RedisClient::set(const std::string& key, const std::string& value, int ttl) {
    if (!m_context) return false;

    redisReply* reply;
    if (ttl > 0) {
        reply = static_cast<redisReply*>(redisCommand(m_context, "SETEX %s %d %s", 
                                                      key.c_str(), ttl, value.c_str()));
    } else {
        reply = static_cast<redisReply*>(redisCommand(m_context, "SET %s %s", 
                                                      key.c_str(), value.c_str()));
    }
    
    if (!reply) return false;

    bool success = reply->type == REDIS_REPLY_STATUS && 
                   std::string(reply->str) == "OK";
    freeReplyObject(reply);
    return success;
}

std::string RedisClient::get(const std::string& key) {
    if (!m_context) return "";

    redisReply* reply = static_cast<redisReply*>(redisCommand(m_context, "GET %s", key.c_str()));
    if (!reply) return "";

    std::string result;
    if (reply->type == REDIS_REPLY_STRING) {
        result = std::string(reply->str, reply->len);
    }
    
    freeReplyObject(reply);
    return result;
}

bool RedisClient::del(const std::string& key) {
    if (!m_context) return false;

    redisReply* reply = static_cast<redisReply*>(redisCommand(m_context, "DEL %s", key.c_str()));
    if (!reply) return false;

    bool success = reply->type == REDIS_REPLY_INTEGER && reply->integer > 0;
    freeReplyObject(reply);
    return success;
}

bool RedisClient::exists(const std::string& key) {
    if (!m_context) return false;

    redisReply* reply = static_cast<redisReply*>(redisCommand(m_context, "EXISTS %s", key.c_str()));
    if (!reply) return false;

    bool exists = reply->type == REDIS_REPLY_INTEGER && reply->integer > 0;
    freeReplyObject(reply);
    return exists;
}

bool RedisClient::hset(const std::string& key, const std::string& field, const std::string& value) {
    if (!m_context) return false;

    redisReply* reply = static_cast<redisReply*>(redisCommand(m_context, "HSET %s %s %s", 
                                                              key.c_str(), field.c_str(), value.c_str()));
    if (!reply) return false;

    bool success = reply->type != REDIS_REPLY_ERROR;
    freeReplyObject(reply);
    return success;
}

std::string RedisClient::hget(const std::string& key, const std::string& field) {
    if (!m_context) return "";

    redisReply* reply = static_cast<redisReply*>(redisCommand(m_context, "HGET %s %s", 
                                                              key.c_str(), field.c_str()));
    if (!reply) return "";

    std::string result;
    if (reply->type == REDIS_REPLY_STRING) {
        result = std::string(reply->str, reply->len);
    }
    
    freeReplyObject(reply);
    return result;
}

std::unordered_map<std::string, std::string> RedisClient::hgetall(const std::string& key) {
    std::unordered_map<std::string, std::string> result;
    if (!m_context) return result;

    redisReply* reply = static_cast<redisReply*>(redisCommand(m_context, "HGETALL %s", key.c_str()));
    if (!reply || reply->type != REDIS_REPLY_ARRAY) {
        if (reply) freeReplyObject(reply);
        return result;
    }

    for (size_t i = 0; i < reply->elements; i += 2) {
        if (i + 1 < reply->elements && 
            reply->element[i]->type == REDIS_REPLY_STRING &&
            reply->element[i + 1]->type == REDIS_REPLY_STRING) {
            std::string field(reply->element[i]->str, reply->element[i]->len);
            std::string value(reply->element[i + 1]->str, reply->element[i + 1]->len);
            result[field] = value;
        }
    }

    freeReplyObject(reply);
    return result;
}

bool RedisClient::sadd(const std::string& key, const std::string& member) {
    if (!m_context) return false;

    redisReply* reply = static_cast<redisReply*>(redisCommand(m_context, "SADD %s %s", 
                                                              key.c_str(), member.c_str()));
    if (!reply) return false;

    bool success = reply->type != REDIS_REPLY_ERROR;
    freeReplyObject(reply);
    return success;
}

bool RedisClient::lpush(const std::string& key, const std::string& value) {
    if (!m_context) return false;

    redisReply* reply = static_cast<redisReply*>(redisCommand(m_context, "LPUSH %s %s", 
                                                              key.c_str(), value.c_str()));
    if (!reply) return false;

    bool success = reply->type != REDIS_REPLY_ERROR;
    freeReplyObject(reply);
    return success;
}

void RedisClient::subscriberLoop() {
    if (!m_subscribe_context) return;

    while (m_subscriber_running) {
        redisReply* reply = nullptr;
        
        // Use timeout to allow periodic checking of m_subscriber_running
        struct timeval timeout = {1, 0}; // 1 second timeout
        if (redisSetTimeout(m_subscribe_context, timeout) != REDIS_OK) {
            continue;
        }

        if (redisGetReply(m_subscribe_context, reinterpret_cast<void**>(&reply)) != REDIS_OK) {
            if (m_subscriber_running) {
                std::cerr << "Redis subscriber error" << std::endl;
            }
            continue;
        }

        if (!reply) continue;

        if (reply->type == REDIS_REPLY_ARRAY && reply->elements == 3) {
            if (reply->element[0]->type == REDIS_REPLY_STRING &&
                std::string(reply->element[0]->str) == "message") {
                
                std::string channel(reply->element[1]->str, reply->element[1]->len);
                std::string message(reply->element[2]->str, reply->element[2]->len);

                std::lock_guard<std::mutex> lock(m_callbacks_mutex);
                auto it = m_callbacks.find(channel);
                if (it != m_callbacks.end()) {
                    try {
                        it->second(channel, message);
                    } catch (const std::exception& e) {
                        std::cerr << "Error in Redis message callback: " << e.what() << std::endl;
                    }
                }
            }
        }

        freeReplyObject(reply);
    }
}

} // namespace infra
} // namespace coyote
