#pragma once

#include "IRedisClient.h"
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <mutex>
#include <atomic>
#include <chrono>

namespace coyote {
namespace infra {
namespace mocks {

// Mock implementation of Redis metrics
class MockRedisMetrics : public IRedisMetrics {
private:
    std::atomic<size_t> total_commands_{0};
    std::atomic<size_t> successful_commands_{0};
    std::atomic<size_t> failed_commands_{0};
    std::atomic<double> avg_response_time_ms_{0.0};
    std::atomic<size_t> active_connections_{1};
    std::atomic<bool> is_connected_{true};
    std::chrono::steady_clock::time_point start_time_;

public:
    MockRedisMetrics() : start_time_(std::chrono::steady_clock::now()) {}

    size_t getTotalCommands() const override { return total_commands_.load(); }
    size_t getSuccessfulCommands() const override { return successful_commands_.load(); }
    size_t getFailedCommands() const override { return failed_commands_.load(); }
    double getAverageResponseTime() const override { return avg_response_time_ms_.load(); }
    size_t getActiveConnections() const override { return active_connections_.load(); }
    bool isConnected() const override { return is_connected_.load(); }
    std::chrono::steady_clock::time_point getStartTime() const override { return start_time_; }

    void incrementTotalCommands() { total_commands_++; }
    void incrementSuccessfulCommands() { successful_commands_++; }
    void incrementFailedCommands() { failed_commands_++; }
    void setConnected(bool connected) { is_connected_ = connected; }
    void setActiveConnections(size_t count) { active_connections_ = count; }
    void updateResponseTime(double time_ms) { avg_response_time_ms_ = time_ms; }
};

// Mock Redis Client implementation
class MockRedisClient : public IRedisClient {
private:
    mutable std::mutex data_mutex_;
    std::unordered_map<std::string, std::string> string_data_;
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> hash_data_;
    std::unordered_map<std::string, std::unordered_set<std::string>> set_data_;
    std::unordered_map<std::string, std::vector<std::string>> list_data_;
    std::vector<std::pair<std::string, std::string>> published_messages_;
    std::unique_ptr<MockRedisMetrics> metrics_;
    bool connected_ = true;
    bool simulate_failures_ = false;

public:
    MockRedisClient() : metrics_(std::make_unique<MockRedisMetrics>()) {}

    // Connection management
    bool connect() override {
        connected_ = true;
        metrics_->setConnected(true);
        return true;
    }

    void disconnect() override {
        connected_ = false;
        metrics_->setConnected(false);
    }

    bool isConnected() const override {
        return connected_;
    }

    bool ping() override {
        metrics_->incrementTotalCommands();
        if (connected_ && !simulate_failures_) {
            metrics_->incrementSuccessfulCommands();
            return true;
        }
        metrics_->incrementFailedCommands();
        return false;
    }

    // Pub/Sub operations
    bool publish(const std::string& channel, const std::string& message) override {
        std::lock_guard<std::mutex> lock(data_mutex_);
        metrics_->incrementTotalCommands();
        
        if (connected_ && !simulate_failures_) {
            published_messages_.emplace_back(channel, message);
            metrics_->incrementSuccessfulCommands();
            return true;
        }
        metrics_->incrementFailedCommands();
        return false;
    }

    bool subscribe(const std::string& channel, std::function<void(const std::string&, const std::string&)> callback) override {
        metrics_->incrementTotalCommands();
        if (connected_ && !simulate_failures_) {
            metrics_->incrementSuccessfulCommands();
            return true;
        }
        metrics_->incrementFailedCommands();
        return false;
    }

    bool unsubscribe(const std::string& channel) override {
        metrics_->incrementTotalCommands();
        if (connected_ && !simulate_failures_) {
            metrics_->incrementSuccessfulCommands();
            return true;
        }
        metrics_->incrementFailedCommands();
        return false;
    }

    // String operations
    bool set(const std::string& key, const std::string& value) override {
        std::lock_guard<std::mutex> lock(data_mutex_);
        metrics_->incrementTotalCommands();
        
        if (connected_ && !simulate_failures_) {
            string_data_[key] = value;
            metrics_->incrementSuccessfulCommands();
            return true;
        }
        metrics_->incrementFailedCommands();
        return false;
    }

    bool set(const std::string& key, const std::string& value, int ttlSeconds) override {
        // For mock, ignore TTL
        return set(key, value);
    }

    bool get(const std::string& key, std::string& value) override {
        std::lock_guard<std::mutex> lock(data_mutex_);
        metrics_->incrementTotalCommands();
        
        if (connected_ && !simulate_failures_) {
            auto it = string_data_.find(key);
            if (it != string_data_.end()) {
                value = it->second;
                metrics_->incrementSuccessfulCommands();
                return true;
            }
        }
        metrics_->incrementFailedCommands();
        return false;
    }

    bool del(const std::string& key) override {
        std::lock_guard<std::mutex> lock(data_mutex_);
        metrics_->incrementTotalCommands();
        
        if (connected_ && !simulate_failures_) {
            string_data_.erase(key);
            hash_data_.erase(key);
            set_data_.erase(key);
            list_data_.erase(key);
            metrics_->incrementSuccessfulCommands();
            return true;
        }
        metrics_->incrementFailedCommands();
        return false;
    }

    bool exists(const std::string& key) override {
        std::lock_guard<std::mutex> lock(data_mutex_);
        metrics_->incrementTotalCommands();
        
        if (connected_ && !simulate_failures_) {
            bool keyExists = string_data_.find(key) != string_data_.end() ||
                           hash_data_.find(key) != hash_data_.end() ||
                           set_data_.find(key) != set_data_.end() ||
                           list_data_.find(key) != list_data_.end();
            metrics_->incrementSuccessfulCommands();
            return keyExists;
        }
        metrics_->incrementFailedCommands();
        return false;
    }

    // Hash operations
    bool hset(const std::string& key, const std::string& field, const std::string& value) override {
        std::lock_guard<std::mutex> lock(data_mutex_);
        metrics_->incrementTotalCommands();
        
        if (connected_ && !simulate_failures_) {
            hash_data_[key][field] = value;
            metrics_->incrementSuccessfulCommands();
            return true;
        }
        metrics_->incrementFailedCommands();
        return false;
    }

    bool hget(const std::string& key, const std::string& field, std::string& value) override {
        std::lock_guard<std::mutex> lock(data_mutex_);
        metrics_->incrementTotalCommands();
        
        if (connected_ && !simulate_failures_) {
            auto keyIt = hash_data_.find(key);
            if (keyIt != hash_data_.end()) {
                auto fieldIt = keyIt->second.find(field);
                if (fieldIt != keyIt->second.end()) {
                    value = fieldIt->second;
                    metrics_->incrementSuccessfulCommands();
                    return true;
                }
            }
        }
        metrics_->incrementFailedCommands();
        return false;
    }

    bool hdel(const std::string& key, const std::string& field) override {
        std::lock_guard<std::mutex> lock(data_mutex_);
        metrics_->incrementTotalCommands();
        
        if (connected_ && !simulate_failures_) {
            auto keyIt = hash_data_.find(key);
            if (keyIt != hash_data_.end()) {
                keyIt->second.erase(field);
                metrics_->incrementSuccessfulCommands();
                return true;
            }
        }
        metrics_->incrementFailedCommands();
        return false;
    }

    bool hexists(const std::string& key, const std::string& field) override {
        std::lock_guard<std::mutex> lock(data_mutex_);
        metrics_->incrementTotalCommands();
        
        if (connected_ && !simulate_failures_) {
            auto keyIt = hash_data_.find(key);
            if (keyIt != hash_data_.end()) {
                bool fieldExists = keyIt->second.find(field) != keyIt->second.end();
                metrics_->incrementSuccessfulCommands();
                return fieldExists;
            }
        }
        metrics_->incrementFailedCommands();
        return false;
    }

    std::vector<std::string> hkeys(const std::string& key) override {
        std::lock_guard<std::mutex> lock(data_mutex_);
        metrics_->incrementTotalCommands();
        std::vector<std::string> keys;
        
        if (connected_ && !simulate_failures_) {
            auto keyIt = hash_data_.find(key);
            if (keyIt != hash_data_.end()) {
                for (const auto& [field, value] : keyIt->second) {
                    keys.push_back(field);
                }
                metrics_->incrementSuccessfulCommands();
            }
        } else {
            metrics_->incrementFailedCommands();
        }
        return keys;
    }

    // Set operations
    bool sadd(const std::string& key, const std::string& member) override {
        std::lock_guard<std::mutex> lock(data_mutex_);
        metrics_->incrementTotalCommands();
        
        if (connected_ && !simulate_failures_) {
            set_data_[key].insert(member);
            metrics_->incrementSuccessfulCommands();
            return true;
        }
        metrics_->incrementFailedCommands();
        return false;
    }

    bool srem(const std::string& key, const std::string& member) override {
        std::lock_guard<std::mutex> lock(data_mutex_);
        metrics_->incrementTotalCommands();
        
        if (connected_ && !simulate_failures_) {
            auto keyIt = set_data_.find(key);
            if (keyIt != set_data_.end()) {
                keyIt->second.erase(member);
                metrics_->incrementSuccessfulCommands();
                return true;
            }
        }
        metrics_->incrementFailedCommands();
        return false;
    }

    bool sismember(const std::string& key, const std::string& member) override {
        std::lock_guard<std::mutex> lock(data_mutex_);
        metrics_->incrementTotalCommands();
        
        if (connected_ && !simulate_failures_) {
            auto keyIt = set_data_.find(key);
            if (keyIt != set_data_.end()) {
                bool isMember = keyIt->second.find(member) != keyIt->second.end();
                metrics_->incrementSuccessfulCommands();
                return isMember;
            }
        }
        metrics_->incrementFailedCommands();
        return false;
    }

    std::vector<std::string> smembers(const std::string& key) override {
        std::lock_guard<std::mutex> lock(data_mutex_);
        metrics_->incrementTotalCommands();
        std::vector<std::string> members;
        
        if (connected_ && !simulate_failures_) {
            auto keyIt = set_data_.find(key);
            if (keyIt != set_data_.end()) {
                for (const auto& member : keyIt->second) {
                    members.push_back(member);
                }
                metrics_->incrementSuccessfulCommands();
            }
        } else {
            metrics_->incrementFailedCommands();
        }
        return members;
    }

    // List operations
    bool lpush(const std::string& key, const std::string& value) override {
        std::lock_guard<std::mutex> lock(data_mutex_);
        metrics_->incrementTotalCommands();
        
        if (connected_ && !simulate_failures_) {
            list_data_[key].insert(list_data_[key].begin(), value);
            metrics_->incrementSuccessfulCommands();
            return true;
        }
        metrics_->incrementFailedCommands();
        return false;
    }

    bool rpush(const std::string& key, const std::string& value) override {
        std::lock_guard<std::mutex> lock(data_mutex_);
        metrics_->incrementTotalCommands();
        
        if (connected_ && !simulate_failures_) {
            list_data_[key].push_back(value);
            metrics_->incrementSuccessfulCommands();
            return true;
        }
        metrics_->incrementFailedCommands();
        return false;
    }

    bool lpop(const std::string& key, std::string& value) override {
        std::lock_guard<std::mutex> lock(data_mutex_);
        metrics_->incrementTotalCommands();
        
        if (connected_ && !simulate_failures_) {
            auto keyIt = list_data_.find(key);
            if (keyIt != list_data_.end() && !keyIt->second.empty()) {
                value = keyIt->second.front();
                keyIt->second.erase(keyIt->second.begin());
                metrics_->incrementSuccessfulCommands();
                return true;
            }
        }
        metrics_->incrementFailedCommands();
        return false;
    }

    bool rpop(const std::string& key, std::string& value) override {
        std::lock_guard<std::mutex> lock(data_mutex_);
        metrics_->incrementTotalCommands();
        
        if (connected_ && !simulate_failures_) {
            auto keyIt = list_data_.find(key);
            if (keyIt != list_data_.end() && !keyIt->second.empty()) {
                value = keyIt->second.back();
                keyIt->second.pop_back();
                metrics_->incrementSuccessfulCommands();
                return true;
            }
        }
        metrics_->incrementFailedCommands();
        return false;
    }

    size_t llen(const std::string& key) override {
        std::lock_guard<std::mutex> lock(data_mutex_);
        metrics_->incrementTotalCommands();
        
        if (connected_ && !simulate_failures_) {
            auto keyIt = list_data_.find(key);
            if (keyIt != list_data_.end()) {
                metrics_->incrementSuccessfulCommands();
                return keyIt->second.size();
            }
        }
        metrics_->incrementFailedCommands();
        return 0;
    }

    std::vector<std::string> lrange(const std::string& key, int start, int stop) override {
        std::lock_guard<std::mutex> lock(data_mutex_);
        metrics_->incrementTotalCommands();
        std::vector<std::string> result;
        
        if (connected_ && !simulate_failures_) {
            auto keyIt = list_data_.find(key);
            if (keyIt != list_data_.end()) {
                const auto& list = keyIt->second;
                int size = static_cast<int>(list.size());
                
                // Handle negative indices
                if (start < 0) start = size + start;
                if (stop < 0) stop = size + stop;
                
                // Bounds checking
                start = std::max(0, std::min(start, size - 1));
                stop = std::max(0, std::min(stop, size - 1));
                
                if (start <= stop) {
                    for (int i = start; i <= stop; ++i) {
                        result.push_back(list[i]);
                    }
                }
                metrics_->incrementSuccessfulCommands();
            }
        } else {
            metrics_->incrementFailedCommands();
        }
        return result;
    }

    std::shared_ptr<IRedisMetrics> getMetrics() override {
        return metrics_;
    }

    // Mock-specific methods for testing
    void setConnected(bool connected) {
        connected_ = connected;
        metrics_->setConnected(connected);
    }

    void setSimulateFailures(bool simulate) {
        simulate_failures_ = simulate;
    }

    void clearData() {
        std::lock_guard<std::mutex> lock(data_mutex_);
        string_data_.clear();
        hash_data_.clear();
        set_data_.clear();
        list_data_.clear();
        published_messages_.clear();
    }

    std::vector<std::pair<std::string, std::string>> getPublishedMessages() const {
        std::lock_guard<std::mutex> lock(data_mutex_);
        return published_messages_;
    }
};

// Mock Redis Client Factory
class MockRedisClientFactory : public IRedisClientFactory {
public:
    std::unique_ptr<IRedisClient> create(const RedisConfig& config) override {
        return std::make_unique<MockRedisClient>();
    }

    std::unique_ptr<IRedisClient> createWithConnectionString(const std::string& connectionString) override {
        return std::make_unique<MockRedisClient>();
    }
};

} // namespace mocks
} // namespace infra
} // namespace coyote
