#pragma once

#include <string>
#include <memory>
#include <vector>
#include <mutex>
#include <fstream>
#include <chrono>
#include <sstream>
#include <iostream>
#include <unordered_map>

namespace coyote {
namespace infra {

// Log levels enum
enum class LogLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
    FATAL = 5
};

// Log entry structure
struct LogEntry {
    std::chrono::system_clock::time_point timestamp;
    LogLevel level;
    std::string logger;
    std::string message;
    std::string file;
    int line;
    std::string function;
    std::unordered_map<std::string, std::string> context;
};

// Forward declarations
class RedisClient;

// Abstract logger interface
class ILogger {
public:
    virtual ~ILogger() = default;
    
    virtual void log(LogLevel level, const std::string& logger, const std::string& message,
                     const std::string& file = "", int line = 0, const std::string& function = "",
                     const std::unordered_map<std::string, std::string>& context = {}) = 0;
    
    virtual void setLevel(LogLevel level) = 0;
    virtual LogLevel getLevel() const = 0;
    virtual void flush() = 0;
    
    // Convenience methods
    void trace(const std::string& logger, const std::string& message, const std::string& file = "", int line = 0, const std::string& function = "");
    void debug(const std::string& logger, const std::string& message, const std::string& file = "", int line = 0, const std::string& function = "");
    void info(const std::string& logger, const std::string& message, const std::string& file = "", int line = 0, const std::string& function = "");
    void warn(const std::string& logger, const std::string& message, const std::string& file = "", int line = 0, const std::string& function = "");
    void error(const std::string& logger, const std::string& message, const std::string& file = "", int line = 0, const std::string& function = "");
    void fatal(const std::string& logger, const std::string& message, const std::string& file = "", int line = 0, const std::string& function = "");
};

// Console logger implementation
class ConsoleLogger : public ILogger {
private:
    LogLevel m_level;
    mutable std::mutex m_mutex;
    bool m_colorOutput;

public:
    explicit ConsoleLogger(LogLevel level = LogLevel::INFO, bool colorOutput = true);
    
    void log(LogLevel level, const std::string& logger, const std::string& message,
             const std::string& file = "", int line = 0, const std::string& function = "",
             const std::unordered_map<std::string, std::string>& context = {}) override;
    
    void setLevel(LogLevel level) override;
    LogLevel getLevel() const override;
    void flush() override;
    
private:
    std::string formatLogEntry(const LogEntry& entry) const;
    std::string levelToString(LogLevel level) const;
    std::string levelToColor(LogLevel level) const;
};

// File logger implementation
class FileLogger : public ILogger {
private:
    LogLevel m_level;
    std::string m_filePath;
    mutable std::mutex m_mutex;
    mutable std::ofstream m_file;
    size_t m_maxFileSize;
    int m_maxFiles;
    bool m_autoFlush;

public:
    explicit FileLogger(const std::string& filePath, LogLevel level = LogLevel::INFO,
                       size_t maxFileSize = 100 * 1024 * 1024, int maxFiles = 5, bool autoFlush = true);
    ~FileLogger();
    
    void log(LogLevel level, const std::string& logger, const std::string& message,
             const std::string& file = "", int line = 0, const std::string& function = "",
             const std::unordered_map<std::string, std::string>& context = {}) override;
    
    void setLevel(LogLevel level) override;
    LogLevel getLevel() const override;
    void flush() override;
    
private:
    void rotateFile();
    std::string formatLogEntry(const LogEntry& entry) const;
    std::string levelToString(LogLevel level) const;
};

// Redis logger implementation
class RedisLogger : public ILogger {
private:
    LogLevel m_level;
    std::shared_ptr<RedisClient> m_redisClient;
    std::string m_channel;
    std::string m_keyPrefix;
    mutable std::mutex m_mutex;
    bool m_publishToChannel;
    bool m_storeInList;
    size_t m_maxListSize;

public:
    explicit RedisLogger(std::shared_ptr<RedisClient> redisClient, const std::string& channel = "logs",
                        const std::string& keyPrefix = "log:", LogLevel level = LogLevel::INFO,
                        bool publishToChannel = true, bool storeInList = true, size_t maxListSize = 10000);
    
    void log(LogLevel level, const std::string& logger, const std::string& message,
             const std::string& file = "", int line = 0, const std::string& function = "",
             const std::unordered_map<std::string, std::string>& context = {}) override;
    
    void setLevel(LogLevel level) override;
    LogLevel getLevel() const override;
    void flush() override;
    
private:
    std::string formatLogEntry(const LogEntry& entry) const;
    std::string levelToString(LogLevel level) const;
};

// Composite logger - logs to multiple backends
class CompositeLogger : public ILogger {
private:
    std::vector<std::shared_ptr<ILogger>> m_loggers;
    LogLevel m_level;
    mutable std::mutex m_mutex;

public:
    explicit CompositeLogger(LogLevel level = LogLevel::INFO);
    
    void addLogger(std::shared_ptr<ILogger> logger);
    void removeLogger(std::shared_ptr<ILogger> logger);
    void clearLoggers();
    
    void log(LogLevel level, const std::string& logger, const std::string& message,
             const std::string& file = "", int line = 0, const std::string& function = "",
             const std::unordered_map<std::string, std::string>& context = {}) override;
    
    void setLevel(LogLevel level) override;
    LogLevel getLevel() const override;
    void flush() override;
};

// Logger factory
class LoggerFactory {
public:
    static std::shared_ptr<ILogger> createConsoleLogger(LogLevel level = LogLevel::INFO, bool colorOutput = true);
    static std::shared_ptr<ILogger> createFileLogger(const std::string& filePath, LogLevel level = LogLevel::INFO,
                                                     size_t maxFileSize = 100 * 1024 * 1024, int maxFiles = 5, bool autoFlush = true);
    static std::shared_ptr<ILogger> createRedisLogger(std::shared_ptr<RedisClient> redisClient, const std::string& channel = "logs",
                                                      const std::string& keyPrefix = "log:", LogLevel level = LogLevel::INFO,
                                                      bool publishToChannel = true, bool storeInList = true, size_t maxListSize = 10000);
    static std::shared_ptr<ILogger> createCompositeLogger(LogLevel level = LogLevel::INFO);
    
    // Parse log level from string
    static LogLevel parseLogLevel(const std::string& levelStr);
    static std::string logLevelToString(LogLevel level);
};

// Utility macros for easy logging with file/line/function info
#define LOG_TRACE(logger, message) logger->trace(__FILE__, message, __FILE__, __LINE__, __FUNCTION__)
#define LOG_DEBUG(logger, message) logger->debug(__FILE__, message, __FILE__, __LINE__, __FUNCTION__)
#define LOG_INFO(logger, message) logger->info(__FILE__, message, __FILE__, __LINE__, __FUNCTION__)
#define LOG_WARN(logger, message) logger->warn(__FILE__, message, __FILE__, __LINE__, __FUNCTION__)
#define LOG_ERROR(logger, message) logger->error(__FILE__, message, __FILE__, __LINE__, __FUNCTION__)
#define LOG_FATAL(logger, message) logger->fatal(__FILE__, message, __FILE__, __LINE__, __FUNCTION__)

} // namespace infra
} // namespace coyote
// log real impl placeholder