#include "Logger.h"
#include "RedisClient.h"
#include <nlohmann/json.hpp>
#include <iomanip>
#include <filesystem>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#endif

namespace coyote {
namespace infra {

// ILogger convenience methods implementation
void ILogger::trace(const std::string& logger, const std::string& message, const std::string& file, int line, const std::string& function) {
    log(LogLevel::TRACE, logger, message, file, line, function);
}

void ILogger::debug(const std::string& logger, const std::string& message, const std::string& file, int line, const std::string& function) {
    log(LogLevel::DEBUG, logger, message, file, line, function);
}

void ILogger::info(const std::string& logger, const std::string& message, const std::string& file, int line, const std::string& function) {
    log(LogLevel::INFO, logger, message, file, line, function);
}

void ILogger::warn(const std::string& logger, const std::string& message, const std::string& file, int line, const std::string& function) {
    log(LogLevel::WARN, logger, message, file, line, function);
}

void ILogger::error(const std::string& logger, const std::string& message, const std::string& file, int line, const std::string& function) {
    log(LogLevel::ERROR, logger, message, file, line, function);
}

void ILogger::fatal(const std::string& logger, const std::string& message, const std::string& file, int line, const std::string& function) {
    log(LogLevel::FATAL, logger, message, file, line, function);
}

// ConsoleLogger implementation
ConsoleLogger::ConsoleLogger(LogLevel level, bool colorOutput) 
    : m_level(level), m_colorOutput(colorOutput) {
#ifdef _WIN32
    if (m_colorOutput) {
        // Enable ANSI color codes on Windows
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD dwMode = 0;
        GetConsoleMode(hOut, &dwMode);
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, dwMode);
    }
#endif
}

void ConsoleLogger::log(LogLevel level, const std::string& logger, const std::string& message,
                       const std::string& file, int line, const std::string& function,
                       const std::unordered_map<std::string, std::string>& context) {
    if (level < m_level) return;
    
    LogEntry entry;
    entry.timestamp = std::chrono::system_clock::now();
    entry.level = level;
    entry.logger = logger;
    entry.message = message;
    entry.file = file;
    entry.line = line;
    entry.function = function;
    entry.context = context;
    
    std::lock_guard<std::mutex> lock(m_mutex);
    std::cout << formatLogEntry(entry) << std::endl;
}

void ConsoleLogger::setLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_level = level;
}

LogLevel ConsoleLogger::getLevel() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_level;
}

void ConsoleLogger::flush() {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::cout.flush();
}

std::string ConsoleLogger::formatLogEntry(const LogEntry& entry) const {
    auto time_t = std::chrono::system_clock::to_time_t(entry.timestamp);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        entry.timestamp.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    
    if (m_colorOutput) {
        ss << levelToColor(entry.level);
    }
    
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    ss << "." << std::setfill('0') << std::setw(3) << ms.count();
    ss << " [" << levelToString(entry.level) << "]";
    ss << " [" << entry.logger << "]";
    
    if (!entry.file.empty()) {
        std::filesystem::path filePath(entry.file);
        ss << " (" << filePath.filename().string() << ":" << entry.line << ")";
    }
    
    ss << " - " << entry.message;
    
    if (!entry.context.empty()) {
        ss << " {";
        bool first = true;
        for (const auto& [key, value] : entry.context) {
            if (!first) ss << ", ";
            ss << key << "=" << value;
            first = false;
        }
        ss << "}";
    }
    
    if (m_colorOutput) {
        ss << "\033[0m"; // Reset color
    }
    
    return ss.str();
}

std::string ConsoleLogger::levelToString(LogLevel level) const {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO ";
        case LogLevel::WARN:  return "WARN ";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}

std::string ConsoleLogger::levelToColor(LogLevel level) const {
    switch (level) {
        case LogLevel::TRACE: return "\033[37m";   // White
        case LogLevel::DEBUG: return "\033[36m";   // Cyan
        case LogLevel::INFO:  return "\033[32m";   // Green
        case LogLevel::WARN:  return "\033[33m";   // Yellow
        case LogLevel::ERROR: return "\033[31m";   // Red
        case LogLevel::FATAL: return "\033[35m";   // Magenta
        default: return "\033[0m";  // Reset
    }
}

// FileLogger implementation
FileLogger::FileLogger(const std::string& filePath, LogLevel level, size_t maxFileSize, int maxFiles, bool autoFlush)
    : m_level(level), m_filePath(filePath), m_maxFileSize(maxFileSize), m_maxFiles(maxFiles), m_autoFlush(autoFlush) {
    
    // Create directory if it doesn't exist
    std::filesystem::path path(filePath);
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path());
    }
    
    m_file.open(filePath, std::ios::app);
    if (!m_file.is_open()) {
        throw std::runtime_error("Failed to open log file: " + filePath);
    }
}

FileLogger::~FileLogger() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_file.is_open()) {
        m_file.close();
    }
}

void FileLogger::log(LogLevel level, const std::string& logger, const std::string& message,
                    const std::string& file, int line, const std::string& function,
                    const std::unordered_map<std::string, std::string>& context) {
    if (level < m_level) return;
    
    LogEntry entry;
    entry.timestamp = std::chrono::system_clock::now();
    entry.level = level;
    entry.logger = logger;
    entry.message = message;
    entry.file = file;
    entry.line = line;
    entry.function = function;
    entry.context = context;
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Check if file rotation is needed
    if (m_file.tellp() > static_cast<std::streampos>(m_maxFileSize)) {
        rotateFile();
    }
    
    m_file << formatLogEntry(entry) << std::endl;
    
    if (m_autoFlush) {
        m_file.flush();
    }
}

void FileLogger::setLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_level = level;
}

LogLevel FileLogger::getLevel() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_level;
}

void FileLogger::flush() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_file.is_open()) {
        m_file.flush();
    }
}

void FileLogger::rotateFile() {
    if (m_file.is_open()) {
        m_file.close();
    }
    
    // Rotate existing files
    for (int i = m_maxFiles - 1; i > 0; --i) {
        std::string oldFile = m_filePath + "." + std::to_string(i);
        std::string newFile = m_filePath + "." + std::to_string(i + 1);
        
        if (std::filesystem::exists(oldFile)) {
            std::filesystem::rename(oldFile, newFile);
        }
    }
    
    // Move current file to .1
    if (std::filesystem::exists(m_filePath)) {
        std::filesystem::rename(m_filePath, m_filePath + ".1");
    }
    
    // Open new file
    m_file.open(m_filePath, std::ios::app);
}

std::string FileLogger::formatLogEntry(const LogEntry& entry) const {
    auto time_t = std::chrono::system_clock::to_time_t(entry.timestamp);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        entry.timestamp.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    ss << "." << std::setfill('0') << std::setw(3) << ms.count();
    ss << " [" << levelToString(entry.level) << "]";
    ss << " [" << entry.logger << "]";
    
    if (!entry.file.empty()) {
        std::filesystem::path filePath(entry.file);
        ss << " (" << filePath.filename().string() << ":" << entry.line << ")";
    }
    
    ss << " - " << entry.message;
    
    if (!entry.context.empty()) {
        ss << " {";
        bool first = true;
        for (const auto& [key, value] : entry.context) {
            if (!first) ss << ", ";
            ss << key << "=" << value;
            first = false;
        }
        ss << "}";
    }
    
    return ss.str();
}

std::string FileLogger::levelToString(LogLevel level) const {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO ";
        case LogLevel::WARN:  return "WARN ";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}

// RedisLogger implementation
RedisLogger::RedisLogger(std::shared_ptr<RedisClient> redisClient, const std::string& channel,
                        const std::string& keyPrefix, LogLevel level, bool publishToChannel,
                        bool storeInList, size_t maxListSize)
    : m_level(level), m_redisClient(redisClient), m_channel(channel), m_keyPrefix(keyPrefix),
      m_publishToChannel(publishToChannel), m_storeInList(storeInList), m_maxListSize(maxListSize) {
}

void RedisLogger::log(LogLevel level, const std::string& logger, const std::string& message,
                     const std::string& file, int line, const std::string& function,
                     const std::unordered_map<std::string, std::string>& context) {
    if (level < m_level || !m_redisClient) return;
    
    LogEntry entry;
    entry.timestamp = std::chrono::system_clock::now();
    entry.level = level;
    entry.logger = logger;
    entry.message = message;
    entry.file = file;
    entry.line = line;
    entry.function = function;
    entry.context = context;
    
    std::string logJson = formatLogEntry(entry);
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Publish to channel
    if (m_publishToChannel) {
        m_redisClient->publishAsync(m_channel, logJson);
    }
    
    // Store in list
    if (m_storeInList) {
        std::string listKey = m_keyPrefix + "list";
        m_redisClient->executeAsync([this, listKey, logJson](redisContext* context) {
            // Add to list
            redisReply* reply = (redisReply*)redisCommand(context, "LPUSH %s %s", listKey.c_str(), logJson.c_str());
            if (reply) {
                freeReplyObject(reply);
            }
            
            // Trim list to max size
            reply = (redisReply*)redisCommand(context, "LTRIM %s 0 %zu", listKey.c_str(), m_maxListSize - 1);
            if (reply) {
                freeReplyObject(reply);
            }
        });
    }
}

void RedisLogger::setLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_level = level;
}

LogLevel RedisLogger::getLevel() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_level;
}

void RedisLogger::flush() {
    // Redis operations are async, so we don't need to do anything here
}

std::string RedisLogger::formatLogEntry(const LogEntry& entry) const {
    nlohmann::json json;
    
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        entry.timestamp.time_since_epoch()).count();
    
    json["timestamp"] = ms;
    json["level"] = levelToString(entry.level);
    json["logger"] = entry.logger;
    json["message"] = entry.message;
    
    if (!entry.file.empty()) {
        std::filesystem::path filePath(entry.file);
        json["file"] = filePath.filename().string();
        json["line"] = entry.line;
    }
    
    if (!entry.function.empty()) {
        json["function"] = entry.function;
    }
    
    if (!entry.context.empty()) {
        json["context"] = entry.context;
    }
    
    return json.dump();
}

std::string RedisLogger::levelToString(LogLevel level) const {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO";
        case LogLevel::WARN:  return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}

// CompositeLogger implementation
CompositeLogger::CompositeLogger(LogLevel level) : m_level(level) {
}

void CompositeLogger::addLogger(std::shared_ptr<ILogger> logger) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_loggers.push_back(logger);
}

void CompositeLogger::removeLogger(std::shared_ptr<ILogger> logger) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_loggers.erase(std::remove(m_loggers.begin(), m_loggers.end(), logger), m_loggers.end());
}

void CompositeLogger::clearLoggers() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_loggers.clear();
}

void CompositeLogger::log(LogLevel level, const std::string& logger, const std::string& message,
                         const std::string& file, int line, const std::string& function,
                         const std::unordered_map<std::string, std::string>& context) {
    if (level < m_level) return;
    
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& loggerPtr : m_loggers) {
        if (loggerPtr) {
            loggerPtr->log(level, logger, message, file, line, function, context);
        }
    }
}

void CompositeLogger::setLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_level = level;
    for (auto& logger : m_loggers) {
        if (logger) {
            logger->setLevel(level);
        }
    }
}

LogLevel CompositeLogger::getLevel() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_level;
}

void CompositeLogger::flush() {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& logger : m_loggers) {
        if (logger) {
            logger->flush();
        }
    }
}

// LoggerFactory implementation
std::shared_ptr<ILogger> LoggerFactory::createConsoleLogger(LogLevel level, bool colorOutput) {
    return std::make_shared<ConsoleLogger>(level, colorOutput);
}

std::shared_ptr<ILogger> LoggerFactory::createFileLogger(const std::string& filePath, LogLevel level,
                                                         size_t maxFileSize, int maxFiles, bool autoFlush) {
    return std::make_shared<FileLogger>(filePath, level, maxFileSize, maxFiles, autoFlush);
}

std::shared_ptr<ILogger> LoggerFactory::createRedisLogger(std::shared_ptr<RedisClient> redisClient, const std::string& channel,
                                                          const std::string& keyPrefix, LogLevel level,
                                                          bool publishToChannel, bool storeInList, size_t maxListSize) {
    return std::make_shared<RedisLogger>(redisClient, channel, keyPrefix, level, publishToChannel, storeInList, maxListSize);
}

std::shared_ptr<ILogger> LoggerFactory::createCompositeLogger(LogLevel level) {
    return std::make_shared<CompositeLogger>(level);
}

LogLevel LoggerFactory::parseLogLevel(const std::string& levelStr) {
    std::string upper = levelStr;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
    
    if (upper == "TRACE") return LogLevel::TRACE;
    if (upper == "DEBUG") return LogLevel::DEBUG;
    if (upper == "INFO") return LogLevel::INFO;
    if (upper == "WARN" || upper == "WARNING") return LogLevel::WARN;
    if (upper == "ERROR") return LogLevel::ERROR;
    if (upper == "FATAL") return LogLevel::FATAL;
    
    return LogLevel::INFO; // Default
}

std::string LoggerFactory::logLevelToString(LogLevel level) {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO";
        case LogLevel::WARN:  return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}

} // namespace infra
} // namespace coyote
