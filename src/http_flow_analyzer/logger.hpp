#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <iostream>
#include <string>
#include <sstream>
#include <mutex>
#include <ctime>

/**
 * Simple logger with log levels: DEBUG, INFO, WARNING, ERROR
 * 
 * Usage:
 *   Logger::setLevel(LogLevel::INFO);  // Set minimum log level
 *   LOG_DEBUG("Debug message: " << value);
 *   LOG_INFO("Info message");
 *   LOG_WARNING("Warning: " << condition);
 *   LOG_ERROR("Error: " << error_msg);
 * 
 * Features:
 *   - Thread-safe (uses mutex)
 *   - Compile-time disabled for release builds (use -DNDEBUG)
 *   - Zero-cost when level is below threshold
 *   - Timestamp support
 */

enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3,
    NONE = 4  // Disable all logging
};

class Logger {
public:
    // Set global log level (messages below this level are ignored)
    static void setLevel(LogLevel level) {
        std::lock_guard<std::mutex> lock(mutex_);
        current_level_ = level;
    }
    
    // Get current log level
    static LogLevel getLevel() {
        std::lock_guard<std::mutex> lock(mutex_);
        return current_level_;
    }
    
    // Enable/disable timestamps
    static void setShowTimestamp(bool show) {
        std::lock_guard<std::mutex> lock(mutex_);
        show_timestamp_ = show;
    }
    
    // Check if a level is enabled (for optimization)
    static bool isEnabled(LogLevel level) {
        return level >= current_level_;
    }
    
    // Log a message at specified level
    static void log(LogLevel level, const std::string& message,
                   const char* file = nullptr, int line = 0) {
        if (level < current_level_) {
            return;  // Skip if below threshold
        }
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        std::ostringstream oss;
        
        // Timestamp
        if (show_timestamp_) {
            time_t now = time(nullptr);
            char buf[32];
            strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
            oss << "[" << buf << "] ";
        }
        
        // Log level
        oss << "[" << levelToString(level) << "] ";
        
        // File and line (for DEBUG/ERROR)
        if ((level == LogLevel::DEBUG || level == LogLevel::ERROR) && file) {
            oss << file << ":" << line << " - ";
        }
        
        // Message
        oss << message << "\n";
        
        // Output to appropriate stream
        if (level >= LogLevel::ERROR) {
            std::cerr << oss.str() << std::flush;
        } else {
            std::cout << oss.str() << std::flush;
        }
    }

private:
    static const char* levelToString(LogLevel level) {
        switch (level) {
            case LogLevel::DEBUG:   return "DEBUG";
            case LogLevel::INFO:    return "INFO";
            case LogLevel::WARNING: return "WARN";
            case LogLevel::ERROR:   return "ERROR";
            default:                return "UNKNOWN";
        }
    }
    
    static LogLevel current_level_;
    static bool show_timestamp_;
    static std::mutex mutex_;
};

#define LOG_DEBUG(msg) \
    do { \
        if (Logger::isEnabled(LogLevel::DEBUG)) { \
            std::ostringstream oss; \
            oss << msg; \
            Logger::log(LogLevel::DEBUG, oss.str(), __FILE__, __LINE__); \
        } \
    } while(0)

#define LOG_INFO(msg) \
    do { \
        if (Logger::isEnabled(LogLevel::INFO)) { \
            std::ostringstream oss; \
            oss << msg; \
            Logger::log(LogLevel::INFO, oss.str()); \
        } \
    } while(0)

#define LOG_WARNING(msg) \
    do { \
        if (Logger::isEnabled(LogLevel::WARNING)) { \
            std::ostringstream oss; \
            oss << msg; \
            Logger::log(LogLevel::WARNING, oss.str()); \
        } \
    } while(0)

#define LOG_ERROR(msg) \
    do { \
        if (Logger::isEnabled(LogLevel::ERROR)) { \
            std::ostringstream oss; \
            oss << msg; \
            Logger::log(LogLevel::ERROR, oss.str(), __FILE__, __LINE__); \
        } \
    } while(0)

// Compile-time disable for release builds
#ifdef NDEBUG
#undef LOG_DEBUG
#define LOG_DEBUG(msg) do {} while(0)
#endif

#endif  // LOGGER_HPP
