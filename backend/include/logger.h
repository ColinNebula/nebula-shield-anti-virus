#pragma once

#include <string>
#include <memory>
#include <fstream>
#include <mutex>

namespace nebula_shield {

    enum class LogLevel {
        DEBUG = 0,
        INFO = 1,
        WARNING = 2,
        ERROR = 3,
        CRITICAL = 4
    };

    class Logger {
    public:
        static Logger& getInstance();
        
        // Logging methods
        void debug(const std::string& message);
        void info(const std::string& message);
        void warning(const std::string& message);
        void error(const std::string& message);
        void critical(const std::string& message);
        
        void log(LogLevel level, const std::string& message);
        
        // Configuration
        void setLogLevel(LogLevel level) { min_log_level_ = level; }
        void setLogFile(const std::string& file_path);
        void setConsoleLogging(bool enabled) { console_logging_ = enabled; }
        void setFileLogging(bool enabled) { file_logging_ = enabled; }
        
        // File management
        void rotateLogFile();
        void setMaxFileSize(size_t max_size) { max_file_size_ = max_size; }

    private:
        Logger();
        ~Logger();
        
        // Prevent copying
        Logger(const Logger&) = delete;
        Logger& operator=(const Logger&) = delete;
        
        void writeLog(LogLevel level, const std::string& message);
        std::string getCurrentTimestamp();
        std::string logLevelToString(LogLevel level);
        
        LogLevel min_log_level_;
        bool console_logging_;
        bool file_logging_;
        std::string log_file_path_;
        std::ofstream log_file_;
        std::mutex log_mutex_;
        size_t max_file_size_;
        size_t current_file_size_;
    };

    // Convenience macros
    #define LOG_DEBUG(msg) Logger::getInstance().debug(msg)
    #define LOG_INFO(msg) Logger::getInstance().info(msg)
    #define LOG_WARNING(msg) Logger::getInstance().warning(msg)
    #define LOG_ERROR(msg) Logger::getInstance().error(msg)
    #define LOG_CRITICAL(msg) Logger::getInstance().critical(msg)

} // namespace nebula_shield