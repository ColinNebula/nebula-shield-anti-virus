#include "logger.h"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <filesystem>

namespace nebula_shield {

    Logger& Logger::getInstance() {
        static Logger instance;
        return instance;
    }

    Logger::Logger() 
        : min_log_level_(LogLevel::INFO)
        , console_logging_(true)
        , file_logging_(true)
        , log_file_path_("logs/nebula_shield.log")
        , max_file_size_(10 * 1024 * 1024) // 10MB
        , current_file_size_(0) {
        
        // Create logs directory if it doesn't exist
        std::filesystem::path log_dir = std::filesystem::path(log_file_path_).parent_path();
        if (!log_dir.empty()) {
            std::filesystem::create_directories(log_dir);
        }
    }

    Logger::~Logger() {
        if (log_file_.is_open()) {
            log_file_.close();
        }
    }

    void Logger::debug(const std::string& message) {
        log(LogLevel::DEBUG, message);
    }

    void Logger::info(const std::string& message) {
        log(LogLevel::INFO, message);
    }

    void Logger::warning(const std::string& message) {
        log(LogLevel::WARNING, message);
    }

    void Logger::error(const std::string& message) {
        log(LogLevel::ERROR, message);
    }

    void Logger::critical(const std::string& message) {
        log(LogLevel::CRITICAL, message);
    }

    void Logger::log(LogLevel level, const std::string& message) {
        if (level < min_log_level_) {
            return;
        }

        std::lock_guard<std::mutex> lock(log_mutex_);
        writeLog(level, message);
    }

    void Logger::writeLog(LogLevel level, const std::string& message) {
        std::string timestamp = getCurrentTimestamp();
        std::string level_str = logLevelToString(level);
        std::string formatted_message = "[" + timestamp + "] [" + level_str + "] " + message;

        // Console logging
        if (console_logging_) {
            if (level >= LogLevel::ERROR) {
                std::cerr << formatted_message << std::endl;
            } else {
                std::cout << formatted_message << std::endl;
            }
        }

        // File logging
        if (file_logging_) {
            if (!log_file_.is_open()) {
                log_file_.open(log_file_path_, std::ios::app);
            }

            if (log_file_.is_open()) {
                log_file_ << formatted_message << std::endl;
                log_file_.flush();
                
                current_file_size_ += formatted_message.length() + 1; // +1 for newline
                
                if (current_file_size_ > max_file_size_) {
                    rotateLogFile();
                }
            }
        }
    }

    void Logger::setLogFile(const std::string& file_path) {
        std::lock_guard<std::mutex> lock(log_mutex_);
        
        if (log_file_.is_open()) {
            log_file_.close();
        }
        
        log_file_path_ = file_path;
        current_file_size_ = 0;
        
        // Create directory if it doesn't exist
        std::filesystem::path log_dir = std::filesystem::path(log_file_path_).parent_path();
        if (!log_dir.empty()) {
            std::filesystem::create_directories(log_dir);
        }
        
        // Get current file size if file exists
        if (std::filesystem::exists(log_file_path_)) {
            current_file_size_ = std::filesystem::file_size(log_file_path_);
        }
    }

    void Logger::rotateLogFile() {
        if (log_file_.is_open()) {
            log_file_.close();
        }

        // Create backup filename with timestamp
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y%m%d_%H%M%S");
        
        std::filesystem::path original_path(log_file_path_);
        std::string backup_filename = original_path.stem().string() + "_" + ss.str() + original_path.extension().string();
        std::filesystem::path backup_path = original_path.parent_path() / backup_filename;

        try {
            std::filesystem::rename(log_file_path_, backup_path);
            current_file_size_ = 0;
            
            info("Log file rotated to: " + backup_path.string());
        } catch (const std::exception& e) {
            std::cerr << "Failed to rotate log file: " << e.what() << std::endl;
        }
    }

    std::string Logger::getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    std::string Logger::logLevelToString(LogLevel level) {
        switch (level) {
            case LogLevel::DEBUG: return "DEBUG";
            case LogLevel::INFO: return "INFO";
            case LogLevel::WARNING: return "WARN";
            case LogLevel::ERROR: return "ERROR";
            case LogLevel::CRITICAL: return "CRIT";
            default: return "UNKNOWN";
        }
    }

} // namespace nebula_shield