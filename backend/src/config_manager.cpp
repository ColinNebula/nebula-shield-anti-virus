#include "config_manager.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <regex>

namespace nebula_shield {

    ConfigManager::ConfigManager() : is_valid_(false) {
        loadDefaults();
    }

    ConfigManager::~ConfigManager() = default;

    void ConfigManager::loadDefaults() {
        // Server configuration
        setString("server.host", "localhost");
        setInt("server.port", 8080);
        setBool("server.cors_enabled", true);
        setString("server.allowed_origins", "http://localhost:3000");
        
        // Scanner configuration
        setInt("scanner.max_file_size", 104857600); // 100MB
        setInt("scanner.timeout_seconds", 30);
        setBool("scanner.scan_archives", true);
        setBool("scanner.heuristic_analysis", true);
        setDouble("scanner.threat_threshold", 0.6);
        
        // Real-time protection
        setBool("protection.real_time_enabled", true);
        setBool("protection.scan_downloads", true);
        setBool("protection.scan_usb", true);
        setBool("protection.auto_quarantine", true);
        
        // Database configuration
        setString("database.path", "data/nebula_shield.db");
        setInt("database.cleanup_days", 30);
        setBool("database.auto_backup", true);
        
        // Logging configuration
        setString("logging.level", "INFO");
        setString("logging.file", "logs/nebula_shield.log");
        setBool("logging.console", true);
        setBool("logging.file_enabled", true);
        setInt("logging.max_file_size", 10485760); // 10MB
        
        // Update configuration
        setBool("updates.auto_update", true);
        setInt("updates.check_interval_hours", 24);
        setString("updates.signature_url", "https://signatures.nebula-shield.com/latest");
        
        is_valid_ = true;
    }

    bool ConfigManager::loadFromFile(const std::string& config_file) {
        config_file_path_ = config_file;
        std::ifstream file(config_file);
        
        if (!file.is_open()) {
            std::cout << "Config file not found, using defaults: " << config_file << std::endl;
            return true; // Use defaults if file doesn't exist
        }

        std::string line;
        std::regex config_regex(R"(\s*(\w+(?:\.\w+)*)\s*=\s*(.+)\s*)");
        std::smatch match;

        while (std::getline(file, line)) {
            // Skip comments and empty lines
            if (line.empty() || line[0] == '#' || line[0] == ';') {
                continue;
            }

            if (std::regex_match(line, match, config_regex)) {
                std::string key = match[1].str();
                std::string value = match[2].str();
                
                // Remove quotes if present
                if (value.length() >= 2 && value[0] == '"' && value[value.length()-1] == '"') {
                    value = value.substr(1, value.length() - 2);
                }
                
                config_data_[key] = value;
            }
        }

        file.close();
        is_valid_ = true;
        
        std::cout << "Configuration loaded from: " << config_file << std::endl;
        return true;
    }

    bool ConfigManager::saveToFile(const std::string& config_file) {
        std::string file_path = config_file.empty() ? config_file_path_ : config_file;
        std::ofstream file(file_path);
        
        if (!file.is_open()) {
            std::cerr << "Failed to save configuration to: " << file_path << std::endl;
            return false;
        }

        file << "# Nebula Shield Anti-Virus Configuration\n";
        file << "# Generated automatically - modify with care\n\n";

        // Group configurations by prefix
        std::vector<std::string> sections = {"server", "scanner", "protection", "database", "logging", "updates"};
        
        for (const auto& section : sections) {
            file << "# " << section << " configuration\n";
            
            for (const auto& [key, value] : config_data_) {
                if (key.find(section + ".") == 0) {
                    file << key << " = \"" << value << "\"\n";
                }
            }
            file << "\n";
        }

        file.close();
        std::cout << "Configuration saved to: " << file_path << std::endl;
        return true;
    }

    void ConfigManager::setString(const std::string& key, const std::string& value) {
        config_data_[key] = value;
    }

    std::string ConfigManager::getString(const std::string& key, const std::string& default_value) {
        auto it = config_data_.find(key);
        return (it != config_data_.end()) ? it->second : default_value;
    }

    void ConfigManager::setInt(const std::string& key, int value) {
        config_data_[key] = std::to_string(value);
    }

    int ConfigManager::getInt(const std::string& key, int default_value) {
        auto it = config_data_.find(key);
        if (it != config_data_.end()) {
            try {
                return std::stoi(it->second);
            } catch (...) {
                return default_value;
            }
        }
        return default_value;
    }

    void ConfigManager::setDouble(const std::string& key, double value) {
        config_data_[key] = std::to_string(value);
    }

    double ConfigManager::getDouble(const std::string& key, double default_value) {
        auto it = config_data_.find(key);
        if (it != config_data_.end()) {
            try {
                return std::stod(it->second);
            } catch (...) {
                return default_value;
            }
        }
        return default_value;
    }

    void ConfigManager::setBool(const std::string& key, bool value) {
        config_data_[key] = boolToString(value);
    }

    bool ConfigManager::getBool(const std::string& key, bool default_value) {
        auto it = config_data_.find(key);
        return (it != config_data_.end()) ? stringToBool(it->second) : default_value;
    }

    std::string ConfigManager::boolToString(bool value) {
        return value ? "true" : "false";
    }

    bool ConfigManager::stringToBool(const std::string& value) {
        std::string lower_value = value;
        std::transform(lower_value.begin(), lower_value.end(), lower_value.begin(), ::tolower);
        
        return (lower_value == "true" || lower_value == "1" || lower_value == "yes" || lower_value == "on");
    }

} // namespace nebula_shield