#pragma once

#include <string>
#include <unordered_map>
#include <memory>

namespace nebula_shield {

    class ConfigManager {
    public:
        ConfigManager();
        ~ConfigManager();

        // Configuration loading and saving
        bool loadFromFile(const std::string& config_file = "config.json");
        bool saveToFile(const std::string& config_file = "config.json");
        
        // String configuration
        void setString(const std::string& key, const std::string& value);
        std::string getString(const std::string& key, const std::string& default_value = "");
        
        // Numeric configuration
        void setInt(const std::string& key, int value);
        int getInt(const std::string& key, int default_value = 0);
        
        void setDouble(const std::string& key, double value);
        double getDouble(const std::string& key, double default_value = 0.0);
        
        // Boolean configuration
        void setBool(const std::string& key, bool value);
        bool getBool(const std::string& key, bool default_value = false);
        
        // Default settings
        void loadDefaults();
        
        // Validation
        bool isValid() const { return is_valid_; }

    private:
        std::unordered_map<std::string, std::string> config_data_;
        std::string config_file_path_;
        bool is_valid_;
        
        std::string boolToString(bool value);
        bool stringToBool(const std::string& value);
    };

} // namespace nebula_shield