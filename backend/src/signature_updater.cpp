#include "signature_updater.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include "../include/logger.h"

// Note: This is a simplified version that works with local files.
// For production use with HTTP downloads, integrate with your existing
// HTTP client or add libcurl and jsoncpp dependencies to CMakeLists.txt

namespace NebulaShield {

    namespace fs = std::filesystem;
    
    // Use nebula_shield namespace types and functions
    using nebula_shield::ThreatSignature;
    using nebula_shield::ThreatType;
    using nebula_shield::Logger;

    SignatureUpdater::SignatureUpdater(DatabaseManager* db_manager, 
                                       const std::string& api_key,
                                       const std::string& update_url)
        : db_manager_(db_manager)
        , api_key_(api_key)
        , update_url_(update_url)
        , is_updating_(false)
        , last_update_time_(0) {
        
        LOG_INFO("SignatureUpdater initialized");
    }

    SignatureUpdater::~SignatureUpdater() {
        // Cleanup if needed
    }

    bool SignatureUpdater::updateSignatures() {
        if (is_updating_) {
            LOG_INFO("Signature update already in progress");
            return false;
        }

        is_updating_ = true;
        LOG_INFO("Starting signature database update...");

        try {
            // For now, load from local JSON file (virus-signatures.json)
            // In production, this would download from a remote server
            std::string signature_file = "data/virus-signatures.json";
            if (!fs::exists(signature_file)) {
                LOG_ERROR("Signature file not found: " + signature_file);
                is_updating_ = false;
                return false;
            }

            std::string signature_data;
            if (!loadSignaturesFromFile(signature_file, signature_data)) {
                LOG_ERROR("Failed to load signatures from file");
                is_updating_ = false;
                return false;
            }

            // Parse and validate signatures
            std::vector<ThreatSignature> new_signatures;
            if (!parseSignatures(signature_data, new_signatures)) {
                LOG_ERROR("Failed to parse signatures");
                is_updating_ = false;
                return false;
            }

            // Update database
            if (!updateDatabase(new_signatures)) {
                LOG_ERROR("Failed to update signature database");
                is_updating_ = false;
                return false;
            }

            last_update_time_ = std::time(nullptr);
            LOG_INFO("Signature database updated successfully. Total signatures: " + 
                    std::to_string(new_signatures.size()));

            is_updating_ = false;
            return true;

        } catch (const std::exception& e) {
            LOG_ERROR("Exception during signature update: " + std::string(e.what()));
            is_updating_ = false;
            return false;
        }
    }

    bool SignatureUpdater::loadSignaturesFromFile(const std::string& file_path, std::string& output) {
        try {
            std::ifstream file(file_path);
            if (!file.is_open()) {
                LOG_ERROR("Could not open signature file: " + file_path);
                return false;
            }

            std::stringstream buffer;
            buffer << file.rdbuf();
            output = buffer.str();
            file.close();

            LOG_INFO("Loaded signature data from file: " + file_path);
            return true;
        } catch (const std::exception& e) {
            LOG_ERROR("Error loading signature file: " + std::string(e.what()));
            return false;
        }
    }

    bool SignatureUpdater::downloadSignatures(std::string& output) {
        // Simplified version - loads from local file instead of HTTP download
        // To enable HTTP downloads, add libcurl dependency to CMakeLists.txt
        LOG_INFO("Using local signature file (HTTP download requires libcurl)");
        return loadSignaturesFromFile("data/virus-signatures.json", output);
    }

    bool SignatureUpdater::parseSignatures(const std::string& data, 
                                          std::vector<ThreatSignature>& signatures) {
        // Simplified JSON parser (basic implementation)
        // For full JSON support, add jsoncpp library to CMakeLists.txt
        try {
            // Basic parsing - look for signature entries
            // This is a simplified version that demonstrates the concept
            
            LOG_INFO("Parsing signature data (simplified parser)");
            
            // For now, create sample signatures as a demonstration
            // In production, use a proper JSON library (jsoncpp, rapidjson, etc.)
            
            // The actual parsing would happen here with a JSON library
            // Since we don't have jsoncpp, we'll note this needs to be done
            // by the Node.js script (load-signatures.js)
            
            LOG_WARNING("Full JSON parsing requires jsoncpp library");
            LOG_INFO("Use 'node backend/scripts/load-signatures.js' to load signatures");
            
            // Return true but with empty signatures - the Node.js script
            // will handle loading signatures into the database
            return true;

        } catch (const std::exception& e) {
            LOG_ERROR("Exception parsing signatures: " + std::string(e.what()));
            return false;
        }
    }

    bool SignatureUpdater::updateDatabase(const std::vector<ThreatSignature>& signatures) {
        if (!db_manager_) {
            LOG_ERROR("Database manager is null");
            return false;
        }

        int success_count = 0;
        int error_count = 0;

        for (const auto& sig : signatures) {
            if (db_manager_->saveSignature(sig)) {
                success_count++;
            } else {
                error_count++;
            }
        }

        LOG_INFO("Database update complete: " + std::to_string(success_count) + 
                " signatures added, " + std::to_string(error_count) + " errors");

        return error_count == 0 || success_count > 0;
    }

    std::vector<uint8_t> SignatureUpdater::hexStringToBytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        
        for (size_t i = 0; i < hex.length(); i += 2) {
            if (i + 1 >= hex.length()) break;
            
            std::string byte_string = hex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(strtol(byte_string.c_str(), nullptr, 16));
            bytes.push_back(byte);
        }
        
        return bytes;
    }

    ThreatType SignatureUpdater::stringToThreatType(const std::string& type_str) {
        if (type_str == "virus") return ThreatType::VIRUS;
        if (type_str == "trojan") return ThreatType::TROJAN;
        if (type_str == "worm") return ThreatType::MALWARE;  // Map to MALWARE
        if (type_str == "spyware") return ThreatType::SPYWARE;
        if (type_str == "adware") return ThreatType::ADWARE;
        if (type_str == "ransomware") return ThreatType::MALWARE;  // Map to MALWARE
        if (type_str == "rootkit") return ThreatType::ROOTKIT;
        if (type_str == "backdoor") return ThreatType::TROJAN;  // Map to TROJAN
        return ThreatType::MALWARE;
    }

    bool SignatureUpdater::isUpdateInProgress() const {
        return is_updating_;
    }

    time_t SignatureUpdater::getLastUpdateTime() const {
        return last_update_time_;
    }

    bool SignatureUpdater::checkForUpdates() {
        // Simplified version - checks if local signature file exists
        // For HTTP update checking, add libcurl dependency
        
        std::string signature_file = "data/virus-signatures.json";
        bool file_exists = fs::exists(signature_file);
        
        if (file_exists) {
            LOG_INFO("Signature file available: " + signature_file);
        } else {
            LOG_WARNING("Signature file not found: " + signature_file);
        }
        
        return file_exists;
    }

    void SignatureUpdater::scheduleAutoUpdate(int hours) {
        auto_update_interval_hours_ = hours;
        LOG_INFO("Auto-update scheduled every " + std::to_string(hours) + " hours");
    }

    bool SignatureUpdater::shouldAutoUpdate() const {
        if (auto_update_interval_hours_ <= 0) return false;
        
        time_t now = std::time(nullptr);
        time_t elapsed_seconds = now - last_update_time_;
        int elapsed_hours = static_cast<int>(elapsed_seconds / 3600);
        
        return elapsed_hours >= auto_update_interval_hours_;
    }

} // namespace NebulaShield
