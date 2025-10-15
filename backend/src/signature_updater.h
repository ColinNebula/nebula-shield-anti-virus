#ifndef SIGNATURE_UPDATER_H
#define SIGNATURE_UPDATER_H

#include <string>
#include <vector>
#include <ctime>
#include "../include/database_manager.h"
#include "../include/scanner_engine.h"

namespace NebulaShield {

    // Use nebula_shield namespace types
    using nebula_shield::ThreatSignature;
    using nebula_shield::ThreatType;
    using nebula_shield::DatabaseManager;

    /**
     * @brief Handles automatic updates of virus signature database
     * 
     * This class manages downloading, parsing, and updating the virus
     * signature database from a remote server or threat intelligence feed.
     */
    class SignatureUpdater {
    public:
        /**
         * @brief Constructor
         * @param db_manager Pointer to database manager
         * @param api_key API key for authentication (optional)
         * @param update_url URL to download signatures from
         */
        SignatureUpdater(DatabaseManager* db_manager,
                        const std::string& api_key = "",
                        const std::string& update_url = "https://signatures.nebulashield.com/api/v1/signatures");

        /**
         * @brief Destructor
         */
        ~SignatureUpdater();

        /**
         * @brief Update virus signatures from remote server
         * @return true if update successful, false otherwise
         */
        bool updateSignatures();

        /**
         * @brief Check if updates are available
         * @return true if updates available, false otherwise
         */
        bool checkForUpdates();

        /**
         * @brief Check if an update is currently in progress
         * @return true if updating, false otherwise
         */
        bool isUpdateInProgress() const;

        /**
         * @brief Get the timestamp of the last successful update
         * @return Unix timestamp of last update
         */
        time_t getLastUpdateTime() const;

        /**
         * @brief Schedule automatic updates
         * @param hours Interval in hours between automatic updates
         */
        void scheduleAutoUpdate(int hours);

        /**
         * @brief Check if automatic update should run now
         * @return true if auto-update is due, false otherwise
         */
        bool shouldAutoUpdate() const;

    private:
        DatabaseManager* db_manager_;
        std::string api_key_;
        std::string update_url_;
        bool is_updating_;
        time_t last_update_time_;
        int auto_update_interval_hours_ = 24; // Default: update daily

        /**
         * @brief Load signatures from local file
         * @param file_path Path to signature JSON file
         * @param output String to store loaded data
         * @return true if load successful, false otherwise
         */
        bool loadSignaturesFromFile(const std::string& file_path, std::string& output);

        /**
         * @brief Download signatures from remote server
         * @param output String to store downloaded data
         * @return true if download successful, false otherwise
         */
        bool downloadSignatures(std::string& output);

        /**
         * @brief Parse JSON signature data
         * @param data JSON string containing signatures
         * @param signatures Output vector of parsed signatures
         * @return true if parsing successful, false otherwise
         */
        bool parseSignatures(const std::string& data, 
                           std::vector<ThreatSignature>& signatures);

        /**
         * @brief Update database with new signatures
         * @param signatures Vector of signatures to add
         * @return true if update successful, false otherwise
         */
        bool updateDatabase(const std::vector<ThreatSignature>& signatures);

        /**
         * @brief Convert hex string to byte array
         * @param hex Hexadecimal string
         * @return Vector of bytes
         */
        std::vector<uint8_t> hexStringToBytes(const std::string& hex);

        /**
         * @brief Convert string to ThreatType enum
         * @param type_str String representation of threat type
         * @return ThreatType enum value
         */
        ThreatType stringToThreatType(const std::string& type_str);
    };

} // namespace NebulaShield

#endif // SIGNATURE_UPDATER_H
