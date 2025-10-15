#pragma once

#include <string>
#include <vector>
#include <memory>
#include "scanner_engine.h"

struct sqlite3;

namespace nebula_shield {

    struct DatabaseScanResult {
        int id;
        std::string file_path;
        std::string threat_type;
        std::string threat_name;
        double confidence;
        std::string hash;
        size_t file_size;
        std::string scan_time;
        bool quarantined;
    };

    class DatabaseManager {
    public:
        DatabaseManager();
        ~DatabaseManager();

        // Database operations
        bool initialize(const std::string& db_path = "nebula_shield.db");
        void close();
        bool isConnected() const { return db_ != nullptr; }

        // Scan results
        bool saveScanResult(const ScanResult& result);
        std::vector<DatabaseScanResult> getScanResults(int limit = 100);
        std::vector<DatabaseScanResult> getScanResultsByType(ThreatType type);
        bool deleteScanResult(int id);
        bool clearOldScanResults(int days_old = 30);

        // Threat signatures
        bool saveSignature(const ThreatSignature& signature);
        std::vector<ThreatSignature> loadSignatures();
        bool updateSignature(const std::string& name, const ThreatSignature& signature);
        bool deleteSignature(const std::string& name);

        // Quarantine management
        bool addToQuarantine(const std::string& file_path, const std::string& original_path);
        bool removeFromQuarantine(const std::string& file_path);
        std::vector<std::string> getQuarantinedFiles();

        // Statistics
        int getTotalScannedFiles();
        int getTotalThreats();
        int getThreatsInLastDays(int days);

        // Configuration
        bool saveConfiguration(const std::string& key, const std::string& value);
        std::string getConfiguration(const std::string& key, const std::string& default_value = "");

    private:
        bool createTables();
        std::string threatTypeToString(ThreatType type);
        ThreatType stringToThreatType(const std::string& str);
        
        sqlite3* db_;
        std::string db_path_;
    };

} // namespace nebula_shield