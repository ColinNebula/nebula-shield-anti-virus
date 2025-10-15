#include "database_manager.h"
#include <sqlite3.h>
#include <iostream>
#include <sstream>
#include <chrono>
#include <iomanip>

namespace nebula_shield {

    DatabaseManager::DatabaseManager() : db_(nullptr) {
    }

    DatabaseManager::~DatabaseManager() {
        close();
    }

    bool DatabaseManager::initialize(const std::string& db_path) {
        db_path_ = db_path;
        
        int result = sqlite3_open(db_path.c_str(), &db_);
        if (result != SQLITE_OK) {
            std::cerr << "Failed to open database: " << sqlite3_errmsg(db_) << std::endl;
            db_ = nullptr;
            return false;
        }

        if (!createTables()) {
            close();
            return false;
        }

        std::cout << "Database initialized successfully: " << db_path << std::endl;
        return true;
    }

    void DatabaseManager::close() {
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
    }

    bool DatabaseManager::createTables() {
        const char* scan_results_table = R"(
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                threat_name TEXT,
                confidence REAL,
                hash TEXT,
                file_size INTEGER,
                scan_time TEXT,
                quarantined INTEGER DEFAULT 0
            )
        )";

        const char* signatures_table = R"(
            CREATE TABLE IF NOT EXISTS signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                pattern BLOB,
                type TEXT NOT NULL,
                severity REAL,
                description TEXT
            )
        )";

        const char* quarantine_table = R"(
            CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                original_path TEXT NOT NULL,
                quarantine_time TEXT,
                file_size INTEGER
            )
        )";

        const char* configuration_table = R"(
            CREATE TABLE IF NOT EXISTS configuration (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        )";

        // Execute table creation queries
        char* error_msg = nullptr;
        
        if (sqlite3_exec(db_, scan_results_table, nullptr, nullptr, &error_msg) != SQLITE_OK) {
            std::cerr << "Failed to create scan_results table: " << error_msg << std::endl;
            sqlite3_free(error_msg);
            return false;
        }

        if (sqlite3_exec(db_, signatures_table, nullptr, nullptr, &error_msg) != SQLITE_OK) {
            std::cerr << "Failed to create signatures table: " << error_msg << std::endl;
            sqlite3_free(error_msg);
            return false;
        }

        if (sqlite3_exec(db_, quarantine_table, nullptr, nullptr, &error_msg) != SQLITE_OK) {
            std::cerr << "Failed to create quarantine table: " << error_msg << std::endl;
            sqlite3_free(error_msg);
            return false;
        }

        if (sqlite3_exec(db_, configuration_table, nullptr, nullptr, &error_msg) != SQLITE_OK) {
            std::cerr << "Failed to create configuration table: " << error_msg << std::endl;
            sqlite3_free(error_msg);
            return false;
        }

        return true;
    }

    bool DatabaseManager::saveScanResult(const ScanResult& result) {
        if (!db_) return false;

        const char* sql = R"(
            INSERT INTO scan_results 
            (file_path, threat_type, threat_name, confidence, hash, file_size, scan_time, quarantined)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        )";

        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            std::cerr << "Failed to prepare scan result insert statement" << std::endl;
            return false;
        }

        sqlite3_bind_text(stmt, 1, result.file_path.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, threatTypeToString(result.threat_type).c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, result.threat_name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_double(stmt, 4, result.confidence);
        sqlite3_bind_text(stmt, 5, result.hash.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 6, result.file_size);
        sqlite3_bind_text(stmt, 7, result.scan_time.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 8, result.quarantined ? 1 : 0);

        int result_code = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        return result_code == SQLITE_DONE;
    }

    std::vector<DatabaseScanResult> DatabaseManager::getScanResults(int limit) {
        std::vector<DatabaseScanResult> results;
        if (!db_) return results;

        const char* sql = R"(
            SELECT id, file_path, threat_type, threat_name, confidence, hash, file_size, scan_time, quarantined
            FROM scan_results
            ORDER BY id DESC
            LIMIT ?
        )";

        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return results;
        }

        sqlite3_bind_int(stmt, 1, limit);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            DatabaseScanResult result;
            result.id = sqlite3_column_int(stmt, 0);
            result.file_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            result.threat_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            
            const char* threat_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            result.threat_name = threat_name ? threat_name : "";
            
            result.confidence = sqlite3_column_double(stmt, 4);
            
            const char* hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
            result.hash = hash ? hash : "";
            
            result.file_size = sqlite3_column_int64(stmt, 6);
            
            const char* scan_time = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            result.scan_time = scan_time ? scan_time : "";
            
            result.quarantined = sqlite3_column_int(stmt, 8) != 0;

            results.push_back(result);
        }

        sqlite3_finalize(stmt);
        return results;
    }

    std::vector<DatabaseScanResult> DatabaseManager::getScanResultsByType(ThreatType type) {
        std::vector<DatabaseScanResult> results;
        if (!db_) return results;

        const char* sql = R"(
            SELECT id, file_path, threat_type, threat_name, confidence, hash, file_size, scan_time, quarantined
            FROM scan_results
            WHERE threat_type = ?
            ORDER BY id DESC
        )";

        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return results;
        }

        sqlite3_bind_text(stmt, 1, threatTypeToString(type).c_str(), -1, SQLITE_STATIC);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            DatabaseScanResult result;
            result.id = sqlite3_column_int(stmt, 0);
            result.file_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            result.threat_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            
            const char* threat_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            result.threat_name = threat_name ? threat_name : "";
            
            result.confidence = sqlite3_column_double(stmt, 4);
            
            const char* hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
            result.hash = hash ? hash : "";
            
            result.file_size = sqlite3_column_int64(stmt, 6);
            
            const char* scan_time = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            result.scan_time = scan_time ? scan_time : "";
            
            result.quarantined = sqlite3_column_int(stmt, 8) != 0;

            results.push_back(result);
        }

        sqlite3_finalize(stmt);
        return results;
    }

    bool DatabaseManager::saveSignature(const ThreatSignature& signature) {
        if (!db_) return false;

        const char* sql = R"(
            INSERT OR REPLACE INTO signatures (name, pattern, type, severity, description)
            VALUES (?, ?, ?, ?, ?)
        )";

        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }

        sqlite3_bind_text(stmt, 1, signature.name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 2, signature.pattern.data(), signature.pattern.size(), SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, threatTypeToString(signature.type).c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_double(stmt, 4, signature.severity);
        sqlite3_bind_text(stmt, 5, signature.description.c_str(), -1, SQLITE_STATIC);

        int result = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        return result == SQLITE_DONE;
    }

    std::vector<ThreatSignature> DatabaseManager::loadSignatures() {
        std::vector<ThreatSignature> signatures;
        if (!db_) return signatures;

        const char* sql = "SELECT name, pattern, type, severity, description FROM signatures";

        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return signatures;
        }

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            ThreatSignature signature;
            signature.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            
            const void* pattern_data = sqlite3_column_blob(stmt, 1);
            int pattern_size = sqlite3_column_bytes(stmt, 1);
            if (pattern_data && pattern_size > 0) {
                const uint8_t* pattern_bytes = static_cast<const uint8_t*>(pattern_data);
                signature.pattern.assign(pattern_bytes, pattern_bytes + pattern_size);
            }
            
            signature.type = stringToThreatType(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2)));
            signature.severity = sqlite3_column_double(stmt, 3);
            
            const char* description = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
            signature.description = description ? description : "";

            signatures.push_back(signature);
        }

        sqlite3_finalize(stmt);
        return signatures;
    }

    int DatabaseManager::getTotalScannedFiles() {
        if (!db_) return 0;

        const char* sql = "SELECT COUNT(*) FROM scan_results";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return 0;
        }

        int count = 0;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            count = sqlite3_column_int(stmt, 0);
        }

        sqlite3_finalize(stmt);
        return count;
    }

    int DatabaseManager::getTotalThreats() {
        if (!db_) return 0;

        const char* sql = "SELECT COUNT(*) FROM scan_results WHERE threat_type != 'CLEAN'";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return 0;
        }

        int count = 0;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            count = sqlite3_column_int(stmt, 0);
        }

        sqlite3_finalize(stmt);
        return count;
    }

    bool DatabaseManager::saveConfiguration(const std::string& key, const std::string& value) {
        if (!db_) return false;

        const char* sql = "INSERT OR REPLACE INTO configuration (key, value) VALUES (?, ?)";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }

        sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, value.c_str(), -1, SQLITE_STATIC);

        int result = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        return result == SQLITE_DONE;
    }

    std::string DatabaseManager::getConfiguration(const std::string& key, const std::string& default_value) {
        if (!db_) return default_value;

        const char* sql = "SELECT value FROM configuration WHERE key = ?";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return default_value;
        }

        sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);

        std::string value = default_value;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* result_value = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            if (result_value) {
                value = result_value;
            }
        }

        sqlite3_finalize(stmt);
        return value;
    }

    std::string DatabaseManager::threatTypeToString(ThreatType type) {
        switch (type) {
            case ThreatType::VIRUS: return "VIRUS";
            case ThreatType::TROJAN: return "TROJAN";
            case ThreatType::MALWARE: return "MALWARE";
            case ThreatType::ADWARE: return "ADWARE";
            case ThreatType::SPYWARE: return "SPYWARE";
            case ThreatType::ROOTKIT: return "ROOTKIT";
            case ThreatType::SUSPICIOUS: return "SUSPICIOUS";
            case ThreatType::CLEAN: return "CLEAN";
            default: return "UNKNOWN";
        }
    }

    ThreatType DatabaseManager::stringToThreatType(const std::string& str) {
        if (str == "VIRUS") return ThreatType::VIRUS;
        if (str == "TROJAN") return ThreatType::TROJAN;
        if (str == "MALWARE") return ThreatType::MALWARE;
        if (str == "ADWARE") return ThreatType::ADWARE;
        if (str == "SPYWARE") return ThreatType::SPYWARE;
        if (str == "ROOTKIT") return ThreatType::ROOTKIT;
        if (str == "SUSPICIOUS") return ThreatType::SUSPICIOUS;
        if (str == "CLEAN") return ThreatType::CLEAN;
        return ThreatType::CLEAN;
    }

    bool DatabaseManager::addToQuarantine(const std::string& file_path, const std::string& original_path) {
        if (!db_) return false;

        const char* sql = R"(
            INSERT INTO quarantine (file_path, original_path, quarantine_time, file_size)
            VALUES (?, ?, datetime('now'), 0)
        )";

        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }

        sqlite3_bind_text(stmt, 1, file_path.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, original_path.c_str(), -1, SQLITE_STATIC);

        int result = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        return result == SQLITE_DONE;
    }

    std::vector<std::string> DatabaseManager::getQuarantinedFiles() {
        std::vector<std::string> files;
        if (!db_) return files;

        const char* sql = "SELECT file_path FROM quarantine ORDER BY quarantine_time DESC";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return files;
        }

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* file_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            if (file_path) {
                files.push_back(file_path);
            }
        }

        sqlite3_finalize(stmt);
        return files;
    }

    bool DatabaseManager::deleteScanResult(int id) {
        if (!db_) return false;

        const char* sql = "DELETE FROM scan_results WHERE id = ?";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }

        sqlite3_bind_int(stmt, 1, id);

        int result = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        return result == SQLITE_DONE;
    }

    bool DatabaseManager::removeFromQuarantine(const std::string& file_path) {
        if (!db_) return false;

        const char* sql = "DELETE FROM quarantine WHERE file_path = ?";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }

        sqlite3_bind_text(stmt, 1, file_path.c_str(), -1, SQLITE_STATIC);

        int result = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        return result == SQLITE_DONE;
    }

    int DatabaseManager::getThreatsInLastDays(int days) {
        if (!db_) return 0;

        const char* sql = R"(
            SELECT COUNT(*) FROM scan_results 
            WHERE threat_type != 'CLEAN' 
            AND datetime(scan_time) >= datetime('now', '-' || ? || ' days')
        )";
        
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return 0;
        }

        sqlite3_bind_int(stmt, 1, days);

        int count = 0;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            count = sqlite3_column_int(stmt, 0);
        }

        sqlite3_finalize(stmt);
        return count;
    }

    bool DatabaseManager::clearOldScanResults(int days_old) {
        if (!db_) return false;

        const char* sql = R"(
            DELETE FROM scan_results 
            WHERE datetime(scan_time) < datetime('now', '-' || ? || ' days')
        )";
        
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }

        sqlite3_bind_int(stmt, 1, days_old);

        int result = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        return result == SQLITE_DONE;
    }

} // namespace nebula_shield