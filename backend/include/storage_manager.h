#pragma once

#include <string>
#include <cstdint>

namespace nebula_shield {

    struct StorageInfo {
        uint64_t total_space;      // Total disk space in bytes
        uint64_t available_space;  // Available disk space in bytes
        uint64_t used_space;       // Used disk space in bytes
        double usage_percentage;   // Percentage of disk used
        uint64_t quarantine_size;  // Total size of quarantine folder
        uint64_t database_size;    // Size of database file
        uint64_t backup_size;      // Total size of backup files
    };

    class StorageManager {
    public:
        StorageManager();
        ~StorageManager();

        // Storage monitoring
        StorageInfo getStorageInfo(const std::string& path = ".");
        uint64_t getDirectorySize(const std::string& directory_path);
        uint64_t getFileSize(const std::string& file_path);
        
        // Space checks
        bool hasEnoughSpace(uint64_t required_bytes, const std::string& path = ".");
        bool isQuarantineWithinLimit(const std::string& quarantine_path);
        double getQuarantineUsagePercentage(const std::string& quarantine_path);
        
        // Cleanup operations
        bool cleanupOldBackups(const std::string& directory_path, int days_old = 7);
        bool cleanupQuarantineIfNeeded(const std::string& quarantine_path);
        bool deleteOldestQuarantinedFile(const std::string& quarantine_path);
        
        // Limits configuration
        void setQuarantineLimit(uint64_t limit_bytes);
        void setMinimumFreeSpace(uint64_t min_bytes);
        uint64_t getQuarantineLimit() const { return quarantine_limit_; }
        uint64_t getMinimumFreeSpace() const { return min_free_space_; }

    private:
        uint64_t getDiskSpace(const std::string& path, bool get_available);
        
        uint64_t quarantine_limit_;   // Max quarantine size (default 1 GB)
        uint64_t min_free_space_;     // Minimum free space required (default 500 MB)
    };

} // namespace nebula_shield
