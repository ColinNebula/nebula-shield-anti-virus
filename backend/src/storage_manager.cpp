#include "storage_manager.h"
#include "logger.h"
#include <filesystem>
#include <chrono>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#undef max  // Prevent Windows.h max macro from conflicting with std::numeric_limits
#undef min
#else
#include <sys/statvfs.h>
#endif

namespace nebula_shield {

    StorageManager::StorageManager() 
        : quarantine_limit_(1024ULL * 1024 * 1024)  // 1 GB default
        , min_free_space_(500ULL * 1024 * 1024)      // 500 MB default
    {
    }

    StorageManager::~StorageManager() = default;

    uint64_t StorageManager::getDiskSpace(const std::string& path, bool get_available) {
#ifdef _WIN32
        ULARGE_INTEGER freeBytesAvailable, totalBytes, totalFreeBytes;
        
        std::string absolute_path = std::filesystem::absolute(path).string();
        
        if (GetDiskFreeSpaceExA(absolute_path.c_str(), 
                                &freeBytesAvailable, 
                                &totalBytes, 
                                &totalFreeBytes)) {
            return get_available ? freeBytesAvailable.QuadPart : totalBytes.QuadPart;
        }
        return 0;
#else
        struct statvfs stat;
        if (statvfs(path.c_str(), &stat) == 0) {
            if (get_available) {
                return stat.f_bavail * stat.f_frsize;
            } else {
                return stat.f_blocks * stat.f_frsize;
            }
        }
        return 0;
#endif
    }

    StorageInfo StorageManager::getStorageInfo(const std::string& path) {
        StorageInfo info = {};
        
        try {
            info.total_space = getDiskSpace(path, false);
            info.available_space = getDiskSpace(path, true);
            info.used_space = info.total_space - info.available_space;
            
            if (info.total_space > 0) {
                info.usage_percentage = (static_cast<double>(info.used_space) / info.total_space) * 100.0;
            }
            
            // Get quarantine size
            if (std::filesystem::exists("quarantine")) {
                info.quarantine_size = getDirectorySize("quarantine");
            }
            
            // Get database size
            if (std::filesystem::exists("nebula_shield.db")) {
                info.database_size = getFileSize("nebula_shield.db");
            }
            
            // Get backup files size
            info.backup_size = 0;
            for (const auto& entry : std::filesystem::recursive_directory_iterator(".")) {
                if (entry.is_regular_file()) {
                    std::string filename = entry.path().filename().string();
                    if (filename.ends_with(".backup")) {
                        info.backup_size += entry.file_size();
                    }
                }
            }
            
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to get storage info: " + std::string(e.what()));
        }
        
        return info;
    }

    uint64_t StorageManager::getDirectorySize(const std::string& directory_path) {
        uint64_t total_size = 0;
        
        try {
            if (!std::filesystem::exists(directory_path)) {
                return 0;
            }
            
            for (const auto& entry : std::filesystem::recursive_directory_iterator(directory_path)) {
                if (entry.is_regular_file()) {
                    total_size += entry.file_size();
                }
            }
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to get directory size: " + std::string(e.what()));
        }
        
        return total_size;
    }

    uint64_t StorageManager::getFileSize(const std::string& file_path) {
        try {
            if (std::filesystem::exists(file_path)) {
                return std::filesystem::file_size(file_path);
            }
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to get file size: " + std::string(e.what()));
        }
        return 0;
    }

    bool StorageManager::hasEnoughSpace(uint64_t required_bytes, const std::string& path) {
        uint64_t available = getDiskSpace(path, true);
        
        // Check if we have required bytes + minimum free space buffer
        bool has_space = available >= (required_bytes + min_free_space_);
        
        if (!has_space) {
            LOG_WARNING("Insufficient disk space. Required: " + 
                       std::to_string(required_bytes / (1024 * 1024)) + " MB, Available: " + 
                       std::to_string(available / (1024 * 1024)) + " MB");
        }
        
        return has_space;
    }

    bool StorageManager::isQuarantineWithinLimit(const std::string& quarantine_path) {
        uint64_t current_size = getDirectorySize(quarantine_path);
        bool within_limit = current_size < quarantine_limit_;
        
        if (!within_limit) {
            LOG_WARNING("Quarantine folder exceeds limit. Current: " + 
                       std::to_string(current_size / (1024 * 1024)) + " MB, Limit: " + 
                       std::to_string(quarantine_limit_ / (1024 * 1024)) + " MB");
        }
        
        return within_limit;
    }

    double StorageManager::getQuarantineUsagePercentage(const std::string& quarantine_path) {
        uint64_t current_size = getDirectorySize(quarantine_path);
        
        if (quarantine_limit_ == 0) {
            return 0.0;
        }
        
        return (static_cast<double>(current_size) / quarantine_limit_) * 100.0;
    }

    bool StorageManager::cleanupOldBackups(const std::string& directory_path, int days_old) {
        int deleted_count = 0;
        
        try {
            auto now = std::chrono::system_clock::now();
            auto cutoff_time = now - std::chrono::hours(24 * days_old);
            
            for (const auto& entry : std::filesystem::recursive_directory_iterator(directory_path)) {
                if (entry.is_regular_file()) {
                    std::string filename = entry.path().filename().string();
                    
                    if (filename.ends_with(".backup")) {
                        auto file_time = std::filesystem::last_write_time(entry.path());
                        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                            file_time - std::filesystem::file_time_type::clock::now() + 
                            std::chrono::system_clock::now()
                        );
                        
                        if (sctp < cutoff_time) {
                            std::filesystem::remove(entry.path());
                            deleted_count++;
                            LOG_INFO("Deleted old backup: " + entry.path().string());
                        }
                    }
                }
            }
            
            if (deleted_count > 0) {
                LOG_INFO("Cleaned up " + std::to_string(deleted_count) + " old backup files");
            }
            
            return true;
            
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to cleanup old backups: " + std::string(e.what()));
            return false;
        }
    }

    bool StorageManager::deleteOldestQuarantinedFile(const std::string& quarantine_path) {
        try {
            std::filesystem::path oldest_file;
            std::filesystem::file_time_type oldest_time = std::filesystem::file_time_type::max();
            
            for (const auto& entry : std::filesystem::directory_iterator(quarantine_path)) {
                if (entry.is_regular_file()) {
                    auto file_time = std::filesystem::last_write_time(entry.path());
                    if (file_time < oldest_time) {
                        oldest_time = file_time;
                        oldest_file = entry.path();
                    }
                }
            }
            
            if (!oldest_file.empty()) {
                uint64_t file_size = std::filesystem::file_size(oldest_file);
                std::filesystem::remove(oldest_file);
                LOG_INFO("Deleted oldest quarantined file: " + oldest_file.string() + 
                        " (" + std::to_string(file_size / 1024) + " KB)");
                return true;
            }
            
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to delete oldest quarantined file: " + std::string(e.what()));
        }
        
        return false;
    }

    bool StorageManager::cleanupQuarantineIfNeeded(const std::string& quarantine_path) {
        if (!std::filesystem::exists(quarantine_path)) {
            return true;
        }
        
        // Check if quarantine is over limit
        while (!isQuarantineWithinLimit(quarantine_path)) {
            LOG_INFO("Quarantine folder over limit, removing oldest file...");
            if (!deleteOldestQuarantinedFile(quarantine_path)) {
                return false;
            }
        }
        
        return true;
    }

    void StorageManager::setQuarantineLimit(uint64_t limit_bytes) {
        quarantine_limit_ = limit_bytes;
        LOG_INFO("Quarantine limit set to " + std::to_string(limit_bytes / (1024 * 1024)) + " MB");
    }

    void StorageManager::setMinimumFreeSpace(uint64_t min_bytes) {
        min_free_space_ = min_bytes;
        LOG_INFO("Minimum free space set to " + std::to_string(min_bytes / (1024 * 1024)) + " MB");
    }

} // namespace nebula_shield
