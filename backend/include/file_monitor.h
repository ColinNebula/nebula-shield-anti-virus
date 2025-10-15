#pragma once

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <chrono>
#include <condition_variable>

namespace nebula_shield {

    struct FileEvent {
        std::string file_path;
        std::string event_type; // "created", "modified", "deleted", "moved"
        std::string timestamp;
        size_t file_size;
        std::string file_extension;
        bool is_executable;
        uint32_t process_id; // Process that triggered the event
    };

    struct MonitoringStats {
        uint64_t total_events;
        uint64_t files_scanned;
        uint64_t threats_detected;
        uint64_t threats_blocked;
        uint64_t false_positives;
        uint64_t events_per_second;
        std::chrono::system_clock::time_point start_time;
        double cpu_usage;
        size_t memory_usage_mb;
    };

    struct MonitoringConfig {
        // Performance settings
        size_t max_file_size_mb = 100;          // Don't scan files larger than this
        int scan_delay_ms = 100;                 // Delay before scanning (debounce)
        int max_concurrent_scans = 4;            // Maximum parallel scans
        bool enable_deep_scan = true;            // Deep scanning for executables
        
        // Monitoring scope
        bool monitor_downloads = true;
        bool monitor_system_files = true;
        bool monitor_program_files = true;
        bool monitor_temp_files = true;
        bool monitor_user_documents = false;     // Privacy consideration
        bool monitor_network_drives = false;     // Can be slow
        
        // Threat response
        bool auto_quarantine = true;
        double quarantine_threshold = 0.8;       // Confidence threshold
        bool block_on_scan = true;               // Block file access during scan
        bool prompt_user = false;                // Show user prompts
        
        // Advanced features
        bool enable_behavior_analysis = true;
        bool enable_process_monitoring = true;
        bool enable_network_monitoring = false;  // Requires admin
        bool enable_memory_scanning = false;     // CPU intensive
        bool cache_scan_results = true;          // Cache by file hash
        int cache_ttl_minutes = 60;              // Cache validity
    };

    class FileMonitor {
    public:
        FileMonitor();
        ~FileMonitor();

        // Monitoring control
        bool startMonitoring(const std::string& directory_path);
        void stopMonitoring();
        bool isMonitoring() const { return is_monitoring_; }

        // Directory management
        void addWatchDirectory(const std::string& directory_path);
        void removeWatchDirectory(const std::string& directory_path);
        std::vector<std::string> getWatchedDirectories() const;

        // Event callbacks
        void setFileEventCallback(std::function<void(const FileEvent&)> callback);
        
        // Configuration
        void setRealTimeProtection(bool enabled) { real_time_protection_ = enabled; }
        bool isRealTimeProtectionEnabled() const { return real_time_protection_; }
        void setMonitoringConfig(const MonitoringConfig& config) { config_ = config; }
        MonitoringConfig getMonitoringConfig() const { return config_; }
        
        // Whitelist/Blacklist management
        void addToWhitelist(const std::string& path_or_hash);
        void removeFromWhitelist(const std::string& path_or_hash);
        void addToBlacklist(const std::string& path_or_hash);
        void removeFromBlacklist(const std::string& path_or_hash);
        bool isWhitelisted(const std::string& path_or_hash) const;
        bool isBlacklisted(const std::string& path_or_hash) const;
        
        // File extension filtering
        void addMonitoredExtension(const std::string& extension);
        void removeMonitoredExtension(const std::string& extension);
        void addIgnoredExtension(const std::string& extension);
        void removeIgnoredExtension(const std::string& extension);
        
        // Statistics and monitoring
        MonitoringStats getStatistics() const;
        void resetStatistics();
        std::vector<FileEvent> getRecentEvents(size_t count = 100) const;
        
        // Advanced features
        void pauseMonitoring();
        void resumeMonitoring();
        bool isPaused() const { return is_paused_; }
        void setMaxQueueSize(size_t size) { max_queue_size_ = size; }
        size_t getQueueSize() const;

    private:
        void monitoringLoop();
        void processFileEvent(const std::string& file_path, const std::string& event_type, uint32_t process_id = 0);
        void scanQueueProcessor();
        void statisticsCollector();
        
        bool shouldMonitorFile(const std::string& file_path) const;
        bool shouldScanFile(const std::string& file_path, const std::string& event_type);
        std::string getFileExtension(const std::string& file_path) const;
        bool isExecutableFile(const std::string& file_path) const;
        std::string calculateFileHash(const std::string& file_path) const;
        
#ifdef _WIN32
        void watchDirectoryWindows(const std::string& directory_path);
        uint32_t getProcessIdFromHandle(void* handle);
#endif

    private:
        // Core monitoring state
        std::atomic<bool> is_monitoring_;
        std::atomic<bool> is_paused_;
        std::atomic<bool> real_time_protection_;
        std::vector<std::string> watched_directories_;
        std::vector<std::thread> monitoring_threads_;
        std::thread scan_processor_thread_;
        std::thread stats_thread_;
        std::mutex directories_mutex_;
        
        // Configuration
        MonitoringConfig config_;
        
        // Event handling
        std::function<void(const FileEvent&)> file_event_callback_;
        std::queue<FileEvent> scan_queue_;
        mutable std::mutex queue_mutex_;
        std::condition_variable queue_cv_;
        size_t max_queue_size_ = 1000;
        
        // Whitelist/Blacklist
        std::unordered_set<std::string> whitelist_;
        std::unordered_set<std::string> blacklist_;
        mutable std::mutex whitelist_mutex_;
        mutable std::mutex blacklist_mutex_;
        
        // File filtering
        std::unordered_set<std::string> monitored_extensions_;
        std::unordered_set<std::string> ignored_extensions_;
        mutable std::mutex extensions_mutex_;
        
        // Scan result caching
        struct CachedScanResult {
            bool is_threat;
            std::chrono::system_clock::time_point scan_time;
        };
        std::unordered_map<std::string, CachedScanResult> scan_cache_;
        mutable std::mutex cache_mutex_;
        
        // Statistics
        MonitoringStats stats_;
        mutable std::mutex stats_mutex_;
        std::vector<FileEvent> recent_events_;
        mutable std::mutex events_mutex_;
        
        // Debouncing (prevent duplicate scans)
        std::unordered_map<std::string, std::chrono::system_clock::time_point> last_scan_time_;
        mutable std::mutex debounce_mutex_;
    };

} // namespace nebula_shield