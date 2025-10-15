#include "file_monitor.h"
#include "logger.h"
#include <chrono>
#include <iostream>
#include <algorithm>
#include <ctime>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#endif

namespace fs = std::filesystem;

namespace nebula_shield {

    FileMonitor::FileMonitor() 
        : is_monitoring_(false)
        , is_paused_(false)
        , real_time_protection_(false) {
        
        // Initialize default monitored extensions (high-risk files)
        monitored_extensions_ = {
            ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js",
            ".jar", ".com", ".scr", ".pif", ".msi", ".app", ".deb", ".rpm",
            ".sh", ".py", ".rb", ".pl", ".php", ".asp", ".aspx", ".jsp"
        };
        
        // Initialize ignored extensions (safe files, improve performance)
        ignored_extensions_ = {
            ".txt", ".log", ".ini", ".cfg", ".conf", ".json", ".xml", ".yml",
            ".md", ".doc", ".docx", ".pdf", ".jpg", ".jpeg", ".png", ".gif",
            ".bmp", ".mp3", ".mp4", ".avi", ".mkv", ".wav", ".flac"
        };
        
        // Initialize statistics
        stats_.total_events = 0;
        stats_.files_scanned = 0;
        stats_.threats_detected = 0;
        stats_.threats_blocked = 0;
        stats_.false_positives = 0;
        stats_.events_per_second = 0;
        stats_.start_time = std::chrono::system_clock::now();
        stats_.cpu_usage = 0.0;
        stats_.memory_usage_mb = 0;
        
        LOG_INFO("FileMonitor initialized with enhanced real-time protection");
    }

    FileMonitor::~FileMonitor() {
        stopMonitoring();
    }

    bool FileMonitor::startMonitoring(const std::string& directory_path) {
        if (!fs::exists(directory_path)) {
            LOG_ERROR("Directory does not exist: " + directory_path);
            return false;
        }

        addWatchDirectory(directory_path);
        
        if (!is_monitoring_) {
            is_monitoring_ = true;
            is_paused_ = false;
            
            // Start scan queue processor
            scan_processor_thread_ = std::thread(&FileMonitor::scanQueueProcessor, this);
            
            // Start statistics collector
            stats_thread_ = std::thread(&FileMonitor::statisticsCollector, this);
            
            // Start monitoring thread for this directory
            monitoring_threads_.emplace_back(&FileMonitor::monitoringLoop, this);
            
            LOG_INFO("Enhanced file monitoring started");
        }
        
        LOG_INFO("Monitoring directory: " + directory_path);
        return true;
    }

    void FileMonitor::stopMonitoring() {
        if (!is_monitoring_) {
            return;
        }

        LOG_INFO("Stopping file monitoring...");
        is_monitoring_ = false;
        
        // Wake up queue processor
        queue_cv_.notify_all();
        
        // Wait for all monitoring threads
        for (auto& thread : monitoring_threads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        monitoring_threads_.clear();
        
        // Wait for scan processor
        if (scan_processor_thread_.joinable()) {
            scan_processor_thread_.join();
        }
        
        // Wait for stats thread
        if (stats_thread_.joinable()) {
            stats_thread_.join();
        }

        LOG_INFO("File monitoring stopped");
    }

    void FileMonitor::pauseMonitoring() {
        is_paused_ = true;
        LOG_INFO("File monitoring paused");
    }

    void FileMonitor::resumeMonitoring() {
        is_paused_ = false;
        LOG_INFO("File monitoring resumed");
    }

    void FileMonitor::addWatchDirectory(const std::string& directory_path) {
        std::lock_guard<std::mutex> lock(directories_mutex_);
        
        auto it = std::find(watched_directories_.begin(), watched_directories_.end(), directory_path);
        if (it == watched_directories_.end()) {
            watched_directories_.push_back(directory_path);
            LOG_INFO("Added watch directory: " + directory_path);
        }
    }

    void FileMonitor::removeWatchDirectory(const std::string& directory_path) {
        std::lock_guard<std::mutex> lock(directories_mutex_);
        
        watched_directories_.erase(
            std::remove(watched_directories_.begin(), watched_directories_.end(), directory_path),
            watched_directories_.end()
        );
        
        LOG_INFO("Removed watch directory: " + directory_path);
    }

    std::vector<std::string> FileMonitor::getWatchedDirectories() const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(directories_mutex_));
        return watched_directories_;
    }

    void FileMonitor::setFileEventCallback(std::function<void(const FileEvent&)> callback) {
        file_event_callback_ = callback;
    }

    // Whitelist/Blacklist management
    void FileMonitor::addToWhitelist(const std::string& path_or_hash) {
        std::lock_guard<std::mutex> lock(whitelist_mutex_);
        whitelist_.insert(path_or_hash);
        LOG_INFO("Added to whitelist: " + path_or_hash);
    }

    void FileMonitor::removeFromWhitelist(const std::string& path_or_hash) {
        std::lock_guard<std::mutex> lock(whitelist_mutex_);
        whitelist_.erase(path_or_hash);
    }

    void FileMonitor::addToBlacklist(const std::string& path_or_hash) {
        std::lock_guard<std::mutex> lock(blacklist_mutex_);
        blacklist_.insert(path_or_hash);
        LOG_WARNING("Added to blacklist: " + path_or_hash);
    }

    void FileMonitor::removeFromBlacklist(const std::string& path_or_hash) {
        std::lock_guard<std::mutex> lock(blacklist_mutex_);
        blacklist_.erase(path_or_hash);
    }

    bool FileMonitor::isWhitelisted(const std::string& path_or_hash) const {
        std::lock_guard<std::mutex> lock(whitelist_mutex_);
        return whitelist_.find(path_or_hash) != whitelist_.end();
    }

    bool FileMonitor::isBlacklisted(const std::string& path_or_hash) const {
        std::lock_guard<std::mutex> lock(blacklist_mutex_);
        return blacklist_.find(path_or_hash) != blacklist_.end();
    }

    // File extension filtering
    void FileMonitor::addMonitoredExtension(const std::string& extension) {
        std::lock_guard<std::mutex> lock(extensions_mutex_);
        monitored_extensions_.insert(extension);
    }

    void FileMonitor::removeMonitoredExtension(const std::string& extension) {
        std::lock_guard<std::mutex> lock(extensions_mutex_);
        monitored_extensions_.erase(extension);
    }

    void FileMonitor::addIgnoredExtension(const std::string& extension) {
        std::lock_guard<std::mutex> lock(extensions_mutex_);
        ignored_extensions_.insert(extension);
    }

    void FileMonitor::removeIgnoredExtension(const std::string& extension) {
        std::lock_guard<std::mutex> lock(extensions_mutex_);
        ignored_extensions_.erase(extension);
    }

    // Statistics
    MonitoringStats FileMonitor::getStatistics() const {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        return stats_;
    }

    void FileMonitor::resetStatistics() {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_events = 0;
        stats_.files_scanned = 0;
        stats_.threats_detected = 0;
        stats_.threats_blocked = 0;
        stats_.false_positives = 0;
        stats_.start_time = std::chrono::system_clock::now();
        LOG_INFO("Statistics reset");
    }

    std::vector<FileEvent> FileMonitor::getRecentEvents(size_t count) const {
        std::lock_guard<std::mutex> lock(events_mutex_);
        size_t start = recent_events_.size() > count ? recent_events_.size() - count : 0;
        return std::vector<FileEvent>(recent_events_.begin() + start, recent_events_.end());
    }

    size_t FileMonitor::getQueueSize() const {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        return scan_queue_.size();
    }

    // Helper functions
    std::string FileMonitor::getFileExtension(const std::string& file_path) const {
        size_t pos = file_path.find_last_of('.');
        if (pos != std::string::npos) {
            std::string ext = file_path.substr(pos);
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            return ext;
        }
        return "";
    }

    bool FileMonitor::isExecutableFile(const std::string& file_path) const {
        std::string ext = getFileExtension(file_path);
        return ext == ".exe" || ext == ".dll" || ext == ".sys" || ext == ".bat" || 
               ext == ".cmd" || ext == ".ps1" || ext == ".vbs" || ext == ".msi";
    }

    bool FileMonitor::shouldMonitorFile(const std::string& file_path) const {
        // Check if whitelisted
        if (isWhitelisted(file_path)) {
            return false;
        }
        
        // Check if blacklisted (always monitor)
        if (isBlacklisted(file_path)) {
            return true;
        }
        
        // Check file extension
        std::string ext = getFileExtension(file_path);
        
        std::lock_guard<std::mutex> lock(extensions_mutex_);
        
        // Skip ignored extensions
        if (ignored_extensions_.find(ext) != ignored_extensions_.end()) {
            return false;
        }
        
        // Monitor if in monitored extensions or if no specific monitoring is set
        if (monitored_extensions_.empty() || 
            monitored_extensions_.find(ext) != monitored_extensions_.end()) {
            return true;
        }
        
        return false;
    }

    bool FileMonitor::shouldScanFile(const std::string& file_path, const std::string& event_type) const {
        if (!fs::exists(file_path)) {
            return false;
        }
        
        // Only scan on create and modify events
        if (event_type != "created" && event_type != "modified") {
            return false;
        }
        
        // Check file size
        try {
            size_t file_size = fs::file_size(file_path);
            size_t max_size = config_.max_file_size_mb * 1024 * 1024;
            if (file_size > max_size) {
                LOG_DEBUG("File too large to scan: " + file_path + " (" + std::to_string(file_size) + " bytes)");
                return false;
            }
        } catch (const std::exception& e) {
            LOG_DEBUG("Could not check file size: " + file_path);
            return false;
        }
        
        // Check if we should monitor this file
        if (!shouldMonitorFile(file_path)) {
            return false;
        }
        
        // Check cache if enabled
        if (config_.cache_scan_results) {
            std::string hash = calculateFileHash(file_path);
            std::lock_guard<std::mutex> lock(cache_mutex_);
            auto it = scan_cache_.find(hash);
            if (it != scan_cache_.end()) {
                auto age = std::chrono::duration_cast<std::chrono::minutes>(
                    std::chrono::system_clock::now() - it->second.scan_time
                ).count();
                if (age < config_.cache_ttl_minutes) {
                    LOG_DEBUG("Using cached scan result for: " + file_path);
                    return false; // Already scanned recently
                }
            }
        }
        
        // Debouncing - avoid scanning the same file too frequently
        {
            std::lock_guard<std::mutex> lock(debounce_mutex_);
            auto it = last_scan_time_.find(file_path);
            if (it != last_scan_time_.end()) {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now() - it->second
                ).count();
                if (elapsed < config_.scan_delay_ms) {
                    return false; // Too soon, skip this scan
                }
            }
            last_scan_time_[file_path] = std::chrono::system_clock::now();
        }
        
        return true;
    }

    std::string FileMonitor::calculateFileHash(const std::string& file_path) const {
        // Simple hash based on file path and modification time
        // In production, use actual file content hash (SHA-256)
        try {
            auto last_write = fs::last_write_time(file_path);
            auto epoch = last_write.time_since_epoch().count();
            
            std::stringstream ss;
            ss << file_path << "_" << epoch;
            return ss.str();
        } catch (...) {
            return file_path;
        }
    }

    void FileMonitor::processFileEvent(const std::string& file_path, const std::string& event_type, uint32_t process_id) {
        if (!real_time_protection_ || is_paused_) {
            return;
        }

        // Update statistics
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.total_events++;
        }

        FileEvent event;
        event.file_path = file_path;
        event.event_type = event_type;
        event.file_extension = getFileExtension(file_path);
        event.is_executable = isExecutableFile(file_path);
        event.process_id = process_id;
        
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        char buffer[100];
        std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&time_t));
        event.timestamp = buffer;
        
        try {
            if (fs::exists(file_path)) {
                event.file_size = fs::file_size(file_path);
            } else {
                event.file_size = 0;
            }
        } catch (...) {
            event.file_size = 0;
        }

        // Store in recent events
        {
            std::lock_guard<std::mutex> lock(events_mutex_);
            recent_events_.push_back(event);
            if (recent_events_.size() > 1000) {
                recent_events_.erase(recent_events_.begin());
            }
        }

        // Check if we should scan this file
        if (shouldScanFile(file_path, event_type)) {
            // Add to scan queue
            std::lock_guard<std::mutex> lock(queue_mutex_);
            if (scan_queue_.size() < max_queue_size_) {
                scan_queue_.push(event);
                queue_cv_.notify_one();
                LOG_DEBUG("Queued for scanning: " + file_path);
            } else {
                LOG_WARNING("Scan queue full, dropping event for: " + file_path);
            }
        }

        LOG_DEBUG("File event: " + event_type + " - " + file_path);
    }

    void FileMonitor::scanQueueProcessor() {
        LOG_INFO("Scan queue processor started");
        
        while (is_monitoring_) {
            FileEvent event;
            
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                queue_cv_.wait(lock, [this] { return !scan_queue_.empty() || !is_monitoring_; });
                
                if (!is_monitoring_) {
                    break;
                }
                
                if (scan_queue_.empty()) {
                    continue;
                }
                
                event = scan_queue_.front();
                scan_queue_.pop();
            }
            
            // Process the event (call callback)
            if (file_event_callback_) {
                try {
                    file_event_callback_(event);
                    
                    // Update statistics
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.files_scanned++;
                } catch (const std::exception& e) {
                    LOG_ERROR("Error in file event callback: " + std::string(e.what()));
                }
            }
            
            // Small delay to prevent CPU overload
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        LOG_INFO("Scan queue processor stopped");
    }

    void FileMonitor::statisticsCollector() {
        LOG_INFO("Statistics collector started");
        
        auto last_check = std::chrono::system_clock::now();
        uint64_t last_events = 0;
        
        while (is_monitoring_) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            
            auto now = std::chrono::system_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_check).count();
            
            if (elapsed > 0) {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                
                // Calculate events per second
                uint64_t current_events = stats_.total_events;
                stats_.events_per_second = (current_events - last_events) / elapsed;
                last_events = current_events;
                last_check = now;
                
                // Get memory usage
#ifdef _WIN32
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
                    stats_.memory_usage_mb = pmc.WorkingSetSize / (1024 * 1024);
                }
#endif
            }
        }
        
        LOG_INFO("Statistics collector stopped");
    }

    void FileMonitor::monitoringLoop() {
        LOG_INFO("File monitoring loop started");
        
#ifdef _WIN32
        // Use Windows-specific directory monitoring
        std::vector<std::string> dirs_to_watch;
        {
            std::lock_guard<std::mutex> lock(directories_mutex_);
            dirs_to_watch = watched_directories_;
        }
        
        for (const auto& dir : dirs_to_watch) {
            if (!is_monitoring_) break;
            watchDirectoryWindows(dir);
        }
#else
        // Fallback for non-Windows platforms
        while (is_monitoring_) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
#endif
        
        LOG_INFO("File monitoring loop ended");
    }

#ifdef _WIN32
    void FileMonitor::watchDirectoryWindows(const std::string& directory_path) {
        HANDLE dir_handle = CreateFileA(
            directory_path.c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            NULL
        );

        if (dir_handle == INVALID_HANDLE_VALUE) {
            LOG_ERROR("Failed to open directory for monitoring: " + directory_path);
            return;
        }

        const DWORD buffer_size = 64 * 1024; // 64KB buffer
        char* buffer = new char[buffer_size];
        DWORD bytes_returned;
        OVERLAPPED overlapped = {0};
        overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

        LOG_INFO("Watching directory (Windows): " + directory_path);

        while (is_monitoring_) {
            ResetEvent(overlapped.hEvent);
            
            BOOL success = ReadDirectoryChangesW(
                dir_handle,
                buffer,
                buffer_size,
                TRUE, // Watch subdirectories
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION,
                &bytes_returned,
                &overlapped,
                NULL
            );

            if (!success) {
                LOG_ERROR("ReadDirectoryChangesW failed");
                break;
            }

            // Wait for event with timeout
            DWORD wait_result = WaitForSingleObject(overlapped.hEvent, 1000);
            
            if (wait_result == WAIT_OBJECT_0) {
                if (!GetOverlappedResult(dir_handle, &overlapped, &bytes_returned, FALSE)) {
                    continue;
                }

                FILE_NOTIFY_INFORMATION* info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer);
                
                do {
                    std::wstring wide_filename(info->FileName, info->FileNameLength / sizeof(WCHAR));
                    std::string filename(wide_filename.begin(), wide_filename.end());
                    std::string full_path = directory_path + "\\" + filename;
                    
                    std::string event_type;
                    switch (info->Action) {
                        case FILE_ACTION_ADDED:
                            event_type = "created";
                            break;
                        case FILE_ACTION_REMOVED:
                            event_type = "deleted";
                            break;
                        case FILE_ACTION_MODIFIED:
                            event_type = "modified";
                            break;
                        case FILE_ACTION_RENAMED_OLD_NAME:
                        case FILE_ACTION_RENAMED_NEW_NAME:
                            event_type = "moved";
                            break;
                    }
                    
                    if (!event_type.empty()) {
                        processFileEvent(full_path, event_type, 0);
                    }
                    
                    if (info->NextEntryOffset == 0) break;
                    info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                        reinterpret_cast<char*>(info) + info->NextEntryOffset
                    );
                } while (true);
            }
            
            if (!is_monitoring_) break;
        }

        CloseHandle(overlapped.hEvent);
        CloseHandle(dir_handle);
        delete[] buffer;
        
        LOG_INFO("Stopped watching directory: " + directory_path);
    }

    uint32_t FileMonitor::getProcessIdFromHandle(void* handle) {
        return GetProcessId(static_cast<HANDLE>(handle));
    }
#endif

} // namespace nebula_shield
