#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>

namespace nebula_shield {

    enum class ThreatType {
        VIRUS,
        TROJAN,
        MALWARE,
        ADWARE,
        SPYWARE,
        ROOTKIT,
        SUSPICIOUS,
        CLEAN
    };

    struct ScanResult {
        std::string file_path;
        ThreatType threat_type;
        std::string threat_name;
        double confidence;
        std::string hash;
        size_t file_size;
        std::string scan_time;
        bool quarantined;

        ScanResult() : threat_type(ThreatType::CLEAN), confidence(0.0), 
                      file_size(0), quarantined(false) {}
    };

    struct ThreatSignature {
        std::string name;
        std::vector<uint8_t> pattern;
        ThreatType type;
        double severity;
        std::string description;
    };

    class ScannerEngine {
    public:
        ScannerEngine();
        ~ScannerEngine();

        // Core scanning functions
        ScanResult scanFile(const std::string& file_path);
        std::vector<ScanResult> scanDirectory(const std::string& directory_path, bool recursive = true);
        std::vector<ScanResult> scanMultipleFiles(const std::vector<std::string>& file_paths);

        // Configuration
        void setMaxFileSize(size_t max_size);
        void setTimeoutSeconds(int timeout);
        void addFileExtensionFilter(const std::string& extension);
        void removeFileExtensionFilter(const std::string& extension);

        // Signature management
        bool loadSignaturesFromDatabase();
        bool updateSignatures();
        void addCustomSignature(const ThreatSignature& signature);

        // Statistics
        size_t getTotalScannedFiles() const { return total_scanned_files_; }
        size_t getTotalThreatsFound() const { return total_threats_found_; }
        
        // Callbacks for progress reporting
        void setProgressCallback(std::function<void(int)> callback) { progress_callback_ = callback; }
        void setScanCompleteCallback(std::function<void(const ScanResult&)> callback) { scan_complete_callback_ = callback; }

    private:
        // Internal scanning methods
        ScanResult analyzeFile(const std::string& file_path);
        bool isFileExecutable(const std::string& file_path);
        std::string calculateFileHash(const std::string& file_path);
        bool matchesSignature(const std::vector<uint8_t>& file_data, const ThreatSignature& signature);
        
        // Heuristic analysis
        double performHeuristicAnalysis(const std::string& file_path, const std::vector<uint8_t>& file_data);
        bool containsSuspiciousStrings(const std::vector<uint8_t>& file_data);
        bool hasPackerSignature(const std::vector<uint8_t>& file_data);
        
        // Utility methods
        bool shouldScanFile(const std::string& file_path);
        std::vector<uint8_t> readFileBytes(const std::string& file_path, size_t max_bytes = 0);

    private:
        std::vector<ThreatSignature> signatures_;
        std::vector<std::string> allowed_extensions_;
        size_t max_file_size_;
        int timeout_seconds_;
        size_t total_scanned_files_;
        size_t total_threats_found_;
        
        std::function<void(int)> progress_callback_;
        std::function<void(const ScanResult&)> scan_complete_callback_;
    };

} // namespace nebula_shield