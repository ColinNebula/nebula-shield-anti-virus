#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>

namespace nebula_shield {

    class StorageManager;

    // File type enumeration for smart cleaning
    enum class FileType {
        UNKNOWN,
        PE_EXECUTABLE,      // .exe, .dll, .sys
        OFFICE_DOCUMENT,    // .docx, .xlsx, .pptx
        SCRIPT,             // .js, .vbs, .ps1, .bat
        PDF,                // .pdf
        IMAGE,              // .jpg, .png, .gif, .bmp
        TEXT,               // .txt, .ini, .cfg, .json, .xml
        ARCHIVE,            // .zip, .rar, .7z
        MEDIA               // .mp3, .mp4, .avi
    };

    // Cleaning result structure
    struct CleaningResult {
        bool success = false;
        int signaturesRemoved = 0;
        bool backupCreated = false;
        bool fileIntegrityVerified = false;
        std::string message;
        std::string backupPath;
    };

    class ThreatDetector {
    public:
        ThreatDetector();
        ~ThreatDetector();

        // Detection methods
        bool isSuspiciousExecutable(const std::string& file_path);
        bool hasVirusSignature(const std::vector<uint8_t>& file_data);
        double calculateThreatScore(const std::string& file_path, const std::vector<uint8_t>& file_data);
        
        // Behavioral analysis
        bool analyzeProcessBehavior(const std::string& process_name);
        bool detectNetworkAnomalies();
        
        // Signature management
        void loadThreatSignatures();
        void updateSignatureDatabase();
        
        // Quarantine management
        bool quarantineFile(const std::string& file_path);
        bool restoreFromQuarantine(const std::string& file_path);
        std::vector<std::string> getQuarantinedFiles();
        
        // File cleaning - Enhanced
        CleaningResult cleanFile(const std::string& file_path);
        bool cleanFileAdvanced(const std::string& file_path, FileType type);
        bool canFileBeRepaired(const std::string& file_path);
        
        // File type detection
        FileType detectFileType(const std::string& file_path);
        
        // File integrity verification
        bool verifyFileIntegrity(const std::string& file_path, FileType type);
        bool verifyPEStructure(const std::string& file_path);
        bool verifyOfficeDocument(const std::string& file_path);
        bool verifyScriptSyntax(const std::string& file_path);
        
        // Smart byte replacement
        void smartReplaceBytes(std::vector<uint8_t>& data, size_t offset, size_t length, FileType type);

    private:
        // Analysis helpers
        bool containsMaliciousCode(const std::vector<uint8_t>& file_data);
        bool hasPackerIndicators(const std::vector<uint8_t>& file_data);
        bool checkFileEntropy(const std::vector<uint8_t>& file_data);
        
        // File type specific cleaners
        bool cleanExecutable(const std::string& file_path, std::vector<uint8_t>& file_data);
        bool cleanOfficeDocument(const std::string& file_path, std::vector<uint8_t>& file_data);
        bool cleanScript(const std::string& file_path, std::vector<uint8_t>& file_data);
        bool cleanTextFile(const std::string& file_path, std::vector<uint8_t>& file_data);
        bool cleanGeneric(const std::string& file_path, std::vector<uint8_t>& file_data);
        
        // Helper methods
        std::string createBackup(const std::string& file_path);
        bool restoreBackup(const std::string& backup_path, const std::string& original_path);
        int removeVirusSignatures(std::vector<uint8_t>& data, FileType type);
        
        // Registry and system analysis (Windows specific)
#ifdef _WIN32
        bool analyzeRegistryChanges();
        bool checkStartupPrograms();
#endif

    private:
        std::unordered_map<std::string, std::vector<uint8_t>> virus_signatures_;
        std::vector<std::string> suspicious_strings_;
        std::string quarantine_directory_;
        std::unique_ptr<StorageManager> storage_manager_;
        size_t max_quarantine_size_;
    };

} // namespace nebula_shield