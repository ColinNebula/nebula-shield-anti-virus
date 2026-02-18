#include "scanner_engine.h"
#include <fstream>
#include <filesystem>
#include <chrono>
#include <algorithm>
#include <regex>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib")

namespace nebula_shield {

    ScannerEngine::ScannerEngine() 
        : max_file_size_(100 * 1024 * 1024) // 100MB default
        , timeout_seconds_(30)
        , total_scanned_files_(0)
        , total_threats_found_(0) {
        
        // Default allowed extensions for scanning
        allowed_extensions_ = {
            ".exe", ".dll", ".com", ".scr", ".bat", ".cmd", ".pif",
            ".jar", ".zip", ".rar", ".7z", ".pdf", ".doc", ".docx",
            ".xls", ".xlsx", ".ppt", ".pptx", ".js", ".vbs", ".ps1"
        };
        
        loadSignaturesFromDatabase();
    }

    ScannerEngine::~ScannerEngine() = default;

    ScanResult ScannerEngine::scanFile(const std::string& file_path) {
        ScanResult result;
        result.file_path = file_path;
        
        try {
            if (!std::filesystem::exists(file_path)) {
                result.threat_type = ThreatType::CLEAN;
                return result;
            }

            if (!shouldScanFile(file_path)) {
                result.threat_type = ThreatType::CLEAN;
                return result;
            }

            result = analyzeFile(file_path);
            total_scanned_files_++;
            
            if (result.threat_type != ThreatType::CLEAN) {
                total_threats_found_++;
            }

            if (scan_complete_callback_) {
                scan_complete_callback_(result);
            }

        } catch (const std::exception& e) {
            std::cerr << "Error scanning file " << file_path << ": " << e.what() << std::endl;
            result.threat_type = ThreatType::CLEAN;
        }

        return result;
    }

    std::vector<ScanResult> ScannerEngine::scanDirectory(const std::string& directory_path, bool recursive) {
        std::vector<ScanResult> results;
        
        try {
            if (recursive) {
                for (const auto& entry : std::filesystem::recursive_directory_iterator(directory_path)) {
                    if (entry.is_regular_file() && shouldScanFile(entry.path().string())) {
                        auto result = scanFile(entry.path().string());
                        results.push_back(result);
                    }
                }
            } else {
                for (const auto& entry : std::filesystem::directory_iterator(directory_path)) {
                    if (entry.is_regular_file() && shouldScanFile(entry.path().string())) {
                        auto result = scanFile(entry.path().string());
                        results.push_back(result);
                    }
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Error scanning directory " << directory_path << ": " << e.what() << std::endl;
        }

        return results;
    }

    std::vector<ScanResult> ScannerEngine::scanMultipleFiles(const std::vector<std::string>& file_paths) {
        std::vector<ScanResult> results;
        results.reserve(file_paths.size());

        for (size_t i = 0; i < file_paths.size(); ++i) {
            ScanResult result = scanFile(file_paths[i]);
            results.push_back(result);

            if (progress_callback_) {
                int progress = static_cast<int>(((i + 1) * 100) / file_paths.size());
                progress_callback_(progress);
            }
        }

        return results;
    }

    ScanResult ScannerEngine::analyzeFile(const std::string& file_path) {
        ScanResult result;
        result.file_path = file_path;
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        result.scan_time = std::ctime(&time_t);
        
        // Get file size
        try {
            result.file_size = std::filesystem::file_size(file_path);
        } catch (...) {
            result.file_size = 0;
        }

        // Calculate file hash
        result.hash = calculateFileHash(file_path);
        result.file_hash = result.hash;  // Populate both hash fields

        // Read file data for analysis
        std::vector<uint8_t> file_data = readFileBytes(file_path, max_file_size_);
        
        if (file_data.empty()) {
            result.threat_type = ThreatType::CLEAN;
            return result;
        }

        // Check against known signatures
        for (const auto& signature : signatures_) {
            if (matchesSignature(file_data, signature)) {
                result.threat_type = signature.type;
                result.threat_name = signature.name;
                result.confidence = signature.severity;
                result.confidence_score = signature.severity;
                
                auto end_time = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
                result.scan_duration_ms = duration.count();
                
                return result;
            }
        }

        // Perform heuristic analysis
        double heuristic_score = performHeuristicAnalysis(file_path, file_data);
        
        if (heuristic_score > 0.8) {
            result.threat_type = ThreatType::SUSPICIOUS;
            result.threat_name = "Heuristic Detection";
            result.confidence = heuristic_score;
            result.confidence_score = heuristic_score;
        } else if (heuristic_score > 0.6) {
            result.threat_type = ThreatType::SUSPICIOUS;
            result.threat_name = "Potentially Unwanted Program";
            result.confidence = heuristic_score;
            result.confidence_score = heuristic_score;
        } else {
            result.threat_type = ThreatType::CLEAN;
            result.confidence = 1.0 - heuristic_score;
            result.confidence_score = 1.0 - heuristic_score;
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        result.scan_duration_ms = duration.count();

        return result;
    }

    std::string ScannerEngine::calculateFileHash(const std::string& file_path) {
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            return "";
        }

        // Use Windows Crypto API for SHA-256 hashing
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            return "";
        }
        
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            return "";
        }

        char buffer[8192];
        while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
            if (!CryptHashData(hHash, (BYTE*)buffer, (DWORD)file.gcount(), 0)) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                return "";
            }
        }

        DWORD cbHash = 32; // SHA-256 is 32 bytes
        BYTE hash[32];
        if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &cbHash, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }

        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);

        // Convert to hex string
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (DWORD i = 0; i < cbHash; i++) {
            ss << std::setw(2) << (int)hash[i];
        }

        return ss.str();
    }

    bool ScannerEngine::matchesSignature(const std::vector<uint8_t>& file_data, const ThreatSignature& signature) {
        if (signature.pattern.empty() || file_data.size() < signature.pattern.size()) {
            return false;
        }

        // Simple pattern matching - in a real implementation, you'd want more sophisticated matching
        for (size_t i = 0; i <= file_data.size() - signature.pattern.size(); ++i) {
            if (std::equal(signature.pattern.begin(), signature.pattern.end(), file_data.begin() + i)) {
                return true;
            }
        }

        return false;
    }

    double ScannerEngine::performHeuristicAnalysis(const std::string& file_path, const std::vector<uint8_t>& file_data) {
        double score = 0.0;
        
        // Check for suspicious strings
        if (containsSuspiciousStrings(file_data)) {
            score += 0.3;
        }

        // Check for packer signatures
        if (hasPackerSignature(file_data)) {
            score += 0.4;
        }

        // Check if it's an executable
        if (isFileExecutable(file_path)) {
            score += 0.1;
        }

        // Check file entropy (packed/encrypted files have high entropy)
        // This is a simplified entropy calculation
        std::vector<int> byte_counts(256, 0);
        for (uint8_t byte : file_data) {
            byte_counts[byte]++;
        }

        double entropy = 0.0;
        for (int count : byte_counts) {
            if (count > 0) {
                double probability = static_cast<double>(count) / file_data.size();
                entropy -= probability * log2(probability);
            }
        }

        // High entropy indicates possible packing/encryption
        if (entropy > 7.5) {
            score += 0.2;
        }

        return std::min(score, 1.0);
    }

    bool ScannerEngine::containsSuspiciousStrings(const std::vector<uint8_t>& file_data) {
        std::string file_content(file_data.begin(), file_data.end());
        
        std::vector<std::string> suspicious_strings = {
            "keylogger", "password", "backdoor", "trojan", "virus",
            "inject", "shellcode", "exploit", "rootkit", "stealer"
        };

        for (const auto& suspicious : suspicious_strings) {
            if (file_content.find(suspicious) != std::string::npos) {
                return true;
            }
        }

        return false;
    }

    bool ScannerEngine::hasPackerSignature(const std::vector<uint8_t>& file_data) {
        if (file_data.size() < 64) return false;

        // Check for common packer signatures in the first 64 bytes
        std::vector<std::vector<uint8_t>> packer_signatures = {
            {0x55, 0x50, 0x58}, // UPX
            {0x4D, 0x5A, 0x90}, // Common PE header with potential packing
        };

        for (const auto& signature : packer_signatures) {
            if (std::search(file_data.begin(), file_data.begin() + 64, 
                          signature.begin(), signature.end()) != file_data.begin() + 64) {
                return true;
            }
        }

        return false;
    }

    bool ScannerEngine::isFileExecutable(const std::string& file_path) {
        std::string extension = std::filesystem::path(file_path).extension().string();
        std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
        
        std::vector<std::string> executable_extensions = {
            ".exe", ".dll", ".com", ".scr", ".bat", ".cmd", ".pif"
        };

        return std::find(executable_extensions.begin(), executable_extensions.end(), extension) 
               != executable_extensions.end();
    }

    bool ScannerEngine::shouldScanFile(const std::string& file_path) {
        if (std::filesystem::file_size(file_path) > max_file_size_) {
            return false;
        }

        std::string extension = std::filesystem::path(file_path).extension().string();
        std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

        return std::find(allowed_extensions_.begin(), allowed_extensions_.end(), extension) 
               != allowed_extensions_.end();
    }

    std::vector<uint8_t> ScannerEngine::readFileBytes(const std::string& file_path, size_t max_bytes) {
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            return {};
        }

        file.seekg(0, std::ios::end);
        size_t file_size = file.tellg();
        file.seekg(0, std::ios::beg);

        size_t bytes_to_read = (max_bytes > 0) ? std::min(file_size, max_bytes) : file_size;
        
        std::vector<uint8_t> buffer(bytes_to_read);
        file.read(reinterpret_cast<char*>(buffer.data()), bytes_to_read);

        return buffer;
    }

    bool ScannerEngine::loadSignaturesFromDatabase() {
        // In a real implementation, this would load from a database
        // For now, we'll add some sample signatures
        
        ThreatSignature sample_virus;
        sample_virus.name = "Sample.Virus.A";
        sample_virus.pattern = {0x4D, 0x5A, 0x90, 0x00, 0x03}; // Sample pattern
        sample_virus.type = ThreatType::VIRUS;
        sample_virus.severity = 0.9;
        sample_virus.description = "Sample virus signature";
        
        signatures_.push_back(sample_virus);

        return true;
    }

    bool ScannerEngine::updateSignatures() {
        // Implementation for updating signatures from online database
        return loadSignaturesFromDatabase();
    }

    void ScannerEngine::addCustomSignature(const ThreatSignature& signature) {
        signatures_.push_back(signature);
    }

    void ScannerEngine::setMaxFileSize(size_t max_size) {
        max_file_size_ = max_size;
    }

    void ScannerEngine::setTimeoutSeconds(int timeout) {
        timeout_seconds_ = timeout;
    }

    void ScannerEngine::addFileExtensionFilter(const std::string& extension) {
        std::string ext = extension;
        if (ext[0] != '.') {
            ext = "." + ext;
        }
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        
        if (std::find(allowed_extensions_.begin(), allowed_extensions_.end(), ext) 
            == allowed_extensions_.end()) {
            allowed_extensions_.push_back(ext);
        }
    }

    void ScannerEngine::removeFileExtensionFilter(const std::string& extension) {
        std::string ext = extension;
        if (ext[0] != '.') {
            ext = "." + ext;
        }
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        
        allowed_extensions_.erase(
            std::remove(allowed_extensions_.begin(), allowed_extensions_.end(), ext),
            allowed_extensions_.end()
        );
    }

} // namespace nebula_shield