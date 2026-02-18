#include <napi.h>
#include "scanner_engine.h"
#include "threat_detector.h"
#include <memory>
#include <string>
#include <vector>

using namespace nebula_shield;

// Global scanner instance
static std::unique_ptr<ScannerEngine> g_scanner;
static std::unique_ptr<ThreatDetector> g_detector;

// Initialize scanner
Napi::Value InitScanner(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    try {
        g_scanner = std::make_unique<ScannerEngine>();
        g_detector = std::make_unique<ThreatDetector>();
        
        Napi::Object result = Napi::Object::New(env);
        result.Set("success", true);
        result.Set("message", "Scanner initialized successfully");
        return result;
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

// Scan a single file
Napi::Value ScanFile(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "String file path expected").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    std::string filePath = info[0].As<Napi::String>().Utf8Value();
    
    try {
        if (!g_scanner) {
            g_scanner = std::make_unique<ScannerEngine>();
        }
        
        ScanResult result = g_scanner->scanFile(filePath);
        
        Napi::Object obj = Napi::Object::New(env);
        obj.Set("file_path", Napi::String::New(env, result.file_path));
        obj.Set("threat_type", Napi::Number::New(env, static_cast<int>(result.threat_type)));
        obj.Set("threat_name", Napi::String::New(env, result.threat_name));
        obj.Set("confidence", Napi::Number::New(env, result.confidence_score));
        obj.Set("scan_duration_ms", Napi::Number::New(env, static_cast<double>(result.scan_duration_ms)));
        obj.Set("file_hash", Napi::String::New(env, result.file_hash.empty() ? result.hash : result.file_hash));
        
        return obj;
    } catch (const std::exception& e) {
        Napi::Error::New(env, std::string("Scan failed: ") + e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

// Scan directory
Napi::Value ScanDirectory(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "String directory path expected").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    std::string dirPath = info[0].As<Napi::String>().Utf8Value();
    bool recursive = true;
    
    if (info.Length() > 1 && info[1].IsBoolean()) {
        recursive = info[1].As<Napi::Boolean>().Value();
    }
    
    try {
        if (!g_scanner) {
            g_scanner = std::make_unique<ScannerEngine>();
        }
        
        std::vector<ScanResult> results = g_scanner->scanDirectory(dirPath, recursive);
        
        Napi::Array resultsArray = Napi::Array::New(env, results.size());
        
        for (size_t i = 0; i < results.size(); ++i) {
            const auto& result = results[i];
            
            Napi::Object obj = Napi::Object::New(env);
            obj.Set("file_path", Napi::String::New(env, result.file_path));
            obj.Set("threat_type", Napi::Number::New(env, static_cast<int>(result.threat_type)));
            obj.Set("threat_name", Napi::String::New(env, result.threat_name));
            obj.Set("confidence", Napi::Number::New(env, result.confidence_score));
            obj.Set("scan_duration_ms", Napi::Number::New(env, static_cast<double>(result.scan_duration_ms)));
            obj.Set("file_hash", Napi::String::New(env, result.file_hash.empty() ? result.hash : result.file_hash));
            
            resultsArray[i] = obj;
        }
        
        return resultsArray;
    } catch (const std::exception& e) {
        Napi::Error::New(env, std::string("Directory scan failed: ") + e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

// Check if file is suspicious
Napi::Value IsSuspicious(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "String file path expected").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    std::string filePath = info[0].As<Napi::String>().Utf8Value();
    
    try {
        if (!g_detector) {
            g_detector = std::make_unique<ThreatDetector>();
        }
        
        bool isSuspicious = g_detector->isSuspiciousExecutable(filePath);
        return Napi::Boolean::New(env, isSuspicious);
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

// Quarantine file
Napi::Value QuarantineFile(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "String file path expected").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    std::string filePath = info[0].As<Napi::String>().Utf8Value();
    
    try {
        if (!g_detector) {
            g_detector = std::make_unique<ThreatDetector>();
        }
        
        bool success = g_detector->quarantineFile(filePath);
        
        Napi::Object result = Napi::Object::New(env);
        result.Set("success", Napi::Boolean::New(env, success));
        result.Set("file_path", Napi::String::New(env, filePath));
        
        return result;
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

// Clean file
Napi::Value CleanFile(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "String file path expected").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    std::string filePath = info[0].As<Napi::String>().Utf8Value();
    
    try {
        if (!g_detector) {
            g_detector = std::make_unique<ThreatDetector>();
        }
        
        bool canRepair = g_detector->canFileBeRepaired(filePath);
        
        if (canRepair) {
            CleaningResult cleanResult = g_detector->cleanFile(filePath);
            
            Napi::Object result = Napi::Object::New(env);
            result.Set("success", Napi::Boolean::New(env, cleanResult.success));
            result.Set("repairable", Napi::Boolean::New(env, true));
            result.Set("message", Napi::String::New(env, cleanResult.message));
            result.Set("signaturesRemoved", Napi::Number::New(env, cleanResult.signaturesRemoved));
            result.Set("backupCreated", Napi::Boolean::New(env, cleanResult.backupCreated));
            result.Set("backupPath", Napi::String::New(env, cleanResult.backupPath));
            
            return result;
        } else {
            Napi::Object result = Napi::Object::New(env);
            result.Set("success", Napi::Boolean::New(env, false));
            result.Set("repairable", Napi::Boolean::New(env, false));
            result.Set("message", Napi::String::New(env, "File cannot be repaired"));
            
            return result;
        }
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

// Get scanner statistics
Napi::Value GetStats(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    try {
        if (!g_scanner) {
            g_scanner = std::make_unique<ScannerEngine>();
        }
        
        Napi::Object stats = Napi::Object::New(env);
        stats.Set("total_scanned", Napi::Number::New(env, g_scanner->getTotalScannedFiles()));
        stats.Set("total_threats", Napi::Number::New(env, g_scanner->getTotalThreatsFound()));
        
        return stats;
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

// Module initialization
Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("initScanner", Napi::Function::New(env, InitScanner));
    exports.Set("scanFile", Napi::Function::New(env, ScanFile));
    exports.Set("scanDirectory", Napi::Function::New(env, ScanDirectory));
    exports.Set("isSuspicious", Napi::Function::New(env, IsSuspicious));
    exports.Set("quarantineFile", Napi::Function::New(env, QuarantineFile));
    exports.Set("cleanFile", Napi::Function::New(env, CleanFile));
    exports.Set("getStats", Napi::Function::New(env, GetStats));
    
    return exports;
}

NODE_API_MODULE(scanner, Init)
