#include <iostream>
#include <memory>
#include <signal.h>
#include <thread>
#include <chrono>
#include <filesystem>

#include "scanner_engine.h"
#include "http_server.h"
#include "database_manager.h"
#include "config_manager.h"
#include "logger.h"
#include "file_monitor.h"
#include "threat_detector.h"

using namespace nebula_shield;

// Global variables for graceful shutdown
std::unique_ptr<HttpServer> g_server;
std::unique_ptr<FileMonitor> g_file_monitor;
bool g_running = true;

void signalHandler(int signal) {
    std::cout << "\nReceived signal " << signal << ". Shutting down gracefully..." << std::endl;
    
    g_running = false;
    
    if (g_server) {
        g_server->stop();
    }
    
    if (g_file_monitor) {
        g_file_monitor->stopMonitoring();
    }
}

void printBanner() {
    std::cout << R"(
 _   _      _           _         ____  _     _      _     _ 
| \ | | ___| |__  _   _| | __ _  / ___|| |__ (_) ___| | __| |
|  \| |/ _ \ '_ \| | | | |/ _` | \___ \| '_ \| |/ _ \ |/ _` |
| |\  |  __/ |_) | |_| | | (_| |  ___) | | | | |  __/   (_| |
|_| \_|\___|_.__/ \__,_|_|\__,_| |____/|_| |_|_|\___|_|\__,_|

         Anti-Virus Backend Server v1.0.0
    )" << std::endl;
}

int main(int argc, char* argv[]) {
    // Set up signal handlers for graceful shutdown
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    printBanner();

    try {
        // Initialize logger
        Logger& logger = Logger::getInstance();
        logger.setLogLevel(LogLevel::INFO);
        logger.setConsoleLogging(true);
        logger.setFileLogging(true);
        
        LOG_INFO("Starting Nebula Shield Anti-Virus Backend");

        // Load configuration
        ConfigManager config;
        if (!config.loadFromFile("data/config.json")) {
            LOG_WARNING("Could not load configuration file, using defaults");
            config.loadDefaults();
        }

        // Initialize database
        auto database = std::make_shared<DatabaseManager>();
        std::string db_path = config.getString("database.path", "data/nebula_shield.db");
        if (!database->initialize(db_path)) {
            LOG_ERROR("Failed to initialize database");
            return 1;
        }

        // Initialize scanner engine
        auto scanner = std::make_shared<ScannerEngine>();
        scanner->setMaxFileSize(config.getInt("scanner.max_file_size", 104857600));
        scanner->setTimeoutSeconds(config.getInt("scanner.timeout_seconds", 30));
        
        // Set up progress callback
        scanner->setProgressCallback([](int progress) {
            if (progress % 10 == 0) { // Log every 10%
                LOG_DEBUG("Scan progress: " + std::to_string(progress) + "%");
            }
        });

        // Set up scan complete callback to save results to database
        scanner->setScanCompleteCallback([database](const ScanResult& result) {
            if (result.threat_type != ThreatType::CLEAN) {
                database->saveScanResult(result);
                LOG_INFO("Threat detected: " + result.threat_name + " in " + result.file_path);
            }
        });

        // Initialize threat detector
        auto threat_detector = std::make_shared<ThreatDetector>();

        // Initialize file monitor for real-time protection
        g_file_monitor = std::make_unique<FileMonitor>();
        if (config.getBool("protection.real_time_enabled", false)) {
            // Set up file event callback
            g_file_monitor->setFileEventCallback([scanner, threat_detector](const FileEvent& event) {
                if (event.event_type == "created" || event.event_type == "modified") {
                    LOG_DEBUG("Real-time scan triggered: " + event.file_path);
                    
                    // Scan the file
                    ScanResult result = scanner->scanFile(event.file_path);
                    if (result.threat_type != ThreatType::CLEAN) {
                        LOG_WARNING("Real-time threat detected: " + result.threat_name + " in " + event.file_path);
                        
                        // Auto-quarantine if enabled
                        if (threat_detector && result.confidence > 0.8) {
                            threat_detector->quarantineFile(event.file_path);
                        }
                    }
                }
            });

            g_file_monitor->setRealTimeProtection(true);
            
            // Start monitoring common directories
            std::vector<std::string> monitor_dirs = {
                config.getString("protection.downloads_dir", "C:\\Users\\Public\\Downloads"),
                config.getString("protection.temp_dir", "C:\\Windows\\Temp"),
                "C:\\Windows\\System32",           // System files
                "C:\\Windows\\SysWOW64",           // 32-bit system files on 64-bit Windows
                "C:\\Program Files",               // Installed applications
                "C:\\Program Files (x86)",         // 32-bit applications
                "C:\\ProgramData"                  // Application data
            };
            
            for (const auto& dir : monitor_dirs) {
                if (std::filesystem::exists(dir)) {
                    g_file_monitor->startMonitoring(dir);
                }
            }
        }

        // Initialize HTTP server
        g_server = std::make_unique<HttpServer>(config.getInt("server.port", 8080));
        g_server->setScannerEngine(scanner);
        g_server->setFileMonitor(g_file_monitor.get());
        g_server->setCorsEnabled(config.getBool("server.cors_enabled", true));
        g_server->setAllowedOrigins(config.getString("server.allowed_origins", "http://localhost:3000"));

        if (!g_server->start()) {
            LOG_ERROR("Failed to start HTTP server");
            return 1;
        }

        LOG_INFO("Nebula Shield backend started successfully");
        LOG_INFO("HTTP Server listening on port " + std::to_string(g_server->getPort()));
        LOG_INFO("Database: " + db_path);
        LOG_INFO("Real-time protection: " + std::string(config.getBool("protection.real_time_enabled", false) ? "ENABLED" : "DISABLED"));

        // Main loop
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            
            // Perform periodic tasks
            static int counter = 0;
            counter++;
            
            // Update signatures every hour (3600 seconds)
            if (counter % 3600 == 0) {
                LOG_INFO("Performing periodic signature update");
                scanner->updateSignatures();
                threat_detector->updateSignatureDatabase();
            }
            
            // Clean old scan results every day (86400 seconds)
            if (counter % 86400 == 0) {
                LOG_INFO("Cleaning old scan results");
                database->clearOldScanResults(config.getInt("database.cleanup_days", 30));
            }
        }

        LOG_INFO("Shutting down Nebula Shield backend");

    } catch (const std::exception& e) {
        LOG_CRITICAL("Fatal error: " + std::string(e.what()));
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }

    LOG_INFO("Nebula Shield backend stopped");
    return 0;
}