#pragma once

#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <memory>
#include "scanner_engine.h"

namespace nebula_shield {

    struct ApiResponse {
        int status_code;
        std::string content_type;
        std::string body;
        
        ApiResponse(int code = 200, const std::string& type = "application/json", const std::string& data = "")
            : status_code(code), content_type(type), body(data) {}
    };

    class HttpServer {
    public:
        HttpServer(int port = 8080);
        ~HttpServer();

        // Server control
        bool start();
        void stop();
        bool isRunning() const { return is_running_; }

        // Configuration
        void setPort(int port) { port_ = port; }
        int getPort() const { return port_; }
        
        void setCorsEnabled(bool enabled) { cors_enabled_ = enabled; }
        void setAllowedOrigins(const std::string& origins) { allowed_origins_ = origins; }

        // Scanner integration
        void setScannerEngine(std::shared_ptr<ScannerEngine> scanner) { scanner_engine_ = scanner; }
        
        // File monitor integration
        void setFileMonitor(class FileMonitor* monitor) { file_monitor_ = monitor; }

    private:
        // Route handlers
        ApiResponse handleScanFile(const std::string& request_body);
        ApiResponse handleScanDirectory(const std::string& request_body);
        ApiResponse handleQuickScan();
        ApiResponse handleFullScan();
        ApiResponse handleCustomScan(const std::string& request_body);
        ApiResponse handleGetScanResults();
        ApiResponse handleGetSystemStatus();
        ApiResponse handleStartRealTimeProtection();
        ApiResponse handleStopRealTimeProtection();
        ApiResponse handleGetQuarantineList();
        ApiResponse handleRestoreFromQuarantine(const std::string& request_body);
        ApiResponse handleUpdateSignatures();
        ApiResponse handleGetConfiguration();
        ApiResponse handleSetConfiguration(const std::string& request_body);

        // Utility methods
        std::string escapeJsonString(const std::string& str);
        std::string scanResultToJson(const ScanResult& result);
        std::string scanResultsToJson(const std::vector<ScanResult>& results);
        std::string jsonError(const std::string& message, int code = 400);
        std::string jsonSuccess(const std::string& message = "Success");
        
        // CORS handling
        ApiResponse handleOptions();
        void addCorsHeaders(ApiResponse& response);

        // Server implementation
        void serverLoop();
        void handleClient(int client_socket);
        std::string parseHttpRequest(const std::string& request);
        ApiResponse routeRequest(const std::string& method, const std::string& path, const std::string& body);

    private:
        int port_;
        std::atomic<bool> is_running_;
        std::thread server_thread_;
        int server_socket_;
        
        bool cors_enabled_;
        std::string allowed_origins_;
        
        std::shared_ptr<ScannerEngine> scanner_engine_;
        class FileMonitor* file_monitor_;
        std::vector<ScanResult> recent_scan_results_;
    };

} // namespace nebula_shield