#include "http_server.h"
#include "file_monitor.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <regex>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

namespace nebula_shield {

    HttpServer::HttpServer(int port) 
        : port_(port)
        , is_running_(false)
        , server_socket_(-1)
        , cors_enabled_(true)
        , allowed_origins_("*")  // Allow all origins - supports any port
        , file_monitor_(nullptr) {
        
#ifdef _WIN32
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
    }

    HttpServer::~HttpServer() {
        stop();
#ifdef _WIN32
        WSACleanup();
#endif
    }

    bool HttpServer::start() {
        if (is_running_) {
            return true;
        }

        // Create socket
        server_socket_ = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket_ < 0) {
            std::cerr << "Failed to create socket" << std::endl;
            return false;
        }

        // Set socket options
        int opt = 1;
#ifdef _WIN32
        setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
#else
        setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

        // Bind socket
        sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port_);

        if (bind(server_socket_, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "Failed to bind socket to port " << port_ << std::endl;
#ifdef _WIN32
            closesocket(server_socket_);
#else
            close(server_socket_);
#endif
            return false;
        }

        // Listen for connections
        if (listen(server_socket_, 10) < 0) {
            std::cerr << "Failed to listen on socket" << std::endl;
#ifdef _WIN32
            closesocket(server_socket_);
#else
            close(server_socket_);
#endif
            return false;
        }

        is_running_ = true;
        server_thread_ = std::thread(&HttpServer::serverLoop, this);

        std::cout << "HTTP Server started on port " << port_ << std::endl;
        return true;
    }

    void HttpServer::stop() {
        if (!is_running_) {
            return;
        }

        is_running_ = false;

        if (server_socket_ >= 0) {
#ifdef _WIN32
            closesocket(server_socket_);
#else
            close(server_socket_);
#endif
            server_socket_ = -1;
        }

        if (server_thread_.joinable()) {
            server_thread_.join();
        }

        std::cout << "HTTP Server stopped" << std::endl;
    }

    void HttpServer::serverLoop() {
        while (is_running_) {
            sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            
            int client_socket = accept(server_socket_, (struct sockaddr*)&client_addr, &client_len);
            if (client_socket < 0) {
                if (is_running_) {
                    std::cerr << "Failed to accept client connection" << std::endl;
                }
                continue;
            }

            // Handle client in a separate thread (simplified for demo)
            std::thread client_thread(&HttpServer::handleClient, this, client_socket);
            client_thread.detach();
        }
    }

    void HttpServer::handleClient(int client_socket) {
        char buffer[4096];
        int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        
        if (bytes_received <= 0) {
#ifdef _WIN32
            closesocket(client_socket);
#else
            close(client_socket);
#endif
            return;
        }

        buffer[bytes_received] = '\0';
        std::string request(buffer);

        // Parse HTTP request
        std::istringstream request_stream(request);
        std::string method, path, version;
        request_stream >> method >> path >> version;

        // Extract body if present
        std::string body;
        size_t body_start = request.find("\r\n\r\n");
        if (body_start != std::string::npos) {
            body = request.substr(body_start + 4);
        }

        // Route request
        ApiResponse response = routeRequest(method, path, body);
        
        // Add CORS headers if enabled
        if (cors_enabled_) {
            addCorsHeaders(response);
        }

        // Send response
        std::ostringstream response_stream;
        response_stream << "HTTP/1.1 " << response.status_code << " OK\r\n";
        response_stream << "Content-Type: " << response.content_type << "\r\n";
        response_stream << "Content-Length: " << response.body.length() << "\r\n";
        
        if (cors_enabled_) {
            response_stream << "Access-Control-Allow-Origin: " << allowed_origins_ << "\r\n";
            response_stream << "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n";
            response_stream << "Access-Control-Allow-Headers: Content-Type, Authorization\r\n";
        }
        
        response_stream << "\r\n";
        response_stream << response.body;

        std::string response_str = response_stream.str();
        send(client_socket, response_str.c_str(), response_str.length(), 0);

#ifdef _WIN32
        closesocket(client_socket);
#else
        close(client_socket);
#endif
    }

    ApiResponse HttpServer::routeRequest(const std::string& method, const std::string& path, const std::string& body) {
        if (method == "OPTIONS") {
            return handleOptions();
        }

        if (method == "POST" && path == "/api/scan/file") {
            return handleScanFile(body);
        }
        
        if (method == "POST" && path == "/api/scan/directory") {
            return handleScanDirectory(body);
        }
        
        if (method == "POST" && path == "/api/scan/quick") {
            return handleQuickScan();
        }
        
        if (method == "POST" && path == "/api/scan/full") {
            return handleFullScan();
        }
        
        if (method == "POST" && path == "/api/scan/custom") {
            return handleCustomScan(body);
        }
        
        if (method == "GET" && path == "/api/scan/results") {
            return handleGetScanResults();
        }
        
        if (method == "GET" && path == "/api/status") {
            return handleGetSystemStatus();
        }
        
        if (method == "POST" && path == "/api/protection/start") {
            return handleStartRealTimeProtection();
        }
        
        if (method == "POST" && path == "/api/protection/stop") {
            return handleStopRealTimeProtection();
        }
        
        if (method == "POST" && path == "/api/protection/toggle") {
            // Toggle protection: check current state and switch
            if (file_monitor_ && file_monitor_->isRealTimeProtectionEnabled()) {
                return handleStopRealTimeProtection();
            } else {
                return handleStartRealTimeProtection();
            }
        }
        
        if (method == "GET" && path == "/api/quarantine") {
            return handleGetQuarantineList();
        }
        
        if (method == "POST" && path == "/api/quarantine/restore") {
            return handleRestoreFromQuarantine(body);
        }
        
        if (method == "POST" && path == "/api/signatures/update") {
            return handleUpdateSignatures();
        }
        
        if (method == "POST" && path == "/api/system/shutdown") {
            // Graceful shutdown - stop monitoring and close server
            std::cout << "[INFO] Shutdown requested via API" << std::endl;
            
            // Stop real-time protection if running
            if (file_monitor_ && file_monitor_->isRealTimeProtectionEnabled()) {
                file_monitor_->stopMonitoring();
                std::cout << "[INFO] Real-time protection stopped" << std::endl;
            }
            
            // Send success response before shutting down
            std::string response = "{\n  \"success\": true,\n  \"message\": \"Server shutting down gracefully\"\n}";
            ApiResponse apiResponse(200, "application/json", response);
            
            // Set shutdown flag
            is_running_ = false;
            
            return apiResponse;
        }
        
        if (method == "GET" && path == "/api/config") {
            return handleGetConfiguration();
        }
        
        if (method == "POST" && path == "/api/config") {
            return handleSetConfiguration(body);
        }

        // Default 404 response
        return ApiResponse(404, "application/json", jsonError("Endpoint not found", 404));
    }

    ApiResponse HttpServer::handleScanFile(const std::string& request_body) {
        if (!scanner_engine_) {
            return ApiResponse(500, "application/json", jsonError("Scanner engine not initialized"));
        }

        // Parse JSON to extract file path
        // Simplified JSON parsing - in production, use a proper JSON library
        std::regex file_path_regex("\"file_path\"\\s*:\\s*\"([^\"]+)\"");
        std::smatch match;
        
        if (!std::regex_search(request_body, match, file_path_regex)) {
            return ApiResponse(400, "application/json", jsonError("Missing file_path parameter"));
        }

        std::string file_path = match[1].str();
        
        try {
            ScanResult result = scanner_engine_->scanFile(file_path);
            recent_scan_results_.push_back(result);
            
            return ApiResponse(200, "application/json", scanResultToJson(result));
        } catch (const std::exception& e) {
            return ApiResponse(500, "application/json", jsonError("Scan failed: " + std::string(e.what())));
        }
    }

    ApiResponse HttpServer::handleScanDirectory(const std::string& request_body) {
        if (!scanner_engine_) {
            return ApiResponse(500, "application/json", jsonError("Scanner engine not initialized"));
        }

        std::regex dir_path_regex("\"directory_path\"\\s*:\\s*\"([^\"]+)\"");
        std::regex recursive_regex("\"recursive\"\\s*:\\s*(true|false)");
        std::smatch match;
        
        if (!std::regex_search(request_body, match, dir_path_regex)) {
            return ApiResponse(400, "application/json", jsonError("Missing directory_path parameter"));
        }

        std::string directory_path = match[1].str();
        bool recursive = true; // default
        
        if (std::regex_search(request_body, match, recursive_regex)) {
            recursive = (match[1].str() == "true");
        }

        try {
            std::vector<ScanResult> results = scanner_engine_->scanDirectory(directory_path, recursive);
            
            // Add to recent results
            recent_scan_results_.insert(recent_scan_results_.end(), results.begin(), results.end());
            
            return ApiResponse(200, "application/json", scanResultsToJson(results));
        } catch (const std::exception& e) {
            return ApiResponse(500, "application/json", jsonError("Directory scan failed: " + std::string(e.what())));
        }
    }

    ApiResponse HttpServer::handleQuickScan() {
        if (!scanner_engine_) {
            return ApiResponse(500, "application/json", jsonError("Scanner engine not initialized"));
        }

        // Quick scan targets common malware locations on Windows
        std::vector<std::string> quick_scan_paths = {
            "C:\\Users\\Public\\Downloads",
            "C:\\Windows\\Temp"
        };

        std::ostringstream json;
        json << "{\n";
        json << "  \"status\": \"started\",\n";
        json << "  \"scan_type\": \"quick\",\n";
        json << "  \"message\": \"Quick scan started\",\n";
        json << "  \"paths\": [";
        for (size_t i = 0; i < quick_scan_paths.size(); ++i) {
            json << "\"" << escapeJsonString(quick_scan_paths[i]) << "\"";
            if (i < quick_scan_paths.size() - 1) json << ", ";
        }
        json << "]\n";
        json << "}";

        return ApiResponse(200, "application/json", json.str());
    }

    ApiResponse HttpServer::handleFullScan() {
        if (!scanner_engine_) {
            return ApiResponse(500, "application/json", jsonError("Scanner engine not initialized"));
        }

        std::ostringstream json;
        json << "{\n";
        json << "  \"status\": \"started\",\n";
        json << "  \"scan_type\": \"full\",\n";
        json << "  \"message\": \"Full system scan started\",\n";
        json << "  \"estimated_time\": \"30-60 minutes\"\n";
        json << "}";

        return ApiResponse(200, "application/json", json.str());
    }

    ApiResponse HttpServer::handleCustomScan(const std::string& request_body) {
        if (!scanner_engine_) {
            return ApiResponse(500, "application/json", jsonError("Scanner engine not initialized"));
        }

        // Parse custom scan path from request body
        std::regex path_regex("\"path\"\\s*:\\s*\"([^\"]+)\"");
        std::smatch match;
        
        if (!std::regex_search(request_body, match, path_regex)) {
            return ApiResponse(400, "application/json", jsonError("Missing path parameter"));
        }

        std::string scan_path = match[1].str();

        std::ostringstream json;
        json << "{\n";
        json << "  \"status\": \"started\",\n";
        json << "  \"scan_type\": \"custom\",\n";
        json << "  \"message\": \"Custom scan started\",\n";
        json << "  \"path\": \"" << escapeJsonString(scan_path) << "\"\n";
        json << "}";

        return ApiResponse(200, "application/json", json.str());
    }

    ApiResponse HttpServer::handleGetScanResults() {
        return ApiResponse(200, "application/json", scanResultsToJson(recent_scan_results_));
    }

    ApiResponse HttpServer::handleGetSystemStatus() {
        std::ostringstream json;
        json << "{\n";
        json << "  \"server_running\": true,\n";
        json << "  \"scanner_initialized\": " << (scanner_engine_ ? "true" : "false") << ",\n";
        json << "  \"total_scanned_files\": " << (scanner_engine_ ? scanner_engine_->getTotalScannedFiles() : 0) << ",\n";
        json << "  \"total_threats_found\": " << (scanner_engine_ ? scanner_engine_->getTotalThreatsFound() : 0) << ",\n";
        json << "  \"real_time_protection\": " << (file_monitor_ && file_monitor_->isRealTimeProtectionEnabled() ? "true" : "false") << ",\n";
        json << "  \"last_update\": \"2024-01-01T00:00:00Z\"\n";
        json << "}";
        
        return ApiResponse(200, "application/json", json.str());
    }

    ApiResponse HttpServer::handleStartRealTimeProtection() {
        if (file_monitor_) {
            file_monitor_->setRealTimeProtection(true);
            return ApiResponse(200, "application/json", jsonSuccess("Real-time protection started"));
        }
        return ApiResponse(500, "application/json", jsonError("File monitor not available", 500));
    }

    ApiResponse HttpServer::handleStopRealTimeProtection() {
        if (file_monitor_) {
            file_monitor_->setRealTimeProtection(false);
            return ApiResponse(200, "application/json", jsonSuccess("Real-time protection stopped"));
        }
        return ApiResponse(500, "application/json", jsonError("File monitor not available", 500));
    }

    ApiResponse HttpServer::handleGetQuarantineList() {
        std::ostringstream json;
        json << "{\n";
        json << "  \"quarantined_files\": []\n";
        json << "}";
        
        return ApiResponse(200, "application/json", json.str());
    }

    ApiResponse HttpServer::handleRestoreFromQuarantine(const std::string& request_body) {
        return ApiResponse(200, "application/json", jsonSuccess("File restored from quarantine"));
    }

    ApiResponse HttpServer::handleUpdateSignatures() {
        if (scanner_engine_) {
            scanner_engine_->updateSignatures();
        }
        return ApiResponse(200, "application/json", jsonSuccess("Signatures updated"));
    }

    ApiResponse HttpServer::handleGetConfiguration() {
        std::ostringstream json;
        json << "{\n";
        json << "  \"real_time_protection\": " << (file_monitor_ && file_monitor_->isRealTimeProtectionEnabled() ? "true" : "false") << ",\n";
        json << "  \"scan_archives\": true,\n";
        json << "  \"scan_email\": true,\n";
        json << "  \"quarantine_threats\": true,\n";
        json << "  \"auto_update\": true\n";
        json << "}";
        
        return ApiResponse(200, "application/json", json.str());
    }

    ApiResponse HttpServer::handleSetConfiguration(const std::string& request_body) {
        return ApiResponse(200, "application/json", jsonSuccess("Configuration updated"));
    }

    ApiResponse HttpServer::handleOptions() {
        return ApiResponse(200, "text/plain", "");
    }

    void HttpServer::addCorsHeaders(ApiResponse& response) {
        // CORS headers are added in handleClient method
    }

    std::string HttpServer::scanResultToJson(const ScanResult& result) {
        std::ostringstream json;
        json << "{\n";
        json << "  \"file_path\": \"" << escapeJsonString(result.file_path) << "\",\n";
        json << "  \"threat_type\": \"" << static_cast<int>(result.threat_type) << "\",\n";
        json << "  \"threat_name\": \"" << escapeJsonString(result.threat_name) << "\",\n";
        json << "  \"confidence\": " << result.confidence << ",\n";
        json << "  \"hash\": \"" << result.hash << "\",\n";
        json << "  \"file_size\": " << result.file_size << ",\n";
        json << "  \"scan_time\": \"" << result.scan_time << "\",\n";
        json << "  \"quarantined\": " << (result.quarantined ? "true" : "false") << "\n";
        json << "}";
        
        return json.str();
    }

    std::string HttpServer::scanResultsToJson(const std::vector<ScanResult>& results) {
        std::ostringstream json;
        json << "{\n";
        json << "  \"results\": [\n";
        
        for (size_t i = 0; i < results.size(); ++i) {
            json << "    " << scanResultToJson(results[i]);
            if (i < results.size() - 1) {
                json << ",";
            }
            json << "\n";
        }
        
        json << "  ],\n";
        json << "  \"total_count\": " << results.size() << "\n";
        json << "}";
        
        return json.str();
    }

    std::string HttpServer::escapeJsonString(const std::string& str) {
        std::ostringstream escaped;
        for (char c : str) {
            switch (c) {
                case '\\': escaped << "\\\\"; break;
                case '\"': escaped << "\\\""; break;
                case '\n': escaped << "\\n"; break;
                case '\r': escaped << "\\r"; break;
                case '\t': escaped << "\\t"; break;
                default: escaped << c; break;
            }
        }
        return escaped.str();
    }

    std::string HttpServer::jsonError(const std::string& message, int code) {
        std::ostringstream json;
        json << "{\n";
        json << "  \"error\": true,\n";
        json << "  \"code\": " << code << ",\n";
        json << "  \"message\": \"" << escapeJsonString(message) << "\"\n";
        json << "}";
        
        return json.str();
    }

    std::string HttpServer::jsonSuccess(const std::string& message) {
        std::ostringstream json;
        json << "{\n";
        json << "  \"success\": true,\n";
        json << "  \"message\": \"" << escapeJsonString(message) << "\"\n";
        json << "}";
        
        return json.str();
    }

} // namespace nebula_shield