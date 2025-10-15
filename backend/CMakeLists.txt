cmake_minimum_required(VERSION 3.16)
project(NebulaShieldBackend VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set build type if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler-specific options
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Include directories
include_directories(include)

# Find packages
find_package(Threads REQUIRED)

# Find SQLite3 (via vcpkg)
find_package(unofficial-sqlite3 CONFIG REQUIRED)

# Find OpenSSL (via vcpkg)
find_package(OpenSSL REQUIRED)

# Add subdirectories
add_subdirectory(src)

# Main executable
add_executable(nebula_shield_backend
    src/main.cpp
    src/scanner_engine.cpp
    src/http_server.cpp
    src/database_manager.cpp
    src/config_manager.cpp
    src/logger.cpp
    src/file_monitor.cpp
    src/threat_detector.cpp
    src/storage_manager.cpp
)

# Link libraries
target_link_libraries(nebula_shield_backend 
    PRIVATE 
    Threads::Threads
    unofficial::sqlite3::sqlite3
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Windows-specific libraries
if(WIN32)
    target_link_libraries(nebula_shield_backend PRIVATE ws2_32 wsock32)
endif()

# Set output directory
set_target_properties(nebula_shield_backend PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Copy configuration files
configure_file(data/config.json ${CMAKE_BINARY_DIR}/bin/config.json COPYONLY)
configure_file(data/signatures.db ${CMAKE_BINARY_DIR}/bin/signatures.db COPYONLY)

# Install targets
install(TARGETS nebula_shield_backend
    RUNTIME DESTINATION bin
)

install(FILES data/config.json data/signatures.db
    DESTINATION bin
)