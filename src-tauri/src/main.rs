// Prevents additional console window on Windows in release mode
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod scanner;
mod quarantine;
mod monitoring;
mod windows_integration;

use tauri::{Manager, WindowEvent};

// Import command modules
use commands::*;
use windows_integration::*;

fn main() {
    env_logger::init();

    tauri::Builder::default()
        .setup(|app| {
            // Initialize background services
            let app_handle = app.app_handle().clone();
            
            // Start real-time protection
            tauri::async_runtime::spawn(async move {
                log::info!("Starting real-time protection service...");
                // Initialize monitoring services here
            });

            Ok(())
        })
        .on_window_event(|window, event| match event {
            WindowEvent::CloseRequested { api, .. } => {
                // Hide to tray instead of closing
                window.hide().unwrap();
                api.prevent_close();
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            // Scanner commands
            scan_file,
            scan_directory,
            quick_scan,
            full_scan,
            get_scan_progress,
            cancel_scan,
            
            // Quarantine commands
            quarantine_file,
            restore_file,
            delete_quarantined_file,
            list_quarantined_files,
            
            // Monitoring commands
            start_realtime_protection,
            stop_realtime_protection,
            get_protection_status,
            get_threat_history,
            
            // System commands
            get_system_info,
            check_for_updates,
            get_signature_version,
            update_signatures,
            
            // Windows-specific commands
            check_windows_defender_status,
            get_firewall_status,
            scan_registry,
            check_startup_programs,
            get_running_processes,
            
            // Settings commands
            get_settings,
            update_settings,
            export_logs,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
