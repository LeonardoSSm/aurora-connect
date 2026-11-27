#![forbid(unsafe_code)]

pub mod commands;
pub mod platform;

use std::sync::Arc;

use aurora_core::protocol::sanitize_device_name;
use aurora_core::{Engine, EngineConfig, EngineEvent, SecretStore};
use commands::AppState;
use platform::OsKeyringSecretStore;
use tauri::{Emitter, Manager, RunEvent};
use tracing::error;

const SNAPSHOT_EVENT: &str = "aurora://snapshot";

fn default_host_display_name() -> String {
    let raw = gethostname::gethostname().to_string_lossy().into_owned();
    sanitize_device_name(&raw).unwrap_or_else(|| "Computador Aurora".to_string())
}

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let app = tauri::Builder::default()
        .setup(|app| {
            let data_dir = app
                .path()
                .app_data_dir()
                .map_err(|e| format!("falha ao resolver diretório de dados do SO: {e}"))?;

            let cfg = EngineConfig::production(
                data_dir,
                default_host_display_name(),
                env!("CARGO_PKG_VERSION").to_string(),
            );
            let secret_store: Arc<dyn SecretStore> = Arc::new(OsKeyringSecretStore::default());

            let engine =
                tauri::async_runtime::block_on(Engine::start(cfg, secret_store)).map_err(|e| {
                    error!("falha crítica ao iniciar Aurora Connect Engine: {e}");
                    format!("Falha ao iniciar o motor de conectividade: {e}")
                })?;

            let app_handle = app.handle().clone();
            let engine_for_events = Arc::clone(&engine);
            let mut rx = engine.subscribe();

            tauri::async_runtime::spawn(async move {
                while let Ok(EngineEvent::SnapshotChanged)
                | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) = rx.recv().await
                {
                    let snap = engine_for_events.snapshot();
                    let _ = app_handle.emit(SNAPSHOT_EVENT, snap);
                }
            });

            app.manage(AppState { engine });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_snapshot,
            commands::connect_address,
            commands::connect_device,
            commands::respond_pairing,
            commands::disconnect_device,
            commands::revoke_device,
            commands::update_settings,
            commands::get_build_info,
        ])
        .build(tauri::generate_context!())
        .expect("erro ao inicializar aplicação Tauri");

    app.run(|app_handle, event| {
        if let RunEvent::Exit = event {
            if let Some(state) = app_handle.try_state::<AppState>() {
                tauri::async_runtime::block_on(state.engine.shutdown());
            }
        }
    });
}
