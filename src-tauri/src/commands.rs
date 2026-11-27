use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use aurora_core::protocol::{
    validate_session_id, DeviceId, MIN_UNPRIVILEGED_PORT, PROTOCOL_VERSION,
};
use aurora_core::{ConnectOutcome, CoreError, Engine, EngineSnapshot, Settings, SettingsPatch};
use serde::Serialize;
use tauri::State;

pub struct AppState {
    pub engine: Arc<Engine>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuildInfo {
    pub app_version: &'static str,
    pub protocol_version: u16,
    pub platform: &'static str,
    pub cycle: &'static str,
}

fn user_error(err: CoreError) -> String {
    match err {
        CoreError::AddressPolicyViolation => {
            "Endereço recusado: apenas endereços IP da rede local são permitidos.".to_string()
        }
        CoreError::IdentityMismatch => {
            "Identidade criptográfica divergente detectada. A conexão foi bloqueada.".to_string()
        }
        CoreError::SelfConnection => {
            "Não é possível conectar este computador a ele mesmo.".to_string()
        }
        CoreError::Timeout => {
            "Tempo esgotado ao conectar. Verifique o endereço IP, a rede local e o firewall."
                .to_string()
        }
        CoreError::ConnectionLimitExceeded => {
            "Limite máximo de conexões simultâneas atingido.".to_string()
        }
        CoreError::PeerRejected(reason) => {
            format!("Conexão recusada pelo dispositivo remoto ({reason:?}).")
        }
        other => other.to_string(),
    }
}

#[tauri::command]
pub async fn get_snapshot(state: State<'_, AppState>) -> Result<EngineSnapshot, String> {
    Ok(state.engine.snapshot())
}

#[tauri::command]
pub async fn connect_address(
    state: State<'_, AppState>,
    address: String,
    port: Option<u16>,
) -> Result<ConnectOutcome, String> {
    let trimmed = address.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return Err("Informe um endereço IP válido da rede local.".to_string());
    }
    let ip = IpAddr::from_str(trimmed).map_err(|_| {
        "Informe um endereço IP literal válido (ex.: 192.168.1.25). Nomes DNS não são aceitos."
            .to_string()
    })?;
    if let Some(p) = port {
        if p < MIN_UNPRIVILEGED_PORT {
            return Err(format!(
                "A porta deve estar entre {MIN_UNPRIVILEGED_PORT} e 65535."
            ));
        }
    }

    state
        .engine
        .connect_address(ip, port)
        .await
        .map_err(user_error)
}

#[tauri::command]
pub async fn connect_device(
    state: State<'_, AppState>,
    device_id: String,
) -> Result<ConnectOutcome, String> {
    let id = DeviceId::parse_normalized(&device_id)
        .map_err(|_| "Identificador de dispositivo inválido.".to_string())?;
    state.engine.connect_device(id).await.map_err(user_error)
}

#[tauri::command]
pub async fn respond_pairing(
    state: State<'_, AppState>,
    pairing_id: String,
    accept: bool,
) -> Result<(), String> {
    validate_session_id(&pairing_id)
        .map_err(|_| "Identificador de solicitação de pareamento inválido.".to_string())?;
    state
        .engine
        .respond_pairing(&pairing_id, accept)
        .map_err(user_error)
}

#[tauri::command]
pub async fn disconnect_device(
    state: State<'_, AppState>,
    device_id: String,
) -> Result<(), String> {
    let id = DeviceId::parse_normalized(&device_id)
        .map_err(|_| "Identificador de dispositivo inválido.".to_string())?;
    state
        .engine
        .disconnect_device(&id)
        .await
        .map_err(user_error)
}

#[tauri::command]
pub async fn revoke_device(state: State<'_, AppState>, device_id: String) -> Result<(), String> {
    let id = DeviceId::parse_normalized(&device_id)
        .map_err(|_| "Identificador de dispositivo inválido.".to_string())?;
    state.engine.revoke_device(&id).await.map_err(user_error)
}

#[tauri::command]
pub async fn update_settings(
    state: State<'_, AppState>,
    patch: SettingsPatch,
) -> Result<Settings, String> {
    state
        .engine
        .update_settings(patch)
        .await
        .map_err(user_error)
}

#[tauri::command]
pub fn get_build_info() -> BuildInfo {
    BuildInfo {
        app_version: env!("CARGO_PKG_VERSION"),
        protocol_version: PROTOCOL_VERSION,
        platform: std::env::consts::OS,
        cycle: "Ciclo 01 — Fundação e Conectividade",
    }
}
