#![forbid(unsafe_code)]

use std::env;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aurora_core::protocol::DeviceId;
use aurora_core::{
    Engine, EngineConfig, MemorySecretStore, SecretStore, SettingsPatch, DEFAULT_MDNS_SERVICE_TYPE,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, BufReader};

#[derive(Deserialize)]
struct RpcRequest {
    req_id: u64,
    #[serde(flatten)]
    command: NodeCommand,
}

#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum NodeCommand {
    Snapshot,
    ConnectAddress { ip: IpAddr, port: Option<u16> },
    ConnectDevice { device_id: String },
    RespondPairing { pairing_id: String, accept: bool },
    DisconnectDevice { device_id: String },
    RevokeDevice { device_id: String },
    UpdateSettings { patch: SettingsPatch },
    ExportTestKeyHex,
    Shutdown,
}

#[derive(Serialize)]
struct RpcResponse {
    req_id: u64,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

struct CliArgs {
    data_dir: PathBuf,
    name: String,
    bind_ip: IpAddr,
    port: u16,
    enable_mdns: bool,
    mdns_type: String,
    heartbeat_ms: u64,
    timeout_ms: u64,
    pairing_timeout_ms: u64,
    reconnect_ms: u64,
}

fn parse_args() -> Result<CliArgs, String> {
    let mut data_dir: Option<PathBuf> = None;
    let mut name = "Aurora Node".to_string();
    let mut bind_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut port: u16 = 0;
    let mut enable_mdns = false;
    let mut mdns_type = DEFAULT_MDNS_SERVICE_TYPE.to_string();
    let mut heartbeat_ms: u64 = 2_000;
    let mut timeout_ms: u64 = 6_000;
    let mut pairing_timeout_ms: u64 = 60_000;
    let mut reconnect_ms: u64 = 1_000;

    let mut iter = env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--data-dir" => {
                data_dir = Some(PathBuf::from(
                    iter.next().ok_or("valor ausente para --data-dir")?,
                ));
            }
            "--name" => {
                name = iter.next().ok_or("valor ausente para --name")?;
            }
            "--bind" => {
                bind_ip = iter
                    .next()
                    .ok_or("valor ausente para --bind")?
                    .parse()
                    .map_err(|e| format!("IP inválido em --bind: {e}"))?;
            }
            "--port" => {
                port = iter
                    .next()
                    .ok_or("valor ausente para --port")?
                    .parse()
                    .map_err(|e| format!("porta inválida em --port: {e}"))?;
            }
            "--mdns" => {
                enable_mdns = true;
            }
            "--no-mdns" => {
                enable_mdns = false;
            }
            "--mdns-type" => {
                mdns_type = iter.next().ok_or("valor ausente para --mdns-type")?;
            }
            "--heartbeat-ms" => {
                heartbeat_ms = iter
                    .next()
                    .ok_or("valor ausente para --heartbeat-ms")?
                    .parse()
                    .map_err(|e| format!("valor inválido em --heartbeat-ms: {e}"))?;
            }
            "--timeout-ms" => {
                timeout_ms = iter
                    .next()
                    .ok_or("valor ausente para --timeout-ms")?
                    .parse()
                    .map_err(|e| format!("valor inválido em --timeout-ms: {e}"))?;
            }
            "--pairing-timeout-ms" => {
                pairing_timeout_ms = iter
                    .next()
                    .ok_or("valor ausente para --pairing-timeout-ms")?
                    .parse()
                    .map_err(|e| format!("valor inválido em --pairing-timeout-ms: {e}"))?;
            }
            "--reconnect-ms" => {
                reconnect_ms = iter
                    .next()
                    .ok_or("valor ausente para --reconnect-ms")?
                    .parse()
                    .map_err(|e| format!("valor inválido em --reconnect-ms: {e}"))?;
            }
            other => return Err(format!("argumento desconhecido: {other}")),
        }
    }

    let data_dir = data_dir.ok_or("--data-dir é obrigatório")?;
    Ok(CliArgs {
        data_dir,
        name,
        bind_ip,
        port,
        enable_mdns,
        mdns_type,
        heartbeat_ms,
        timeout_ms,
        pairing_timeout_ms,
        reconnect_ms,
    })
}

fn write_json_line<T: Serialize>(value: &T) {
    if let Ok(line) = serde_json::to_string(value) {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{line}");
        let _ = out.flush();
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("erro: {msg}");
            std::process::exit(2);
        }
    };

    let mem_store = Arc::new(MemorySecretStore::new());
    if let Ok(hex_key) = env::var("AURORA_NODE_EPHEMERAL_KEY_HEX") {
        let mut bytes = Vec::with_capacity(hex_key.len() / 2);
        let mut valid = hex_key.len() % 2 == 0;
        if valid {
            for chunk in hex_key.as_bytes().chunks(2) {
                if let Ok(s) = std::str::from_utf8(chunk) {
                    if let Ok(b) = u8::from_str_radix(s, 16) {
                        bytes.push(b);
                        continue;
                    }
                }
                valid = false;
                break;
            }
        }
        if !valid || mem_store.store_identity_key(&bytes).is_err() {
            eprintln!("erro: AURORA_NODE_EPHEMERAL_KEY_HEX inválido");
            std::process::exit(2);
        }
    }

    let mut cfg = EngineConfig::production(
        args.data_dir.clone(),
        args.name.clone(),
        env!("CARGO_PKG_VERSION").to_string(),
    );
    cfg.bind_ip = args.bind_ip;
    cfg.allow_ephemeral_port = true;
    cfg.enable_mdns = args.enable_mdns;
    cfg.mdns_service_type = args.mdns_type;
    cfg.heartbeat_interval = Duration::from_millis(args.heartbeat_ms);
    cfg.session_timeout = Duration::from_millis(args.timeout_ms);
    cfg.pairing_timeout = Duration::from_millis(args.pairing_timeout_ms);
    cfg.reconnect_base_unit = Duration::from_millis(args.reconnect_ms);

    // Pre-seed desired port into settings if settings.json does not yet exist.
    let settings_store = aurora_core::SettingsStore::new(&args.data_dir, true);
    if let Ok(mut initial) = settings_store.load_or_init(&args.name) {
        let should_override = (initial.listen_port != args.port && args.port != 0)
            || !args.data_dir.join("settings.json").exists()
            || (initial.listen_port == 47_821 && args.port == 0);
        if should_override {
            initial.listen_port = args.port;
            let _ = settings_store.save(&initial);
        }
    }

    let secret_trait: Arc<dyn SecretStore> = Arc::clone(&mem_store) as Arc<dyn SecretStore>;
    let engine = match Engine::start(cfg, secret_trait).await {
        Ok(e) => e,
        Err(err) => {
            eprintln!("falha ao iniciar engine: {err}");
            std::process::exit(1);
        }
    };

    write_json_line(&serde_json::json!({
        "event": "ready",
        "device_id": engine.local_device_id().as_str(),
        "port": engine.listening_port(),
    }));

    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let parsed: RpcRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(err) => {
                write_json_line(&RpcResponse {
                    req_id: 0,
                    ok: false,
                    data: None,
                    error: Some(format!("JSON inválido: {err}")),
                });
                continue;
            }
        };

        let req_id = parsed.req_id;
        let should_exit = matches!(parsed.command, NodeCommand::Shutdown);
        let outcome = handle_command(&engine, &mem_store, parsed.command).await;
        match outcome {
            Ok(val) => write_json_line(&RpcResponse {
                req_id,
                ok: true,
                data: Some(val),
                error: None,
            }),
            Err(err) => write_json_line(&RpcResponse {
                req_id,
                ok: false,
                data: None,
                error: Some(err),
            }),
        }

        if should_exit {
            break;
        }
    }

    engine.shutdown().await;
}

async fn handle_command(
    engine: &Arc<Engine>,
    mem_store: &Arc<MemorySecretStore>,
    cmd: NodeCommand,
) -> Result<Value, String> {
    match cmd {
        NodeCommand::Snapshot => serde_json::to_value(engine.snapshot()).map_err(|e| e.to_string()),
        NodeCommand::ConnectAddress { ip, port } => {
            let res = engine
                .connect_address(ip, port)
                .await
                .map_err(|e| e.to_string())?;
            serde_json::to_value(res).map_err(|e| e.to_string())
        }
        NodeCommand::ConnectDevice { device_id } => {
            let id = DeviceId::parse_normalized(&device_id).map_err(|e| e.to_string())?;
            let res = engine.connect_device(id).await.map_err(|e| e.to_string())?;
            serde_json::to_value(res).map_err(|e| e.to_string())
        }
        NodeCommand::RespondPairing { pairing_id, accept } => {
            engine
                .respond_pairing(&pairing_id, accept)
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        NodeCommand::DisconnectDevice { device_id } => {
            let id = DeviceId::parse_normalized(&device_id).map_err(|e| e.to_string())?;
            engine
                .disconnect_device(&id)
                .await
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        NodeCommand::RevokeDevice { device_id } => {
            let id = DeviceId::parse_normalized(&device_id).map_err(|e| e.to_string())?;
            engine.revoke_device(&id).await.map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        NodeCommand::UpdateSettings { patch } => {
            let updated = engine
                .update_settings(patch)
                .await
                .map_err(|e| e.to_string())?;
            serde_json::to_value(updated).map_err(|e| e.to_string())
        }
        NodeCommand::ExportTestKeyHex => {
            let key = mem_store
                .load_identity_key()
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "chave ausente".to_string())?;
            let mut hex_out = String::with_capacity(key.len() * 2);
            for b in key.iter() {
                use std::fmt::Write as _;
                let _ = write!(&mut hex_out, "{b:02x}");
            }
            Ok(Value::String(hex_out))
        }
        NodeCommand::Shutdown => {
            engine.shutdown().await;
            Ok(Value::Null)
        }
    }
}
