use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tempfile::TempDir;

struct NodeProc {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
    pub device_id: String,
    pub port: u16,
}

impl NodeProc {
    fn spawn(data_dir: &Path, name: &str, port: u16, key_hex: Option<&str>) -> Self {
        let bin = env!("CARGO_BIN_EXE_aurora-node");
        let mut cmd = Command::new(bin);
        cmd.arg("--data-dir")
            .arg(data_dir)
            .arg("--name")
            .arg(name)
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--no-mdns")
            .arg("--heartbeat-ms")
            .arg("100")
            .arg("--timeout-ms")
            .arg("450")
            .arg("--reconnect-ms")
            .arg("120")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        if let Some(hex) = key_hex {
            cmd.env("AURORA_NODE_EPHEMERAL_KEY_HEX", hex);
        }

        let mut child = cmd.spawn().expect("falha ao iniciar processo aurora-node");
        let stdin = child.stdin.take().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());

        let mut ready_line = String::new();
        stdout
            .read_line(&mut ready_line)
            .expect("falha ao ler evento ready do aurora-node");
        let ready: Value = serde_json::from_str(&ready_line).expect("JSON ready inválido");
        assert_eq!(ready["event"], "ready");

        let device_id = ready["device_id"].as_str().unwrap().to_string();
        let bound_port = ready["port"].as_u64().unwrap() as u16;

        Self {
            child,
            stdin,
            stdout,
            next_id: 1,
            device_id,
            port: bound_port,
        }
    }

    fn call(&mut self, mut payload: Value) -> Value {
        let req_id = self.next_id;
        self.next_id += 1;
        payload["req_id"] = json!(req_id);
        let line = serde_json::to_string(&payload).unwrap();
        writeln!(self.stdin, "{line}").unwrap();
        self.stdin.flush().unwrap();

        let mut resp_line = String::new();
        self.stdout.read_line(&mut resp_line).unwrap();
        let resp: Value = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(resp["req_id"], req_id);
        resp
    }

    fn snapshot(&mut self) -> Value {
        let r = self.call(json!({ "cmd": "snapshot" }));
        assert_eq!(r["ok"], true);
        r["data"].clone()
    }

    fn export_key_hex(&mut self) -> String {
        let r = self.call(json!({ "cmd": "export_test_key_hex" }));
        assert_eq!(r["ok"], true);
        r["data"].as_str().unwrap().to_string()
    }

    fn shutdown(mut self) {
        let _ = self.call(json!({ "cmd": "shutdown" }));
        let _ = self.child.wait();
    }

    fn kill_abruptly(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_until<F: FnMut() -> bool>(timeout: Duration, mut check: F) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    check()
}

#[test]
fn cross_process_pairing_persistence_revocation_and_crash_detection() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let dir_c = TempDir::new().unwrap();

    let mut node_a = NodeProc::spawn(dir_a.path(), "Estacao Alpha", 0, None);
    let mut node_b = NodeProc::spawn(dir_b.path(), "Estacao Beta", 0, None);

    let key_a = node_a.export_key_hex();
    let key_b = node_b.export_key_hex();
    let id_a = node_a.device_id.clone();
    let id_b = node_b.device_id.clone();
    let port_b = node_b.port;

    // 1. Connect manually by IP between two independent OS processes -> PairingRequired
    let conn_resp = node_a.call(json!({
        "cmd": "connect_address",
        "ip": "127.0.0.1",
        "port": port_b,
    }));
    assert_eq!(conn_resp["ok"], true);
    assert_eq!(conn_resp["data"]["status"], "pairing_required");
    let pair_id_a = conn_resp["data"]["pairing_id"]
        .as_str()
        .unwrap()
        .to_string();

    assert!(wait_until(Duration::from_secs(3), || {
        !node_b.snapshot()["pending_pairings"]
            .as_array()
            .unwrap()
            .is_empty()
    }));

    let snap_a = node_a.snapshot();
    let snap_b = node_b.snapshot();
    let sas_a = snap_a["pending_pairings"][0]["verification_code"]
        .as_str()
        .unwrap();
    let sas_b = snap_b["pending_pairings"][0]["verification_code"]
        .as_str()
        .unwrap();
    assert_eq!(sas_a, sas_b, "SAS entre processos deve ser idêntico");

    let pair_id_b = snap_b["pending_pairings"][0]["pairing_id"]
        .as_str()
        .unwrap()
        .to_string();

    assert_eq!(
        node_a.call(json!({
            "cmd": "respond_pairing",
            "pairing_id": pair_id_a,
            "accept": true
        }))["ok"],
        true
    );
    assert_eq!(
        node_b.call(json!({
            "cmd": "respond_pairing",
            "pairing_id": pair_id_b,
            "accept": true
        }))["ok"],
        true
    );

    // Wait for authenticated session AND real RTT heartbeat across OS processes
    assert!(wait_until(Duration::from_secs(3), || {
        let sa = node_a.snapshot();
        let sessions = sa["active_sessions"].as_array().unwrap();
        sessions.len() == 1 && !sessions[0]["smoothed_rtt_ms"].is_null()
    }));

    // 2. Restart both processes and verify persisted trust allows direct SessionEstablished without re-pairing
    node_a.shutdown();
    node_b.shutdown();

    let mut node_a = NodeProc::spawn(dir_a.path(), "Estacao Alpha", 0, Some(&key_a));
    let mut node_b = NodeProc::spawn(dir_b.path(), "Estacao Beta", port_b, Some(&key_b));
    assert_eq!(node_a.device_id, id_a);
    assert_eq!(node_b.device_id, id_b);

    let recon_resp = node_a.call(json!({
        "cmd": "connect_address",
        "ip": "127.0.0.1",
        "port": node_b.port,
    }));
    assert_eq!(recon_resp["ok"], true);
    assert_eq!(recon_resp["data"]["status"], "session_established");

    // 3. Unauthorized 3rd process C rejected when pairing is disabled on B
    assert_eq!(
        node_b.call(json!({
            "cmd": "update_settings",
            "patch": { "allow_pairing": false }
        }))["ok"],
        true
    );
    let mut node_c = NodeProc::spawn(dir_c.path(), "Intruso C", 0, None);
    let intrude = node_c.call(json!({
        "cmd": "connect_address",
        "ip": "127.0.0.1",
        "port": node_b.port,
    }));
    assert_eq!(intrude["ok"], false);
    node_c.shutdown();

    // 4. Abrupt crash (`kill()`) of Process B -> Process A detects unexpected disconnection and enters Reconnecting!
    node_b.kill_abruptly();

    assert!(
        wait_until(Duration::from_secs(3), || {
            let sa = node_a.snapshot();
            sa["active_sessions"].as_array().unwrap().is_empty()
                && sa["trusted_devices"][0]["connection_state"] == "reconnecting"
        }),
        "processo A deve detectar queda abrupta do processo B e iniciar reconexão"
    );

    // Respawn Process B on the same port -> Process A automatically reconnects with ID pinning!
    let node_b_recovered = NodeProc::spawn(dir_b.path(), "Estacao Beta", port_b, Some(&key_b));
    assert!(
        wait_until(Duration::from_secs(4), || {
            let sa = node_a.snapshot();
            sa["active_sessions"].as_array().unwrap().len() == 1
        }),
        "processo A deve reconectar automaticamente quando processo B retornar"
    );

    node_a.shutdown();
    node_b_recovered.shutdown();
}
