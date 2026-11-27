fn main() {
    let attributes =
        tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(&[
            "get_snapshot",
            "connect_address",
            "connect_device",
            "respond_pairing",
            "disconnect_device",
            "revoke_device",
            "update_settings",
            "get_build_info",
        ]));
    tauri_build::try_build(attributes).expect("falha ao executar tauri-build");
}
