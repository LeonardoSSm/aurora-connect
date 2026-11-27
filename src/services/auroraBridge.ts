import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  BuildInfo,
  ConnectOutcome,
  EngineSnapshot,
  Settings,
  SettingsPatch,
} from "../types/aurora";

export interface AuroraBridge {
  getSnapshot(): Promise<EngineSnapshot>;
  getBuildInfo(): Promise<BuildInfo>;
  connectAddress(address: string, port?: number): Promise<ConnectOutcome>;
  connectDevice(deviceId: string): Promise<ConnectOutcome>;
  respondPairing(pairingId: string, accept: boolean): Promise<void>;
  disconnectDevice(deviceId: string): Promise<void>;
  revokeDevice(deviceId: string): Promise<void>;
  updateSettings(patch: SettingsPatch): Promise<Settings>;
  onSnapshot(handler: (snapshot: EngineSnapshot) => void): Promise<UnlistenFn>;
}

export const tauriAuroraBridge: AuroraBridge = {
  getSnapshot() {
    return invoke<EngineSnapshot>("get_snapshot");
  },
  getBuildInfo() {
    return invoke<BuildInfo>("get_build_info");
  },
  connectAddress(address: string, port?: number) {
    return invoke<ConnectOutcome>("connect_address", {
      address,
      port: port ?? null,
    });
  },
  connectDevice(deviceId: string) {
    return invoke<ConnectOutcome>("connect_device", { deviceId });
  },
  respondPairing(pairingId: string, accept: boolean) {
    return invoke<void>("respond_pairing", { pairingId, accept });
  },
  disconnectDevice(deviceId: string) {
    return invoke<void>("disconnect_device", { deviceId });
  },
  revokeDevice(deviceId: string) {
    return invoke<void>("revoke_device", { deviceId });
  },
  updateSettings(patch: SettingsPatch) {
    return invoke<Settings>("update_settings", { patch });
  },
  onSnapshot(handler: (snapshot: EngineSnapshot) => void) {
    return listen<EngineSnapshot>("aurora://snapshot", (event) => {
      handler(event.payload);
    });
  },
};
