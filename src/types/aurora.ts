export type PeerConnectionState =
  | "disconnected"
  | "connecting"
  | "pairing"
  | "connected"
  | "reconnecting";

export type ConnectionDirection = "inbound" | "outbound";

export type PairingDirection = "inbound" | "outbound";

export type NoticeLevel = "info" | "success" | "warning" | "error";

export interface Settings {
  device_name: string;
  listen_port: number;
  discovery_enabled: boolean;
  allow_pairing: boolean;
  auto_reconnect: boolean;
}

export interface SettingsPatch {
  device_name?: string;
  listen_port?: number;
  discovery_enabled?: boolean;
  allow_pairing?: boolean;
  auto_reconnect?: boolean;
}

export interface ActiveSessionView {
  session_id: string;
  peer_id: string;
  peer_id_short: string;
  peer_name: string;
  remote_addr: string;
  direction: ConnectionDirection;
  connected_at_ms: number;
  last_rtt_ms: number | null;
  smoothed_rtt_ms: number | null;
}

export interface DiscoveredDeviceView {
  device_id: string;
  device_id_short: string;
  device_id_grouped: string;
  device_name: string;
  addresses: string[];
  port: number;
  last_seen_ms: number;
  verified: boolean;
  trusted: boolean;
  connection_state: PeerConnectionState;
}

export interface TrustedDeviceView {
  device_id: string;
  device_id_short: string;
  device_id_grouped: string;
  device_name: string;
  paired_at_ms: number;
  last_connected_ms: number | null;
  last_known_addr: string | null;
  connection_state: PeerConnectionState;
  reconnect_attempt: number | null;
  session: ActiveSessionView | null;
}

export interface PendingPairingView {
  pairing_id: string;
  peer_id: string;
  peer_id_short: string;
  peer_id_grouped: string;
  peer_name: string;
  verification_code: string;
  direction: PairingDirection;
  local_confirmed: boolean;
  remote_confirmed: boolean;
  expires_at_ms: number;
}

export interface NoticeView {
  id: number;
  timestamp_ms: number;
  level: NoticeLevel;
  message: string;
}

export interface EngineSnapshot {
  local_device_id: string;
  local_device_id_short: string;
  local_device_id_grouped: string;
  settings: Settings;
  listening_port: number;
  lan_addresses: string[];
  mdns_active: boolean;
  discovered_devices: DiscoveredDeviceView[];
  trusted_devices: TrustedDeviceView[];
  pending_pairings: PendingPairingView[];
  active_sessions: ActiveSessionView[];
  recent_notices: NoticeView[];
}

export type ConnectOutcome =
  | { status: "session_established"; peer_id: string; session_id: string }
  | { status: "pairing_required"; peer_id: string; pairing_id: string };

export interface BuildInfo {
  app_version: string;
  protocol_version: number;
  platform: string;
  cycle: string;
}
