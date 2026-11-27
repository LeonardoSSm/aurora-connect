import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { App } from "./App";
import type { AuroraBridge } from "./services/auroraBridge";
import type { BuildInfo, EngineSnapshot } from "./types/aurora";
import { classifyLatency, formatRtt, validateManualTarget } from "./utils/format";

const LOCAL_ID = "A".repeat(52);
const PEER_ID = "B".repeat(52);

function makeSnapshot(overrides: Partial<EngineSnapshot> = {}): EngineSnapshot {
  return {
    local_device_id: LOCAL_ID,
    local_device_id_short: "AAAA-AAAA",
    local_device_id_grouped: "AAAA-AAAA-AAAA-AAAA",
    settings: {
      device_name: "Desktop Principal",
      listen_port: 47821,
      discovery_enabled: true,
      allow_pairing: true,
      auto_reconnect: true,
    },
    listening_port: 47821,
    lan_addresses: ["192.168.1.10"],
    mdns_active: true,
    discovered_devices: [],
    trusted_devices: [],
    pending_pairings: [],
    active_sessions: [],
    recent_notices: [],
    ...overrides,
  };
}

function makeMockBridge(initial: EngineSnapshot): AuroraBridge & {
  setSnapshotState: (next: EngineSnapshot) => void;
} {
  let current = initial;
  let listener: ((s: EngineSnapshot) => void) | null = null;
  const buildInfo: BuildInfo = {
    app_version: "0.1.0",
    protocol_version: 1,
    platform: "windows",
    cycle: "Ciclo 01 — Fundação e Conectividade",
  };

  return {
    setSnapshotState(next: EngineSnapshot) {
      current = next;
      listener?.(next);
    },
    getSnapshot: vi.fn(async () => current),
    getBuildInfo: vi.fn(async () => buildInfo),
    connectAddress: vi.fn(async () => ({
      status: "pairing_required" as const,
      peer_id: PEER_ID,
      pairing_id: "0123456789abcdef0123456789abcdef",
    })),
    connectDevice: vi.fn(async () => ({
      status: "session_established" as const,
      peer_id: PEER_ID,
      session_id: "fedcba9876543210fedcba9876543210",
    })),
    respondPairing: vi.fn(async () => undefined),
    disconnectDevice: vi.fn(async () => undefined),
    revokeDevice: vi.fn(async () => undefined),
    updateSettings: vi.fn(async (patch) => ({
      ...current.settings,
      ...patch,
    })),
    onSnapshot: vi.fn(async (handler) => {
      listener = handler;
      return () => {
        listener = null;
      };
    }),
  };
}

describe("utilitários de rede e latência", () => {
  it("rejeita IPs públicos, hostnames DNS e portas privilegiadas na conexão manual", () => {
    expect(validateManualTarget("", "")).toMatchObject({ ok: false });
    expect(validateManualTarget("meu-pc.local", "")).toMatchObject({ ok: false });
    expect(validateManualTarget("8.8.8.8", "")).toMatchObject({ ok: false });
    expect(validateManualTarget("192.168.1.25", "80")).toMatchObject({
      ok: false,
    });
    expect(validateManualTarget("192.168.1.25", "70000")).toMatchObject({
      ok: false,
    });
    expect(validateManualTarget("192.168.1.25", "47821")).toEqual({
      ok: true,
      ip: "192.168.1.25",
      port: 47821,
    });
  });

  it("classifica e formata indicadores reais de latência", () => {
    expect(classifyLatency(null).quality).toBe("idle");
    expect(classifyLatency(2.4).quality).toBe("excellent");
    expect(classifyLatency(14.0).quality).toBe("good");
    expect(classifyLatency(42.0).quality).toBe("elevated");
    expect(formatRtt(0.4)).toBe("< 1 ms");
    expect(formatRtt(3.25)).toBe("3,3 ms");
  });
});

describe("interface Aurora Connect (Ciclo 01)", () => {
  it("exibe dispositivos descobertos por mDNS como não verificados sem confiança automática", async () => {
    const snap = makeSnapshot({
      discovered_devices: [
        {
          device_id: PEER_ID,
          device_id_short: "BBBB-BBBB",
          device_id_grouped: "BBBB-BBBB-BBBB-BBBB",
          device_name: "Notebook Aurora",
          addresses: ["192.168.1.44"],
          port: 47821,
          last_seen_ms: Date.now(),
          verified: false,
          trusted: false,
          connection_state: "disconnected",
        },
      ],
    });
    const bridge = makeMockBridge(snap);
    render(<App bridge={bridge} />);

    expect(await screen.findByText("Notebook Aurora")).toBeInTheDocument();
    expect(screen.getByText("Não verificado · mDNS")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Parear dispositivo" }),
    ).toBeInTheDocument();
  });

  it("apresenta modal de pareamento explícito com código SAS de 6 dígitos e envia decisão", async () => {
    const user = userEvent.setup();
    const pairingId = "0123456789abcdef0123456789abcdef";
    const snap = makeSnapshot({
      pending_pairings: [
        {
          pairing_id: pairingId,
          peer_id: PEER_ID,
          peer_id_short: "BBBB-BBBB",
          peer_id_grouped: "BBBB-BBBB-BBBB-BBBB",
          peer_name: "Notebook Estúdio",
          verification_code: "482 917",
          direction: "inbound",
          local_confirmed: false,
          remote_confirmed: false,
          expires_at_ms: Date.now() + 60_000,
        },
      ],
    });
    const bridge = makeMockBridge(snap);
    render(<App bridge={bridge} />);

    expect(await screen.findByTestId("pairing-sas-code")).toHaveTextContent(
      "482 917",
    );

    await user.click(
      screen.getByRole("button", { name: /Os códigos coincidem — Confirmar/i }),
    );
    expect(bridge.respondPairing).toHaveBeenCalledWith(pairingId, true);
  });

  it("exibe latência real em sessão ativa, permite revogação em duas etapas e reserva área de topologia", async () => {
    const user = userEvent.setup();
    const activeSession = {
      session_id: "fedcba9876543210fedcba9876543210",
      peer_id: PEER_ID,
      peer_id_short: "BBBB-BBBB",
      peer_name: "Workstation Secundária",
      remote_addr: "192.168.1.50:47821",
      direction: "outbound" as const,
      connected_at_ms: Date.now() - 5000,
      last_rtt_ms: 1.8,
      smoothed_rtt_ms: 2.1,
    };

    const snap = makeSnapshot({
      active_sessions: [activeSession],
      trusted_devices: [
        {
          device_id: PEER_ID,
          device_id_short: "BBBB-BBBB",
          device_id_grouped: "BBBB-BBBB-BBBB-BBBB",
          device_name: "Workstation Secundária",
          paired_at_ms: Date.now() - 60_000,
          last_connected_ms: Date.now(),
          last_known_addr: "192.168.1.50:47821",
          connection_state: "connected",
          reconnect_attempt: null,
          session: activeSession,
        },
      ],
    });
    const bridge = makeMockBridge(snap);
    render(<App bridge={bridge} />);

    expect(
      await screen.findByText("Workstation Secundária"),
    ).toBeInTheDocument();
    expect(screen.getByText("2,1 ms")).toBeInTheDocument();

    // Two-step revocation safeguard
    await user.click(screen.getByRole("button", { name: "Revogar confiança" }));
    await user.click(
      screen.getByRole("button", { name: "Confirmar revogação" }),
    );
    expect(bridge.revokeDevice).toHaveBeenCalledWith(PEER_ID);

    // Navigate to reserved Cycle 03 topology view
    await user.click(screen.getByRole("button", { name: /Topologia Visual/i }));
    await waitFor(() => {
      expect(screen.getByTestId("topology-stage")).toBeInTheDocument();
    });
    expect(
      screen.getByText(/Organização de computadores e monitores/i),
    ).toBeInTheDocument();
  });

  it("bloqueia IP público no formulário manual e envia IP privado válido ao motor", async () => {
    const user = userEvent.setup();
    const bridge = makeMockBridge(makeSnapshot());
    render(<App bridge={bridge} />);

    const ipInput = await screen.findByLabelText("Endereço IP da LAN");
    await user.type(ipInput, "8.8.8.8");
    await user.click(screen.getByRole("button", { name: "Conectar" }));

    expect(bridge.connectAddress).not.toHaveBeenCalled();
    expect(await screen.findByRole("alert")).toHaveTextContent(/rede local/i);

    await user.clear(ipInput);
    await user.type(ipInput, "192.168.1.77");
    await user.click(screen.getByRole("button", { name: "Conectar" }));
    expect(bridge.connectAddress).toHaveBeenCalledWith(
      "192.168.1.77",
      undefined,
    );
  });
});
