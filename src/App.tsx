import { useCallback, useEffect, useState } from "react";
import { PairingModal } from "./components/PairingModal";
import { SecurityPanel } from "./components/SecurityPanel";
import { SettingsPanel } from "./components/SettingsPanel";
import { TopologyWorkspace } from "./components/TopologyWorkspace";
import { tauriAuroraBridge, type AuroraBridge } from "./services/auroraBridge";
import type {
  BuildInfo,
  EngineSnapshot,
  PeerConnectionState,
  SettingsPatch,
} from "./types/aurora";
import {
  classifyLatency,
  formatRtt,
  formatTimestampPtBr,
  validateManualTarget,
} from "./utils/format";

type ActiveTab = "conexoes" | "topologia" | "seguranca" | "configuracoes";

interface AppProps {
  bridge?: AuroraBridge;
}

function stateBadgeLabel(
  state: PeerConnectionState,
  reconnectAttempt: number | null,
): string {
  switch (state) {
    case "connected":
      return "Conectado";
    case "connecting":
      return "Conectando…";
    case "pairing":
      return "Aguardando confirmação";
    case "reconnecting":
      return reconnectAttempt
        ? `Reconectando (${reconnectAttempt}/10)`
        : "Reconectando…";
    case "disconnected":
      return "Desconectado";
  }
}

export function App({ bridge = tauriAuroraBridge }: AppProps) {
  const [snapshot, setSnapshot] = useState<EngineSnapshot | null>(null);
  const [buildInfo, setBuildInfo] = useState<BuildInfo | null>(null);
  const [activeTab, setActiveTab] = useState<ActiveTab>("conexoes");
  const [manualIp, setManualIp] = useState("");
  const [manualPort, setManualPort] = useState("");
  const [uiError, setUiError] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState(false);
  const [confirmRevokeId, setConfirmRevokeId] = useState<string | null>(null);
  const [showFullId, setShowFullId] = useState(false);

  const refreshSnapshot = useCallback(async () => {
    try {
      const snap = await bridge.getSnapshot();
      setSnapshot(snap);
    } catch (err) {
      setUiError(String(err));
    }
  }, [bridge]);

  useEffect(() => {
    let cancelled = false;
    let unlistenFn: (() => void) | undefined;

    void (async () => {
      try {
        const [initialSnap, info] = await Promise.all([
          bridge.getSnapshot(),
          bridge.getBuildInfo(),
        ]);
        if (!cancelled) {
          setSnapshot(initialSnap);
          setBuildInfo(info);
        }
      } catch (err) {
        if (!cancelled) {
          setUiError(String(err));
        }
      }

      try {
        const unlisten = await bridge.onSnapshot((nextSnap) => {
          if (!cancelled) {
            setSnapshot(nextSnap);
          }
        });
        if (cancelled) {
          unlisten();
        } else {
          unlistenFn = unlisten;
        }
      } catch {
        // Fallback outside Tauri runtime (e.g. unit test mocks without event bus)
      }
    })();

    return () => {
      cancelled = true;
      unlistenFn?.();
    };
  }, [bridge]);

  async function runAction(task: () => Promise<void>) {
    setUiError(null);
    setBusyAction(true);
    try {
      await task();
      await refreshSnapshot();
    } catch (err) {
      setUiError(err instanceof Error ? err.message : String(err));
      await refreshSnapshot();
    } finally {
      setBusyAction(false);
    }
  }

  async function handleManualConnect(e: React.FormEvent) {
    e.preventDefault();
    const checked = validateManualTarget(manualIp, manualPort);
    if (!checked.ok) {
      setUiError(checked.error);
      return;
    }

    await runAction(async () => {
      await bridge.connectAddress(checked.ip, checked.port);
      setManualIp("");
      setManualPort("");
    });
  }

  async function handleSaveSettings(patch: SettingsPatch) {
    await runAction(async () => {
      await bridge.updateSettings(patch);
    });
  }

  if (!snapshot) {
    return (
      <main className="workspace" style={{ justifyContent: "center", alignItems: "center" }}>
        <div className="aurora-card" style={{ maxWidth: 440, textAlign: "center" }}>
          <div className="brand-row" style={{ justifyContent: "center", marginBottom: 8 }}>
            <span className="brand-mark">✳</span>
            <span>AURORA CONNECT</span>
          </div>
          {uiError ? (
            <div className="alert-banner error" role="alert" style={{ marginTop: 12 }}>
              <span>{uiError}</span>
            </div>
          ) : (
            <p className="page-subtitle">Inicializando identidade e transporte seguro…</p>
          )}
        </div>
      </main>
    );
  }

  const activePairing = snapshot.pending_pairings[0] ?? null;
  const connectedCount = snapshot.active_sessions.length;

  return (
    <div className="app-shell">
      <aside className="sidebar" aria-label="Navegação principal">
        <div>
          <div className="brand-block">
            <div className="brand-row">
              <span className="brand-mark" aria-hidden="true">
                ✳
              </span>
              <span>AURORA CONNECT</span>
            </div>
            <span className="brand-sub">Dois computadores. Um único controle.</span>
          </div>

          <nav className="nav-list">
            <button
              type="button"
              className={`nav-btn ${activeTab === "conexoes" ? "active" : ""}`}
              onClick={() => setActiveTab("conexoes")}
            >
              <span>Estação & Conexões</span>
              <span
                className={`nav-pill ${connectedCount > 0 ? "connected" : ""}`}
              >
                {connectedCount}
              </span>
            </button>

            <button
              type="button"
              className={`nav-btn ${activeTab === "topologia" ? "active" : ""}`}
              onClick={() => setActiveTab("topologia")}
            >
              <span>Topologia Visual</span>
              <span className="nav-pill">Ciclo 03</span>
            </button>

            <button
              type="button"
              className={`nav-btn ${activeTab === "seguranca" ? "active" : ""}`}
              onClick={() => setActiveTab("seguranca")}
            >
              <span>Segurança & Eventos</span>
              {snapshot.recent_notices.length > 0 && (
                <span className="nav-pill">{snapshot.recent_notices.length}</span>
              )}
            </button>

            <button
              type="button"
              className={`nav-btn ${activeTab === "configuracoes" ? "active" : ""}`}
              onClick={() => setActiveTab("configuracoes")}
            >
              <span>Configurações</span>
            </button>
          </nav>
        </div>

        <div className="sidebar-footer">
          <div className="status-summary">
            <span
              className={`status-dot ${
                connectedCount > 0 ? "connected" : "disconnected"
              }`}
              aria-hidden="true"
            />
            <span>
              {connectedCount > 0
                ? `${connectedCount} sessão(ões) ativa(s)`
                : "Escutando na rede local"}
            </span>
          </div>
          <div>
            Porta {snapshot.listening_port} ·{" "}
            {snapshot.mdns_active ? "mDNS ativo" : "mDNS desativado"}
          </div>
          {buildInfo && (
            <div style={{ marginTop: 4 }}>v{buildInfo.app_version} · Ciclo 01</div>
          )}
        </div>
      </aside>

      <main className="workspace">
        {uiError && (
          <div className="alert-banner error" role="alert">
            <span>{uiError}</span>
            <button
              type="button"
              className="btn"
              onClick={() => setUiError(null)}
            >
              Fechar
            </button>
          </div>
        )}

        {activeTab === "conexoes" && (
          <>
            <header className="page-header">
              <div>
                <span className="eyebrow">
                  <span className="eyebrow-dot" aria-hidden="true" />
                  Ciclo 01 · Fundação e Conectividade
                </span>
                <h1 className="page-title">{snapshot.settings.device_name}</h1>
                <p className="page-subtitle">
                  Comunicação local autenticada por TLS 1.3 mútuo. Nenhum dispositivo é
                  confiado sem confirmação nos dois lados.
                </p>
              </div>
              <button
                type="button"
                className="btn"
                onClick={() => setShowFullId((v) => !v)}
              >
                {showFullId ? "Ocultar impressão digital" : "Ver impressão digital"}
              </button>
            </header>

            <section className="aurora-card identity-banner" aria-label="Identidade local">
              <div>
                <div className="device-sub">Identidade criptográfica deste computador</div>
                <div className="mono" style={{ fontSize: 16, fontWeight: 700, marginTop: 4 }}>
                  {showFullId
                    ? snapshot.local_device_id_grouped
                    : snapshot.local_device_id_short}
                </div>
                <div className="identity-meta">
                  <span className="meta-chip">
                    <span className="status-dot connected" aria-hidden="true" />
                    Porta TCP {snapshot.listening_port}
                  </span>
                  <span className="meta-chip">
                    {snapshot.lan_addresses.length > 0
                      ? `IPs LAN: ${snapshot.lan_addresses.join(", ")}`
                      : "Apenas loopback local detectado"}
                  </span>
                </div>
              </div>

              <form onSubmit={(e) => void handleManualConnect(e)} aria-label="Conexão manual por IP">
                <div className="device-name" style={{ marginBottom: 8 }}>
                  Conexão manual por endereço IP
                </div>
                <div className="form-grid">
                  <div className="field">
                    <label htmlFor="manual-ip-input">Endereço IP da LAN</label>
                    <input
                      id="manual-ip-input"
                      className="input mono"
                      type="text"
                      placeholder="192.168.1.25"
                      value={manualIp}
                      onChange={(e) => setManualIp(e.target.value)}
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="manual-port-input">Porta</label>
                    <input
                      id="manual-port-input"
                      className="input mono"
                      type="text"
                      inputMode="numeric"
                      placeholder={String(snapshot.listening_port)}
                      value={manualPort}
                      onChange={(e) => setManualPort(e.target.value)}
                    />
                  </div>
                  <button
                    type="submit"
                    className="btn btn-primary"
                    disabled={busyAction}
                  >
                    Conectar
                  </button>
                </div>
              </form>
            </section>

            <div className="columns-2">
              {/* Trusted Devices */}
              <section
                className="aurora-card"
                aria-labelledby="trusted-devices-heading"
              >
                <div className="section-heading">
                  <h2 id="trusted-devices-heading">Dispositivos confiáveis</h2>
                  <span className="badge trusted">
                    {snapshot.trusted_devices.length} pareado(s)
                  </span>
                </div>

                {snapshot.trusted_devices.length === 0 ? (
                  <div className="empty-state">
                    Nenhum dispositivo confiável persistido ainda. Conecte-se a uma
                    estação descoberta ao lado ou informe o endereço IP manualmente
                    para iniciar o pareamento.
                  </div>
                ) : (
                  <div className="device-list">
                    {snapshot.trusted_devices.map((dev) => {
                      const rtt =
                        dev.session?.smoothed_rtt_ms ?? dev.session?.last_rtt_ms ?? null;
                      const latencyInfo = classifyLatency(rtt);

                      return (
                        <article key={dev.device_id} className="device-item">
                          <div className="device-top">
                            <div>
                              <div className="device-name">{dev.device_name}</div>
                              <div className="device-sub mono">
                                ID {dev.device_id_short}
                                {dev.last_known_addr ? ` · ${dev.last_known_addr}` : ""}
                              </div>
                            </div>

                            <span
                              className={`badge ${
                                dev.connection_state === "connected"
                                  ? "connected"
                                  : dev.connection_state === "reconnecting"
                                    ? "reconnecting"
                                    : ""
                              }`}
                            >
                              <span
                                className={`status-dot ${dev.connection_state}`}
                                aria-hidden="true"
                              />
                              {stateBadgeLabel(
                                dev.connection_state,
                                dev.reconnect_attempt,
                              )}
                            </span>
                          </div>

                          {dev.session ? (
                            <div
                              className="telemetry-strip"
                              aria-label={`Telemetria de ${dev.device_name}`}
                            >
                              <span>
                                Latência:{" "}
                                <strong
                                  className={`telemetry-value ${latencyInfo.quality}`}
                                >
                                  {formatRtt(dev.session.smoothed_rtt_ms)}
                                </strong>{" "}
                                ({latencyInfo.label})
                              </span>
                              <span>
                                Último ping:{" "}
                                <span className="telemetry-value">
                                  {formatRtt(dev.session.last_rtt_ms)}
                                </span>
                              </span>
                              <span>
                                Direção:{" "}
                                {dev.session.direction === "outbound"
                                  ? "Saída"
                                  : "Entrada"}
                              </span>
                            </div>
                          ) : (
                            <div className="device-sub">
                              Última sessão: {formatTimestampPtBr(dev.last_connected_ms)}
                            </div>
                          )}

                          <div className="btn-row">
                            {dev.connection_state === "connected" ||
                            dev.connection_state === "reconnecting" ? (
                              <button
                                type="button"
                                className="btn"
                                disabled={busyAction}
                                onClick={() =>
                                  void runAction(() =>
                                    bridge.disconnectDevice(dev.device_id),
                                  )
                                }
                              >
                                Desconectar
                              </button>
                            ) : (
                              <button
                                type="button"
                                className="btn btn-primary"
                                disabled={busyAction}
                                onClick={() =>
                                  void runAction(async () => {
                                    await bridge.connectDevice(dev.device_id);
                                  })
                                }
                              >
                                Conectar
                              </button>
                            )}

                            {confirmRevokeId === dev.device_id ? (
                              <>
                                <button
                                  type="button"
                                  className="btn btn-danger"
                                  disabled={busyAction}
                                  onClick={() =>
                                    void runAction(async () => {
                                      setConfirmRevokeId(null);
                                      await bridge.revokeDevice(dev.device_id);
                                    })
                                  }
                                >
                                  Confirmar revogação
                                </button>
                                <button
                                  type="button"
                                  className="btn"
                                  disabled={busyAction}
                                  onClick={() => setConfirmRevokeId(null)}
                                >
                                  Cancelar
                                </button>
                              </>
                            ) : (
                              <button
                                type="button"
                                className="btn btn-danger"
                                disabled={busyAction}
                                onClick={() => setConfirmRevokeId(dev.device_id)}
                              >
                                Revogar confiança
                              </button>
                            )}
                          </div>
                        </article>
                      );
                    })}
                  </div>
                )}
              </section>

              {/* Discovered LAN Devices */}
              <section
                className="aurora-card"
                aria-labelledby="discovered-devices-heading"
              >
                <div className="section-heading">
                  <h2 id="discovered-devices-heading">Descobertos na rede (mDNS)</h2>
                  <span className="badge">
                    {snapshot.discovered_devices.length} visível(is)
                  </span>
                </div>

                {!snapshot.settings.discovery_enabled ? (
                  <div className="empty-state">
                    A descoberta automática por mDNS está desativada nas configurações.
                    Você ainda pode conectar manualmente pelo endereço IP.
                  </div>
                ) : snapshot.discovered_devices.length === 0 ? (
                  <div className="empty-state">
                    Procurando computadores com Aurora Connect na rede local… Caso sua
                    rede Wi-Fi isole clientes, utilize a conexão manual por endereço IP.
                  </div>
                ) : (
                  <div className="device-list">
                    {snapshot.discovered_devices.map((disc) => (
                      <article key={disc.device_id} className="device-item">
                        <div className="device-top">
                          <div>
                            <div className="device-name">{disc.device_name}</div>
                            <div className="device-sub mono">
                              ID {disc.device_id_short} ·{" "}
                              {disc.addresses[0] ?? "sem IP"}:{disc.port}
                            </div>
                          </div>

                          {disc.trusted ? (
                            <span className="badge trusted">Confiável</span>
                          ) : (
                            <span className="badge unverified">
                              Não verificado · mDNS
                            </span>
                          )}
                        </div>

                        <div className="btn-row">
                          {disc.connection_state === "connected" ? (
                            <span className="badge connected">
                              <span
                                className="status-dot connected"
                                aria-hidden="true"
                              />
                              Sessão ativa
                            </span>
                          ) : (
                            <button
                              type="button"
                              className="btn btn-primary"
                              disabled={busyAction}
                              onClick={() =>
                                void runAction(async () => {
                                  await bridge.connectDevice(disc.device_id);
                                })
                              }
                            >
                              {disc.trusted ? "Conectar" : "Parear dispositivo"}
                            </button>
                          )}
                        </div>
                      </article>
                    ))}
                  </div>
                )}
              </section>
            </div>
          </>
        )}

        {activeTab === "topologia" && <TopologyWorkspace snapshot={snapshot} />}

        {activeTab === "seguranca" && (
          <SecurityPanel snapshot={snapshot} buildInfo={buildInfo} />
        )}

        {activeTab === "configuracoes" && (
          <SettingsPanel
            settings={snapshot.settings}
            busy={busyAction}
            onSave={handleSaveSettings}
          />
        )}
      </main>

      {activePairing && (
        <PairingModal
          pairing={activePairing}
          busy={busyAction}
          onRespond={(pairingId, accept) =>
            void runAction(() => bridge.respondPairing(pairingId, accept))
          }
        />
      )}
    </div>
  );
}
