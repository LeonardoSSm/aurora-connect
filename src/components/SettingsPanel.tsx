import { useState } from "react";
import type { Settings, SettingsPatch } from "../types/aurora";

interface SettingsPanelProps {
  settings: Settings;
  busy: boolean;
  onSave: (patch: SettingsPatch) => Promise<void>;
}

export function SettingsPanel({ settings, busy, onSave }: SettingsPanelProps) {
  const [deviceName, setDeviceName] = useState(settings.device_name);
  const [listenPort, setListenPort] = useState(String(settings.listen_port));
  const [localError, setLocalError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLocalError(null);

    const trimmed = deviceName.trim();
    if (!trimmed || trimmed.length > 64) {
      setLocalError("O nome do dispositivo deve ter entre 1 e 64 caracteres.");
      return;
    }

    const parsedPort = Number(listenPort.trim());
    if (!Number.isInteger(parsedPort) || parsedPort < 1024 || parsedPort > 65535) {
      setLocalError("A porta TCP deve estar entre 1024 e 65535.");
      return;
    }

    await onSave({
      device_name: trimmed,
      listen_port: parsedPort,
    });
  }

  return (
    <section aria-labelledby="settings-heading">
      <div className="page-header" style={{ marginBottom: 20 }}>
        <div>
          <span className="eyebrow">
            <span className="eyebrow-dot" aria-hidden="true" />
            Preferências Locais
          </span>
          <h1 id="settings-heading" className="page-title">
            Configurações da estação
          </h1>
          <p className="page-subtitle">
            Ajustes persistidos localmente com escrita atômica. Nenhum serviço
            externo ou privilégio administrativo é exigido.
          </p>
        </div>
      </div>

      {localError && (
        <div className="alert-banner error" role="alert" style={{ marginBottom: 16 }}>
          <span>{localError}</span>
        </div>
      )}

      <div className="columns-2">
        <form className="aurora-card" onSubmit={(e) => void handleSubmit(e)}>
          <div className="section-heading">
            <h2>Identificação e porta</h2>
          </div>

          <div className="field" style={{ marginBottom: 14 }}>
            <label htmlFor="setting-device-name">Nome deste computador</label>
            <input
              id="setting-device-name"
              className="input"
              type="text"
              maxLength={64}
              value={deviceName}
              onChange={(e) => setDeviceName(e.target.value)}
            />
          </div>

          <div className="field" style={{ marginBottom: 18 }}>
            <label htmlFor="setting-listen-port">Porta TCP de escuta (TLS 1.3)</label>
            <input
              id="setting-listen-port"
              className="input mono"
              type="text"
              inputMode="numeric"
              value={listenPort}
              onChange={(e) => setListenPort(e.target.value)}
            />
          </div>

          <button type="submit" className="btn btn-primary" disabled={busy}>
            Salvar alterações
          </button>
        </form>

        <div className="aurora-card">
          <div className="section-heading">
            <h2>Políticas de rede e pareamento</h2>
          </div>

          <div className="setting-row">
            <div>
              <div className="device-name">Descoberta na rede local (mDNS)</div>
              <div className="device-sub">
                Anuncia este computador e localiza outras estações na LAN.
              </div>
            </div>
            <button
              type="button"
              className={`btn toggle-btn ${
                settings.discovery_enabled ? "btn-primary" : ""
              }`}
              disabled={busy}
              aria-pressed={settings.discovery_enabled}
              onClick={() =>
                void onSave({ discovery_enabled: !settings.discovery_enabled })
              }
            >
              {settings.discovery_enabled ? "Ativado" : "Desativado"}
            </button>
          </div>

          <div className="setting-row">
            <div>
              <div className="device-name">Aceitar novos pareamentos</div>
              <div className="device-sub">
                Permite receber pedidos de pareamento com confirmação de código.
              </div>
            </div>
            <button
              type="button"
              className={`btn toggle-btn ${
                settings.allow_pairing ? "btn-primary" : ""
              }`}
              disabled={busy}
              aria-pressed={settings.allow_pairing}
              onClick={() =>
                void onSave({ allow_pairing: !settings.allow_pairing })
              }
            >
              {settings.allow_pairing ? "Ativado" : "Bloqueado"}
            </button>
          </div>

          <div className="setting-row">
            <div>
              <div className="device-name">Reconexão automática</div>
              <div className="device-sub">
                Retoma sessões interrompidas com dispositivos já confiáveis.
              </div>
            </div>
            <button
              type="button"
              className={`btn toggle-btn ${
                settings.auto_reconnect ? "btn-primary" : ""
              }`}
              disabled={busy}
              aria-pressed={settings.auto_reconnect}
              onClick={() =>
                void onSave({ auto_reconnect: !settings.auto_reconnect })
              }
            >
              {settings.auto_reconnect ? "Ativado" : "Desativado"}
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}
