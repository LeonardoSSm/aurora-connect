import type { BuildInfo, EngineSnapshot } from "../types/aurora";
import { formatTimeOnlyPtBr } from "../utils/format";

interface SecurityPanelProps {
  snapshot: EngineSnapshot;
  buildInfo: BuildInfo | null;
}

export function SecurityPanel({ snapshot, buildInfo }: SecurityPanelProps) {
  return (
    <section aria-labelledby="security-heading">
      <div className="page-header" style={{ marginBottom: 20 }}>
        <div>
          <span className="eyebrow">
            <span className="eyebrow-dot" aria-hidden="true" />
            Segurança & Telemetria
          </span>
          <h1 id="security-heading" className="page-title">
            Identidade criptográfica e eventos
          </h1>
          <p className="page-subtitle">
            Chave privada protegida pelo cofre de credenciais do sistema operacional;
            transporte autenticado por TLS 1.3 mútuo e fixação de chave pública.
          </p>
        </div>
      </div>

      <div className="columns-2">
        <div className="aurora-card">
          <div className="section-heading">
            <h2>Postura criptográfica</h2>
            {buildInfo && (
              <span className="badge">Protocolo v{buildInfo.protocol_version}</span>
            )}
          </div>

          <div className="device-sub">Impressão digital completa deste dispositivo</div>
          <div
            className="mono"
            style={{
              marginTop: 6,
              padding: "10px 12px",
              borderRadius: 6,
              background: "var(--bg-input)",
              border: "1px solid var(--border-subtle)",
              wordBreak: "break-all",
            }}
          >
            {snapshot.local_device_id_grouped}
          </div>

          <div className="identity-meta" style={{ marginTop: 16 }}>
            <span className="meta-chip">Identidade: Ed25519 (SHA-256 SPKI)</span>
            <span className="meta-chip">Canal: TLS 1.3 mútuo (rustls + ring)</span>
            <span className="meta-chip">Pareamento: SAS 6 dígitos (RFC 8446 §7.5)</span>
            <span className="meta-chip">Escopo: Somente rede local (LAN)</span>
          </div>
        </div>

        <div className="aurora-card">
          <div className="section-heading">
            <h2>Eventos recentes</h2>
            <span className="device-sub">
              {snapshot.recent_notices.length} registro(s)
            </span>
          </div>

          {snapshot.recent_notices.length === 0 ? (
            <div className="empty-state">
              Nenhum evento de segurança ou conectividade registrado nesta execução.
            </div>
          ) : (
            <div className="notice-list">
              {snapshot.recent_notices.map((notice) => (
                <div key={notice.id} className={`notice-item ${notice.level}`}>
                  <span>{notice.message}</span>
                  <span className="mono device-sub">
                    {formatTimeOnlyPtBr(notice.timestamp_ms)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
