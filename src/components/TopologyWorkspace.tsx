import type { EngineSnapshot } from "../types/aurora";
import { formatRtt } from "../utils/format";

interface TopologyWorkspaceProps {
  snapshot: EngineSnapshot;
}

export function TopologyWorkspace({ snapshot }: TopologyWorkspaceProps) {
  return (
    <section aria-labelledby="topology-heading">
      <div className="page-header" style={{ marginBottom: 20 }}>
        <div>
          <span className="eyebrow">
            <span className="eyebrow-dot" aria-hidden="true" />
            Espaço de Topologia
          </span>
          <h1 id="topology-heading" className="page-title">
            Organização de computadores e monitores
          </h1>
          <p className="page-subtitle">
            Estrutura preparada no Ciclo 01 para receber o canvas interativo
            multimonitor, bordas de transição e DPI no Ciclo 03.
          </p>
        </div>
        <span className="badge trusted">Extensão prevista · Ciclo 03</span>
      </div>

      <div className="topology-stage" data-testid="topology-stage">
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: 12,
          }}
        >
          <span className="device-sub">
            Visualização estrutural das sessões autenticadas ativas (somente leitura
            neste ciclo)
          </span>
          <span className="mono" style={{ color: "var(--text-muted)" }}>
            {snapshot.active_sessions.length + 1} estação(ões) na malha local
          </span>
        </div>

        <div className="topology-nodes">
          <div className="topology-node local">
            <div className="badge trusted" style={{ marginBottom: 8 }}>
              Este computador
            </div>
            <div className="device-name">{snapshot.settings.device_name}</div>
            <div className="device-sub mono">{snapshot.local_device_id_short}</div>
            <div className="device-sub" style={{ marginTop: 8 }}>
              Porta {snapshot.listening_port} · TLS 1.3
            </div>
          </div>

          {snapshot.active_sessions.map((session) => (
            <div key={session.session_id} className="topology-node remote">
              <div className="badge connected" style={{ marginBottom: 8 }}>
                <span className="status-dot connected" aria-hidden="true" />
                Sessão autenticada
              </div>
              <div className="device-name">{session.peer_name}</div>
              <div className="device-sub mono">{session.peer_id_short}</div>
              <div className="device-sub" style={{ marginTop: 8 }}>
                RTT: {formatRtt(session.smoothed_rtt_ms ?? session.last_rtt_ms)}
              </div>
            </div>
          ))}
        </div>

        <div className="device-sub" style={{ textAlign: "center" }}>
          Captura/injeção de mouse e teclado (Ciclo 02) e posicionamento visual de
          bordas multimonitor (Ciclo 03) permanecem desativados neste ciclo por
          escopo arquitetural.
        </div>
      </div>
    </section>
  );
}
