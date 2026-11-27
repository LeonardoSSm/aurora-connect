import type { PendingPairingView } from "../types/aurora";

interface PairingModalProps {
  pairing: PendingPairingView;
  busy: boolean;
  onRespond: (pairingId: string, accept: boolean) => void;
}

export function PairingModal({ pairing, busy, onRespond }: PairingModalProps) {
  const isInbound = pairing.direction === "inbound";

  return (
    <div
      className="modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="pairing-modal-title"
    >
      <div className="modal-card">
        <div className="eyebrow">
          <span className="eyebrow-dot" aria-hidden="true" />
          {isInbound
            ? "Solicitação de pareamento recebida"
            : "Confirmação de pareamento enviada"}
        </div>

        <h2 id="pairing-modal-title" className="page-title">
          Verificar identidade de {pairing.peer_name}
        </h2>

        <p className="page-subtitle">
          Confirme se os 6 dígitos abaixo são idênticos nos dois computadores antes
          de autorizar a confiança criptográfica.
        </p>

        <div className="sas-box" aria-live="polite">
          <div className="device-sub" style={{ marginBottom: 6 }}>
            Código de verificação SAS (TLS 1.3 Exporter)
          </div>
          <div className="sas-code" data-testid="pairing-sas-code">
            {pairing.verification_code}
          </div>
        </div>

        <div
          className="device-item"
          style={{ marginBottom: 20, background: "rgba(8, 10, 17, 0.72)" }}
        >
          <div className="device-sub">Impressão digital Ed25519 do par</div>
          <div className="mono" style={{ wordBreak: "break-all" }}>
            {pairing.peer_id_grouped}
          </div>
          {pairing.remote_confirmed && (
            <div className="badge connected" style={{ alignSelf: "flex-start" }}>
              Confirmado pelo dispositivo remoto
            </div>
          )}
        </div>

        {pairing.local_confirmed ? (
          <div className="alert-banner" role="status">
            <span>
              Código confirmado neste computador. Aguardando confirmação em{" "}
              <strong>{pairing.peer_name}</strong>…
            </span>
            <button
              type="button"
              className="btn btn-danger"
              disabled={busy}
              onClick={() => onRespond(pairing.pairing_id, false)}
            >
              Cancelar
            </button>
          </div>
        ) : (
          <div className="btn-row" style={{ justifyContent: "flex-end" }}>
            <button
              type="button"
              className="btn btn-danger"
              disabled={busy}
              onClick={() => onRespond(pairing.pairing_id, false)}
            >
              Recusar
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy}
              onClick={() => onRespond(pairing.pairing_id, true)}
            >
              Os códigos coincidem — Confirmar
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
