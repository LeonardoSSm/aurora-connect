use aurora_protocol::{ProtocolError, RejectReason};
use thiserror::Error;

/// Unified error type for `aurora-core`.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("erro de protocolo: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("erro de E/S: {0}")]
    Io(#[from] std::io::Error),

    #[error("erro TLS: {0}")]
    Tls(#[from] rustls::Error),

    #[error("erro criptográfico: {0}")]
    Crypto(String),

    #[error("erro no cofre de credenciais: {0}")]
    SecretStore(String),

    #[error("erro de persistência: {0}")]
    Storage(String),

    #[error("endereço fora da rede local permitida")]
    AddressPolicyViolation,

    #[error("limite de conexões simultâneas atingido")]
    ConnectionLimitExceeded,

    #[error("limite de taxa excedido")]
    RateLimited,

    #[error("conexão encerrada")]
    ConnectionClosed,

    #[error("tempo limite esgotado")]
    Timeout,

    #[error("não é permitido conectar ao próprio dispositivo")]
    SelfConnection,

    #[error("identidade do dispositivo divergente da esperada")]
    IdentityMismatch,

    #[error("conexão recusada pelo dispositivo remoto ({0:?})")]
    PeerRejected(RejectReason),

    #[error("recurso não encontrado: {0}")]
    NotFound(String),

    #[error("entrada inválida: {0}")]
    InvalidInput(String),
}
