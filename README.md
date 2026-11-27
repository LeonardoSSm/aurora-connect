# Aurora Connect

> **Dois computadores. Um único controle.**

**Estado:** Ciclo 01 concluído (Fundação arquitetural e conectividade autenticada em Windows).

O **Aurora Connect** integra o ecossistema Aurora com o objetivo de permitir que múltiplos computadores compartilhem mouse, teclado, clipboard e arquivos através da rede local — operando de maneira 100% local, sem serviços externos, contas em nuvem, internet ou inteligência artificial.

---

## Escopo do Ciclo 01 (Implementado)

Este ciclo estabelece a fundação de segurança, rede, sessão e interface desktop em Windows:

- **Identidade criptográfica individual**: par de chaves Ed25519 por dispositivo; identificador canônico derivado de `SHA-256(SubjectPublicKeyInfo)` em Base32; chave privada armazenada exclusivamente no cofre de credenciais do sistema operacional (Windows Credential Manager / DPAPI).
- **Transporte autenticado e criptografado**: TCP + **TLS 1.3 mútuo** (`rustls` + `ring`), sem 0-RTT e sem retomada de sessão, com fixação de chave pública (*certificate pinning*).
- **Descoberta na rede local (mDNS)**: anúncio e localização via `_aurora-connect._tcp.local.`. Dispositivos descobertos são sempre exibidos como **não verificados** até o pareamento explícito.
- **Conexão manual por endereço IP**: conexão direta a endereços IPv4/IPv6 da rede local quando mDNS estiver desativado ou bloqueado pela rede.
- **Pareamento seguro com confirmação mútua**: código SAS de 6 dígitos derivado do *TLS 1.3 Keying Material Exporter* (RFC 8446 §7.5), exigindo confirmação explícita do usuário nos dois computadores.
- **Persistência e revogação de confiança**: registro local com escrita atômica (`trusted_devices.json`, apenas metadados públicos) e revogação imediata com encerramento de sessão ativa.
- **Gerenciamento de sessões e telemetria real**: heartbeat bidirecional (`ping`/`pong`), medição real de latência RTT (última amostra e média móvel exponencial), detecção de desconexão inesperada, deduplicação determinística e reconexão automática com *backoff* exponencial.
- **Defesa contra abuso e falhas**: política estrita de endereços locais (bloqueio de IPs públicos), limite de tamanho de frame (64 KiB), numeração de sequência monotônica anti-replay, *token bucket* por conexão, limites de conexões globais/por IP e *capabilities* mínimas no Tauri 2.
- **Interface Aurora em português brasileiro**: tema escuro do ecossistema Aurora, suporte a movimento reduzido (`prefers-reduced-motion`) e área estrutural já preparada para o futuro canvas visual multimonitor (Ciclo 03).

> **Fora do escopo do Ciclo 01:** captura/injeção de mouse e teclado (Ciclo 02), canvas interativo multimonitor (Ciclo 03), clipboard compartilhado (Ciclo 04) e transferência de arquivos (Ciclo 05). Nenhum componente futuro possui implementação fictícia.

---

## Estrutura do projeto

```text
aurora-connect/
├── crates/
│   ├── aurora-protocol/   # Mensagens v1, framing (64 KiB máx.), validação estrita e sequência anti-replay
│   ├── aurora-core/       # Identidade Ed25519, TLS 1.3 mútuo, mDNS, pareamento, sessões, registro e políticas
│   └── aurora-node/       # Nó headless de desenvolvimento para testes entre processos e validação física
├── src-tauri/             # Aplicação desktop Tauri 2, cofre de credenciais do SO e comandos IPC validados
├── src/                   # Interface React 19 + TypeScript + Vite (identidade visual Aurora)
└── docs/                  # Documentação arquitetural, protocolo, segurança, modelo de ameaças e ciclos
```

---

## Documentação técnica

- [`docs/architecture.md`](docs/architecture.md) — Arquitetura em camadas, responsabilidades, concorrência, persistência e ADRs.
- [`docs/protocol.md`](docs/protocol.md) — Especificação do protocolo v1 (mDNS, TLS 1.3, framing, handshake, pareamento e limites).
- [`docs/security.md`](docs/security.md) — Decisões criptográficas, superfície IPC, CSP, logs e controles obrigatórios.
- [`docs/threat-model.md`](docs/threat-model.md) — Modelo de ameaças STRIDE, premissas, mitigações e riscos residuais.
- [`docs/roadmap.md`](docs/roadmap.md) — Roadmap completo (Ciclos 01 a 08).
- [`docs/cycle-01.md`](docs/cycle-01.md) — Registro completo do Ciclo 01: decisões, evidências de validação, limitações e roteiro de validação física em duas máquinas.

---

## Desenvolvimento e validação local

### Pré-requisitos (Windows)

- **Node.js** 20+ e **npm**
- **Rust** (`stable-x86_64-pc-windows-msvc`) com `rustfmt` e `clippy`
- **Visual Studio 2022 Build Tools** (workload *Desenvolvimento para desktop com C++*)
- **Microsoft Edge WebView2 Runtime** (pré-instalado no Windows 11)

### Comandos principais

```powershell
# Instalar dependências do frontend
npm install

# Executar em modo desenvolvimento desktop
npx tauri dev

# Verificações de qualidade e testes TypeScript
npm run lint
npm run typecheck
npm test

# Formatação, análise estática e testes Rust (inclui testes entre processos)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# Gerar build desktop de produção (Windows)
npx tauri build
```

---

## Roadmap resumido

1. **Ciclo 01:** Fundação Windows, pareamento e transporte autenticado *(concluído)*
2. **Ciclo 02:** Mouse e teclado, bordas, recuperação de foco e atalho de emergência
3. **Ciclo 03:** Layout visual multimonitor, DPI, hotplug e perfis
4. **Ciclo 04:** Clipboard texto/imagem e controles de privacidade
5. **Ciclo 05:** Transferência de arquivos/pastas, cancelamento e integridade
6. **Ciclo 06:** Reconexão avançada, testes de carga, auditoria, instalador e autostart
7. **Ciclo 07:** Suporte a Linux e macOS após pesquisa de plataforma
8. **Ciclo 08:** Integração opcional com Aurora Central e Aurora Control

---

## Referências

- [Ecossistema Aurora](https://aurora-ecosystem-sousa.vercel.app)
- [Deskflow](https://github.com/deskflow/deskflow) — referência conceitual de compartilhamento de periféricos
- [Microsoft PowerToys (Mouse Without Borders)](https://github.com/microsoft/PowerToys) — referência de UX em Windows
