# Ciclo 01 — Fundação Arquitetural e Conectividade Autenticada

> **Dois computadores. Um único controle.**

Este documento consolida o escopo entregue, as decisões técnicas, os critérios de aceitação, as evidências de validação, as limitações conhecidas e o roteiro de validação física em duas máquinas para o **Ciclo 01** do **Aurora Connect**.

---

## 1. Resumo das entregas

| Requisito do Ciclo 01 | Estado | Implementação |
|---|---|---|
| Aplicação desktop funcional (Windows primeiro) | Concluído | `src-tauri/` (Tauri 2) + `src/` (React 19 + TypeScript + Vite) |
| Identidade criptográfica individual por dispositivo | Concluído | Ed25519 (`rcgen`/`ring`), `DeviceId = BASE32(SHA-256(SPKI))`, chave privada somente no cofre de credenciais do SO (`keyring` / Windows Credential Manager) |
| Descoberta na rede local (mDNS) sem confiança automática | Concluído | `_aurora-connect._tcp.local.` (`mdns-sd`), TXT validado, estado fixo `verified = false` |
| Conexão manual por endereço IP | Concluído | Validação de IP literal de escopo local (loopback, RFC 1918, link-local, ULA) e porta `1024..=65535` |
| Pareamento seguro com confirmação explícita mútua | Concluído | Código SAS de 6 dígitos derivado via *TLS 1.3 Keying Material Exporter* (RFC 8446 §7.5), exigindo aprovação nos dois lados |
| Comunicação autenticada e criptografada | Concluído | TCP + TLS 1.3 mútuo (`rustls`), sem 0-RTT, sem tickets de retomada, ALPN `aurora-connect/1` e fixação de chave pública |
| Persistência de dispositivos confiáveis | Concluído | `trusted_devices.json` com escrita atômica e quarentena automática de arquivos corrompidos (*fail-closed*) |
| Revogação de confiança | Concluído | Remoção persistente + envio de `goodbye(revoked)` e bloqueio imediato de novas sessões (`reject(not_trusted)`) |
| Gerenciamento de sessões, heartbeat e desconexão | Concluído | `ping`/`pong` a cada 2 s, timeout de inatividade em 6 s, deduplicação determinística e reconexão com *backoff* exponencial |
| Indicadores reais de conexão e latência | Concluído | Último RTT e média móvel exponencial ($\alpha = 0{,}3$) medidos com relógio monotônico |
| Tratamento de falhas de rede e abuso | Concluído | Limite de frame (64 KiB), sequência estrita anti-replay, *token bucket* (50 frames/s), limites por IP e globais |
| Interface em português brasileiro + identidade Aurora | Concluído | Paleta escura (`#080a11`, violeta/lilás/azul), animações discretas, `prefers-reduced-motion` e rota reservada para Topologia (Ciclo 03) |

---

## 2. Decisões técnicas principais

As decisões arquiteturais completas (ADR-001 a ADR-012) encontram-se em [`architecture.md`](architecture.md), [`protocol.md`](protocol.md), [`security.md`](security.md) e [`threat-model.md`](threat-model.md):

1. **Separação estrita entre núcleo e UI**: `aurora-protocol` e `aurora-core` não dependem do Tauri, permitindo testes determinísticos em memória e testes reais entre processos independentes através do binário auxiliar `aurora-node`.
2. **Validação TLS preservada com *pinning* Ed25519**: em vez de desabilitar verificação TLS, implementamos `PinnedServerVerifier` e `MutualClientVerifier` sobre `rustls`, exigindo TLS 1.3, certificado único X.509 Ed25519 válido, assinatura `CertificateVerify` verificada criptograficamente e correspondência exata do `DeviceId` esperado.
3. **Confiança inicial verificável sem segredo prévio**: o código SAS de 6 dígitos nunca trafega pela rede; cada computador o deriva localmente do segredo mestre da sessão TLS 1.3 (`export_keying_material`) concatenado aos dois `DeviceId`s ordenados.
4. **Privilégio mínimo no Tauri 2**: nenhuma permissão de shell, sistema de arquivos arbitrário ou rede HTTP foi habilitada; apenas `core:event:allow-listen`, `core:event:allow-unlisten` e as 8 permissões geradas para os comandos do aplicativo estão ativas na janela `main`, com `freezePrototype: true` e CSP restritiva.

---

## 3. Evidências de validação automatizada

Todos os testes e verificações abaixo foram executados nativamente em **Windows 11 (`x86_64-pc-windows-msvc`)**:

### Qualidade estática e build
- **Lint TypeScript/React**: `npm run lint` (`eslint . --max-warnings 0`) — aprovado sem erros ou avisos.
- **Typecheck**: `npm run typecheck` (`tsc --noEmit` com `strict: true` e `noUncheckedIndexedAccess: true`) — aprovado.
- **Testes TypeScript (Vitest + Testing Library)**: `npm test` — **6 testes aprovados** cobrindo validação de IP manual (bloqueio de IPs públicos, DNS e portas privilegiadas), formatação de RTT, exibição de descobertos como *não verificados*, modal de confirmação SAS, revogação em duas etapas e área reservada de topologia.
- **Formatação Rust**: `cargo fmt --all -- --check` — aprovado.
- **Análise estática Rust**: `cargo clippy --workspace --all-targets -- -D warnings` — aprovado com zero avisos e `#![forbid(unsafe_code)]` em todos os crates.
- **Build Desktop Windows**: `npx tauri build --bundles nsis` — executável nativo `target/release/aurora-connect.exe` e instalador NSIS `target/release/bundle/nsis/Aurora Connect_0.1.0_x64-setup.exe` (2,04 MiB) gerados com sucesso.

### Cenários funcionais e de segurança validados em Rust (`cargo test --workspace`)
- **Protocolo e framing (`aurora-protocol`)**:
  - Roundtrip de frames válidos e verificação monotônica estrita de `seq` (bloqueio imediato de *replay* `seq=0` e de salto `seq=6`).
  - Rejeição de frames vazios (`0` bytes) e gigantes (`> 64 KiB`) antes de alocar buffer.
  - Rejeição de versões desconhecidas (`UnsupportedVersion`), campos desconhecidos (`deny_unknown_fields`) e strings com caracteres de controle.
- **Segurança, descoberta e sessão (`aurora-core`)**:
  - Identidade Ed25519 persistente no `SecretStore` sem gravar chave privada em disco; quarentena automática (`.corrupt`) e falha fechada para arquivos JSON corrompidos.
  - Política de endereços locais: bloqueio de `0.0.0.0`, broadcast, multicast, CGNAT (`100.64.0.1`), IPs públicos (`8.8.8.8`, `1.1.1.1`, `2001:4860:...`) e IPv4 público mapeado em IPv6 (`::ffff:8.8.8.8`).
  - Descoberta mDNS real entre duas instâncias `Engine`: anúncio localizado com `verified == false`, `trusted == false` e nenhuma sessão automática criada.
  - Pareamento seguro: igualdade do código SAS nos dois lados, bloqueio enquanto apenas um lado confirma, criação de sessão autenticada e medição real de RTT após confirmação mútua, e recusa limpa (`UserRejected`) quando negado.
  - Conexões não autorizadas e impostores: bloqueio de `hello(intent=session)` forjado por par não confiável (`Reject(NotTrusted)`), bloqueio de cliente TLS sem certificado, bloqueio de certificado divergente (`IdentityMismatch`) e bloqueio de autoconexão (`SelfConnection`).
  - Revogação de dispositivos: encerramento imediato da sessão ativa com remoção mútua de confiança.
  - Desconexão inesperada e reconexão automática: queda silenciosa de socket detectada por timeout de heartbeat, transição para `Reconnecting` e retomada automática quando o par retorna com o mesmo `DeviceId`.
  - Resiliência a lixo/limites: tráfego HTTP puro na porta TLS descartado sem falha, encerramento imediato de mensagens fora de fase, limite de 4 conexões por IP e bloqueio de múltiplos pareamentos simultâneos (`Reject(Busy)`).
- **Processos independentes (`aurora-node/tests/cross_process.rs`)**:
  - Dois processos `aurora-node.exe` independentes executam conexão manual por IP, comparam o código SAS, confirmam nos dois processos, medem RTT real via TCP/TLS, reiniciam preservando `trusted_devices.json`, rejeitam um terceiro processo intruso e recuperam automaticamente a sessão após encerramento abrupto (`kill`) de um dos processos.

---

## 4. Limitações conhecidas e riscos residuais

1. **Validação física em um único host de desenvolvimento**: neste ambiente de execução dispomos de apenas um computador físico Windows. Toda a pilha TCP/TLS 1.3, mDNS e persistência foi validada entre processos nativos independentes (`aurora-node.exe`), mas nuances físicas de roteadores Wi-Fi (isolamento de clientes AP, multicast snooping e regras de firewall por perfil Público/Privado do Windows) exigem validação em dois computadores reais seguindo a Seção 5 abaixo.
2. **Firewall do Windows Defender**: ao escutar na porta TCP padrão (`47821`) pela primeira vez, o Windows pode exibir o diálogo padrão de permissão de rede; recomenda-se autorizar apenas para **Redes privadas**. O aplicativo não modifica regras de firewall nem solicita elevação UAC.
3. **Escopo intencional do Ciclo 01**: captura/injeção de mouse e teclado, canvas interativo de monitores, clipboard e transferência de arquivos ainda não estão implementados e só devem iniciar após aprovação deste ciclo.

---

## 5. Roteiro para validação física em dois computadores Windows

Quando dois computadores Windows estiverem conectados à mesma rede local (Ethernet ou Wi-Fi privado sem isolamento de clientes):

1. **Instalação / Execução**:
   - Copie o instalador gerado em `target/release/bundle/nsis/Aurora Connect_0.1.0_x64-setup.exe` (ou execute `target/release/aurora-connect.exe`) nos **Computadores A e B**.
   - Caso o Windows exiba o aviso do Firewall, permita o acesso apenas em **Redes privadas**.
2. **Verificação de descoberta sem confiança automática**:
   - Na aba **Estação & Conexões**, confirme que o Computador B aparece no painel **Descobertos na rede (mDNS)** do Computador A com o selo **Não verificado · mDNS** e que nenhuma sessão é iniciada sozinha.
3. **Pareamento com confirmação explícita**:
   - Clique em **Parear dispositivo** no Computador A (ou informe o IP LAN exibido no topo do Computador B no formulário **Conexão manual por endereço IP**).
   - Compare visualmente os **6 dígitos SAS** exibidos nos modais das duas telas e confira a impressão digital Ed25519.
   - Clique em **Confirmar** apenas em A e verifique que a sessão permanece aguardando; em seguida confirme em B e verifique que ambos passam a **Conectado** com indicadores reais de latência em milissegundos.
4. **Persistência e reconexão**:
   - Feche e reabra o aplicativo nos dois computadores; clique em **Conectar** em **Dispositivos confiáveis** e confirme que a sessão autenticada sobe imediatamente sem novo pareamento.
   - Desconecte temporariamente o cabo/Wi-Fi do Computador B: observe no Computador A a detecção da queda em ~6 s e o estado **Reconectando**, seguido da retomada automática ao reconectar B à rede.
5. **Revogação**:
   - No Computador A, clique em **Revogar confiança → Confirmar revogação**. Verifique que a sessão encerra imediatamente nos dois computadores e que uma nova conexão exige novo pareamento completo.

---

## 6. Critérios de aceitação do Ciclo 01

- [x] Aplicação desktop Tauri 2 funcional compilando nativamente no Windows.
- [x] Identidade criptográfica Ed25519 individual protegida pelo cofre de credenciais do SO.
- [x] Descoberta mDNS sem confiança implícita + conexão manual por IP literal da LAN.
- [x] Pareamento com confirmação explícita nos dois dispositivos via código SAS vinculado ao TLS 1.3.
- [x] Persistência atômica e revogação imediata de dispositivos confiáveis.
- [x] Sessões autenticadas com heartbeat, RTT real, detecção de desconexão e reconexão com *backoff*.
- [x] Limites de recursos, validação estrita de mensagens, anti-replay, política de IPs locais e *capabilities* mínimas.
- [x] Interface em português brasileiro alinhada à identidade visual Aurora e preparada para o canvas de topologia futuro.
- [x] Testes TypeScript, testes Rust, testes entre processos, lint, typecheck, rustfmt, clippy e build desktop aprovados.
