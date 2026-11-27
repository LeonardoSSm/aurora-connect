# Segurança — Aurora Connect

Este documento descreve os controles de segurança do Ciclo 01 e as decisões criptográficas.
O modelo de ameaças está em [`threat-model.md`](threat-model.md).

> **Nenhum algoritmo criptográfico próprio é usado.** Todas as primitivas vêm de bibliotecas
> amplamente auditadas (`rustls`, `ring`, `rcgen`, `sha2`) e de padrões IETF.

## 1. Decisões criptográficas

| Item | Escolha | Referência |
|---|---|---|
| Protocolo de canal | TLS 1.3 somente (rustls 0.23, provider `ring`) | RFC 8446 |
| Suítes | Padrão do rustls para TLS 1.3: `TLS13_AES_256_GCM_SHA384`, `TLS13_AES_128_GCM_SHA256`, `TLS13_CHACHA20_POLY1305_SHA256` | RFC 8446 §9.1 |
| Troca de chaves | X25519 / ECDHE (padrão do provider) — sigilo futuro (*forward secrecy*) | RFC 7748 |
| Assinatura / identidade | Ed25519 | RFC 8032, RFC 8410 |
| ID do dispositivo | SHA-256 do SubjectPublicKeyInfo, codificado em base32 | FIPS 180-4, RFC 4648 |
| Código de pareamento | TLS Exporter (8 bytes) → 6 dígitos decimais | RFC 8446 §7.5, RFC 5705 |
| Aleatoriedade | `getrandom` (CSPRNG do SO) via `rand`/`ring` | — |
| 0-RTT / retomada | Desabilitados | Evita replay de early data e simplifica autenticação |

### Por que certificados autoassinados com *pinning*

Não existe uma autoridade certificadora em comum entre computadores domésticos. O Aurora Connect
usa o modelo de confiança em primeiro uso **com verificação humana** (semelhante a SSH/Syncthing,
mas com comparação obrigatória de código):

- A chave pública de cada dispositivo é sua identidade; o ID é o hash dessa chave.
- **A validação TLS não é desabilitada**: o rustls executa todo o handshake, e nossos
  verificadores (`PeerCertVerifier`) checam estrutura do certificado, algoritmo, assinatura do
  handshake (prova de posse) e, quando aplicável, o ID esperado. A API `dangerous()` do rustls é
  usada apenas para **substituir** a validação por CA pela validação por chave fixada.
- A confiança inicial é estabelecida pela comparação do código derivado do TLS exporter, que
  vincula o código às chaves daquela sessão TLS específica.

### Força do código de verificação

6 dígitos ⇒ probabilidade de 10⁻⁶ de um MITM produzir códigos iguais em uma tentativa. As
tentativas são limitadas (5 pedidos/min, um pendente por vez, timeout de 60 s) e cada uma exige
ação explícita dos dois usuários, o que torna o ataque online impraticável e visível.

## 2. Controles obrigatórios e como são atendidos

| Requisito | Implementação |
|---|---|
| Não confiar em dispositivos descobertos por mDNS | Descobertos aparecem como "não verificado"; conexão exige ID igual ao anunciado e pareamento confirmado. |
| Sem sessões sem autenticação e consentimento | Sessão só após TLS mútuo + ID no registro de confiáveis (que só é preenchido por pareamento confirmado nos dois lados). |
| Não desabilitar a validação TLS | Verificadores próprios fazem validação completa por chave fixada (ver §1). |
| Mecanismo verificável de identidade e confiança inicial | ID = SHA-256(chave pública); código SAS do exporter TLS; ID completo visível na UI. |
| Credenciais privadas fora de texto puro | Chave privada somente no cofre do SO (`keyring`: Windows Credential Manager/DPAPI). Em memória, envolta em `Zeroizing`. Sem fallback para arquivo. |
| Sem privilégios administrativos | Aplicação roda como usuário comum; porta > 1024; dados em `%APPDATA%`. |
| Sem portas públicas na internet | Sem UPnP/NAT-PMP; política de endereços aceita apenas loopback, RFC 1918, link-local e ULA (IPv6), tanto na entrada quanto na saída. |
| Limitar mensagens, conexões e filas | Ver [protocolo §9](protocol.md#9-limites). |
| Validar rigorosamente mensagens | Serde com `deny_unknown_fields`, enums fechados, validação de texto, máquina de estados que rejeita mensagens fora de fase. |
| Proteção contra replay | TLS 1.3 (AEAD com número de sequência de registro, sem 0-RTT) + `seq` estrito por direção + código de pareamento vinculado à sessão TLS + `session_id` aleatório por sessão. |
| Não executar comandos arbitrários | Nenhuma mensagem do protocolo dispara execução; Tauri sem plugins de shell/fs/http. |
| Menor privilégio no Tauri | Capability única para a janela `main` com apenas `core:event:allow-listen`, `core:event:allow-unlisten` e as permissões geradas para os 8 comandos do app. CSP restritiva. |
| Logs sem dados sensíveis | Logs usam ID curto (8 caracteres); não registram nomes de dispositivos, endereços IP, códigos de pareamento nem material de chave. |

## 3. Superfície IPC (Tauri)

Comandos expostos à UI (todos validam entrada no lado Rust):

| Comando | Validação |
|---|---|
| `get_snapshot` | — |
| `connect_address(address, port?)` | IP literal (sem DNS), porta 1024–65535, política de rede local. |
| `connect_device(deviceId)` | Formato do ID; dispositivo descoberto ou confiável. |
| `respond_pairing(pairingId, accept)` | Formato do ID do pareamento; pareamento existente. |
| `disconnect_device(deviceId)` | Formato do ID. |
| `revoke_device(deviceId)` | Formato do ID. |
| `update_settings(patch)` | Nome 1–64 sem controle; porta 1024–65535; booleanos. |
| `get_build_info` | — |

CSP de produção:

```
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;
font-src 'self'; connect-src ipc: http://ipc.localhost; object-src 'none';
base-uri 'none'; frame-ancestors 'none'; form-action 'none'
```

Nenhum recurso remoto é carregado (fontes e ícones são locais).

## 4. Armazenamento local

- `settings.json` e `trusted_devices.json` contêm apenas dados públicos. Um processo malicioso com
  os mesmos privilégios do usuário poderia alterá-los — isso está fora do escopo (ver modelo de
  ameaças, premissa P2).
- Corrupção ⇒ arquivo isolado como `.corrupt` e estado vazio (falha fechada).

## 5. Registro (logs)

- `tracing` com nível padrão `info`; `RUST_LOG` permite `debug` em desenvolvimento.
- Campos permitidos: ID curto, tipo de evento, motivo de encerramento, latência agregada.
- Campos proibidos: nome do dispositivo, endereço IP/porta remota, código de pareamento,
  chaves, conteúdo de mensagens.

## 6. Dependências

- Versões fixadas em `Cargo.lock` e `package-lock.json`.
- CI executa `cargo clippy -D warnings`, testes e build; recomenda-se adicionar `cargo audit`/
  `cargo deny` e `npm audit` como verificação periódica (ver roadmap).

## 7. Limitações conhecidas do Ciclo 01

- Firewall do Windows: na primeira escuta, o Windows pode solicitar permissão para redes
  privadas; aceitar pode exigir confirmação administrativa conforme a política local. Conexões de
  saída funcionam sem a regra. O aplicativo não altera o firewall.
- O nome do dispositivo e o ID são anunciados por mDNS na rede local quando "Visível na rede"
  está ativo. O usuário pode desativar a visibilidade e usar conexão manual por IP.
- Redes com isolamento de clientes (Wi-Fi de convidados) bloqueiam mDNS e conexões diretas.
- Endereços CGNAT/VPN (ex.: `100.64.0.0/10`) não são aceitos por padrão.
