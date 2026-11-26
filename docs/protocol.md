# Protocolo Aurora Connect — versão 1

Especificação do protocolo de rede usado entre dispositivos Aurora Connect no Ciclo 01.
Implementação de referência: `crates/aurora-protocol` (mensagens, framing, validação) e
`crates/aurora-core` (transporte, handshake, sessão).

## 1. Camadas

| Camada | Definição |
|---|---|
| Descoberta | mDNS/DNS-SD, serviço `_aurora-connect._tcp.local.` (UDP 5353). Informativo e não confiável. |
| Transporte | TCP, porta padrão **47821** (configurável). `TCP_NODELAY` ativo. |
| Segurança | TLS **1.3 somente**, autenticação **mútua** com certificados Ed25519 autoassinados, ALPN `aurora-connect/1`. Sem 0-RTT, sem *session tickets*/retomada. |
| Framing | `u32` big-endian (tamanho) + payload JSON UTF-8. |
| Aplicação | Envelope versionado com número de sequência e mensagem tipada. |

## 2. Descoberta (mDNS)

- Nome de instância: `aurora-<12 primeiros caracteres do ID>`; tipo `_aurora-connect._tcp.local.`.
- Registros TXT:

| Chave | Valor | Validação no receptor |
|---|---|---|
| `v` | `1` | Igual a `1`, senão ignorado. |
| `id` | ID do dispositivo (52 caracteres base32) | Formato válido; diferente do próprio ID. |
| `name` | Nome escolhido pelo usuário | 1–64 caracteres, sem caracteres de controle (sanitizado). |

- Endereços anunciados que não sejam de rede local (política do Network Manager) são descartados.
- **Descoberta não gera confiança.** Ao conectar a um dispositivo descoberto, o cliente exige no
  handshake TLS que o certificado apresentado corresponda ao `id` anunciado (*pinning*); se não
  corresponder, a conexão é abortada como "identidade divergente".

## 3. Identidade e TLS

- Cada dispositivo gera uma chave **Ed25519** (via `rcgen`/`ring`) na primeira execução.
- **ID do dispositivo** = `BASE32(SHA-256(SubjectPublicKeyInfo DER))`, sem padding (52 caracteres).
  Exibição curta: 8 primeiros caracteres em dois grupos (`ABCD-EFGH`); exibição completa em grupos
  de 4.
- Certificado X.509 autoassinado derivado da chave (CN `Aurora Connect Device`,
  SAN `device.aurora-connect.invalid`). O certificado pode ser regenerado sem mudar o ID, pois o ID
  depende só da chave pública.
- Verificação no handshake (cliente e servidor):
  1. Exatamente um certificado, sem intermediários.
  2. Certificado X.509 bem-formado com chave pública Ed25519 (OID 1.3.101.112).
  3. Assinatura `CertificateVerify` do TLS 1.3 verificada com a chave do certificado
     (`rustls::crypto::verify_tls13_signature`) — prova de posse da chave privada.
  4. Se o ID esperado é conhecido (dispositivo descoberto ou confiável), o ID calculado deve ser
     igual; caso contrário, o handshake falha.
  5. Esquema de assinatura aceito: somente `ed25519`.
- A decisão de **confiança** (o ID está no registro de confiáveis?) é feita imediatamente após o
  handshake, antes de qualquer mensagem que não seja de handshake/pareamento.
- Após o handshake, ALPN negociado deve ser `aurora-connect/1`, senão a conexão é encerrada.

## 4. Framing

```
+----------------------+-----------------------------+
| length: u32 (BE)     | payload: JSON UTF-8         |
+----------------------+-----------------------------+
```

- `1 ≤ length ≤ 65 536` bytes. Valor fora do intervalo encerra a conexão **antes** de ler o payload.
- Timeouts: TLS handshake 10 s; primeira mensagem (`hello`) 5 s; escrita de frame 5 s.

## 5. Envelope

```json
{ "v": 1, "seq": 0, "body": { "type": "hello", "data": { ... } } }
```

| Campo | Regra |
|---|---|
| `v` | Versão do protocolo. Deve ser `1`. |
| `seq` | `u64`. Começa em `0` em cada direção de cada conexão e incrementa exatamente `1` por frame. Qualquer desvio (repetição, salto, regressão) encerra a conexão. |
| `body` | Mensagem tipada (`type` + `data`). Tipos e campos desconhecidos são rejeitados. |

## 6. Mensagens

| `type` | `data` | Direção / fase |
|---|---|---|
| `hello` | `{ "device_name": string(1..64), "app_version": string(1..32), "intent": "pair" \| "session" }` | Cliente→servidor primeiro; servidor responde com seu `hello` (o `intent` do servidor espelha o do cliente). |
| `pair_pending` | `{}` | Servidor→cliente: pareamento aguardando confirmação do usuário. |
| `pair_confirm` | `{}` | Ambas as direções: o usuário daquele lado confirmou o código. |
| `session_accept` | `{ "session_id": string(32 hex) }` | Servidor→cliente: sessão autenticada ativa. |
| `reject` | `{ "reason": RejectReason }` | Qualquer direção durante o handshake; seguido de encerramento. |
| `ping` | `{ "id": u64 }` | Sessão ativa, ambas as direções. |
| `pong` | `{ "id": u64 }` | Resposta imediata a `ping`, com o mesmo `id`. |
| `goodbye` | `{ "reason": "user" \| "shutdown" \| "revoked" \| "replaced" }` | Sessão ativa; encerramento ordenado. |

`RejectReason`: `not_trusted`, `busy`, `unsupported_version`, `pairing_unavailable`,
`rate_limited`, `user_rejected`, `timeout`, `identity_mismatch`, `protocol_error`, `self_connection`.

Os campos de texto são validados após a desserialização: comprimento em caracteres, ausência de
caracteres de controle e espaços nas extremidades.

## 7. Handshake de aplicação

### 7.1 Sessão entre dispositivos já confiáveis

1. Cliente → `hello(intent=session)`.
2. Servidor verifica o ID do cliente no registro. Se não confiável → `reject(not_trusted)`.
3. Servidor → `hello`, depois `session_accept(session_id)`.
4. Cliente verifica o ID do servidor no **seu** registro; se não confiável → `reject(not_trusted)`.

### 7.2 Pareamento

1. Cliente conecta; após o TLS, se o ID do servidor não é confiável, envia `hello(intent=pair)`.
2. Servidor → `hello` e `pair_pending` (ou `reject` com `busy`, `rate_limited` ou
   `pairing_unavailable`).
3. Os dois lados calculam o **código de verificação** e mostram ao usuário (nunca é transmitido):

```
ctx  = SHA-256( "aurora-connect/pair/v1" || min(idA, idB) || max(idA, idB) )
ekm  = TLS-Exporter(label = "EXPORTER-aurora-connect-pair-v1", context = ctx, length = 8)
code = u64_be(ekm) mod 1 000 000   → exibido como "123 456"
```

4. Cada usuário compara os códigos e confirma ou recusa. Cada lado envia `pair_confirm` quando o
   **seu** usuário confirma.
5. Um lado grava o par como confiável somente quando possui **confirmação local e remota**.
6. Servidor envia `session_accept` após gravar; a sessão fica ativa.
7. Recusa em qualquer lado → `reject(user_rejected)`. Sem decisão em 60 s → `reject(timeout)`.

Um atacante em posição de MITM teria duas sessões TLS distintas (com chaves e IDs distintos);
os códigos exibidos só coincidem com probabilidade 10⁻⁶ por tentativa, e as tentativas são
limitadas por taxa.

## 8. Sessão ativa

- `ping` a cada **2 s** em cada direção; `pong` imediato. A latência (RTT) é medida localmente com
  relógio monotônico; a UI exibe o último valor e a média móvel exponencial (α = 0,3).
- **Detecção de desconexão**: nenhum frame recebido em **6 s** → sessão `lost`.
- **Reconexão**: o lado que iniciou a sessão tenta reconectar com backoff exponencial
  (1, 2, 4, 8, 16, 30 s…) por até 10 tentativas, usando o último endereço descoberto ou conhecido
  e exigindo o mesmo ID (*pinning*). Encerramento por `goodbye` não dispara reconexão.
- **Deduplicação**: no máximo uma sessão por par. Se duas conexões coexistem, permanece a iniciada
  pelo dispositivo de menor ID; se ambas têm o mesmo iniciador, a mais nova substitui a antiga
  (`goodbye(replaced)`).
- **Revogação**: `goodbye(revoked)` informa ao par que a confiança foi removida; o receptor também
  remove o remetente do seu registro. Conexões futuras exigem novo pareamento.

## 9. Limites

| Recurso | Limite |
|---|---|
| Tamanho de frame | 64 KiB |
| Conexões simultâneas (total) | 32 |
| Handshakes TLS simultâneos | 8 |
| Conexões por endereço IP de origem | 4 |
| Frames recebidos por conexão | 50/s sustentado, rajada de 100 (token bucket) |
| Fila de frames recebidos por conexão | 32 |
| Fila de eventos do Engine | 256 |
| Pareamentos pendentes recebidos | 1 por vez |
| Pedidos de pareamento | 5 por minuto (global) |
| Dispositivos confiáveis | 64 |
| Dispositivos descobertos mantidos | 64 |

Excesso de limite resulta em recusa (`reject`) ou encerramento imediato da conexão.

## 10. Evolução

- Novas versões incrementam `v`; o Ciclo 02 deverá introduzir negociação de capacidades
  (ex.: `input`) e possivelmente um canal de eventos binário. Versões desconhecidas recebem
  `reject(unsupported_version)`.
