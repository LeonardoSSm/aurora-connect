# Modelo de ameaças — Aurora Connect (Ciclo 01)

Metodologia: STRIDE aplicado aos fluxos do Ciclo 01. Escopo: descoberta, pareamento, transporte,
sessão, persistência local e IPC da aplicação desktop.

## 1. Ativos

| Ativo | Por que importa |
|---|---|
| A1 Chave privada do dispositivo | Permite se passar pelo dispositivo perante pares confiáveis. |
| A2 Lista de dispositivos confiáveis | Define quem pode abrir sessão (e, a partir do Ciclo 02, controlar entrada). |
| A3 Sessão autenticada | No Ciclo 02 transportará eventos de teclado e mouse. |
| A4 Disponibilidade do serviço | Usuário depende da conexão para trabalhar. |
| A5 Privacidade do usuário | Nome do dispositivo, endereços, hábitos de uso. |

## 2. Atores

| Ator | Capacidade |
|---|---|
| T1 Atacante passivo na LAN | Observa tráfego (Wi-Fi compartilhado, porta espelhada). |
| T2 Atacante ativo na LAN | Envia mDNS falso, conecta-se à porta, faz ARP spoofing/MITM, injeta pacotes. |
| T3 Dispositivo revogado | Possui chave válida que já foi confiável. |
| T4 Usuário desatento | Aceita pedidos sem comparar o código. |
| T5 Atacante na internet | Tenta alcançar a porta de fora da LAN. |
| T6 Conteúdo web malicioso | Tenta usar a WebView/IPC (ex.: via XSS). |

## 3. Premissas

- **P1** O sistema operacional e a conta do usuário não estão comprometidos.
- **P2** Processos com os mesmos privilégios do usuário são confiáveis (podem ler o cofre de
  credenciais do usuário e os arquivos de configuração; isso está fora do escopo).
- **P3** Os usuários comparam o código exibido nas duas telas antes de confirmar.
- **P4** As bibliotecas criptográficas (rustls, ring) estão corretas.

## 4. Análise STRIDE

| ID | Ameaça | Categoria | Ator | Mitigação | Risco residual |
|---|---|---|---|---|---|
| S1 | Anúncio mDNS falso com nome de um dispositivo conhecido | Spoofing | T2 | mDNS é informativo; conexão exige ID igual ao anunciado e, para sessão, ID no registro. Um ID novo exige pareamento. | Baixo: usuário vê "não verificado" e um pedido de pareamento inesperado. |
| S2 | MITM durante o pareamento | Spoofing/Tampering | T2 | Código SAS do TLS exporter difere entre as duas sessões do MITM; confirmação nos dois lados. | Baixo, depende de P3 (T4). |
| S3 | MITM em sessão de dispositivos confiáveis | Spoofing | T2 | TLS mútuo com chave fixada; o atacante não possui a chave privada. | Muito baixo. |
| S4 | Uso de chave roubada | Spoofing | — | Chave somente no cofre do SO; revogação remove a confiança. | Depende de P1/P2. |
| S5 | Dispositivo revogado tenta reconectar | Elevation | T3 | Registro consultado em cada conexão; `reject(not_trusted)`. | Muito baixo. |
| T1 | Alteração/injeção de frames | Tampering | T2 | AEAD do TLS 1.3. | Muito baixo. |
| T2 | Replay de frames ou de sessão | Tampering | T2 | Sequência de registros TLS, sem 0-RTT, `seq` estrito, código vinculado à sessão TLS. | Muito baixo. |
| R1 | Usuário nega ter pareado | Repudiation | — | Data de pareamento registrada localmente. | Aceito (produto local). |
| I1 | Escuta de tráfego | Info disclosure | T1 | TLS 1.3 com sigilo futuro. | Metadados (tamanho/tempo) visíveis. |
| I2 | Exposição de nome/ID via mDNS | Info disclosure | T1 | Opção "Visível na rede"; conexão manual por IP como alternativa. | Aceito e documentado. |
| I3 | Dados sensíveis em logs | Info disclosure | — | Política de logs (ID curto, sem IP/nome/código). | Baixo. |
| D1 | Inundação de conexões TCP/TLS | DoS | T2 | Limites globais e por IP, semáforo de handshakes, timeouts. | Médio: um atacante na LAN pode ocupar slots temporariamente. |
| D2 | Frames enormes ou malformados | DoS | T2 | Limite de 64 KiB verificado antes da leitura; parsing estrito; encerramento imediato. | Baixo. |
| D3 | Inundação de pedidos de pareamento (spam de diálogos) | DoS | T2 | 1 pendente por vez, 5/min, opção de desativar pareamento. | Baixo. |
| D4 | Inundação de mensagens em sessão autenticada | DoS | T3 antes da revogação | Token bucket de 50 frames/s; fila limitada. | Baixo. |
| D5 | Inundação de anúncios mDNS | DoS | T2 | Máximo de 64 dispositivos descobertos; validação de TXT. | Baixo. |
| E1 | Acesso pela internet | Elevation | T5 | Sem UPnP; apenas endereços locais aceitos. | Baixo; depende do roteador não expor a porta manualmente. |
| E2 | XSS na WebView invoca comandos | Elevation | T6 | Sem conteúdo remoto, CSP restritiva, React escapa texto (nomes de dispositivos), capabilities mínimas, comandos validam entrada. | Baixo. |
| E3 | Mensagem induz execução de comando | Elevation | T2/T3 | Nenhuma mensagem mapeia para execução; sem plugins shell/fs. | Muito baixo. |

## 5. Ameaças relevantes para ciclos futuros

- **Ciclo 02 (entrada remota)**: impacto de comprometimento sobe muito (controle do teclado).
  Requisitos: capacidade `input` explícita por dispositivo, nenhum input antes do consentimento,
  atalho de emergência local, liberação de teclas na desconexão, respeito a UAC/tela segura.
- **Ciclo 04 (clipboard)**: vazamento de segredos copiados; opt-in por dispositivo, nunca logar.
- **Ciclo 05 (arquivos)**: path traversal, symlinks, sobrescrita, esgotamento de disco.

## 6. Testes de segurança executados

Ver evidências em [`cycle-01.md`](cycle-01.md#evidências): conexão não autorizada, pareamento
recusado, revogação, intenção de sessão forjada, frames inválidos/gigantes, sequência repetida,
lixo/HTTP na porta TLS, inundação de conexões e desconexão inesperada.
