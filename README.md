# Aurora Connect

> Dois computadores. Um único controle.

**Estado:** planejamento / backlog P1 (prioridade proposta), 26/11/2026. Nenhum recurso implementado.

## Visão e motivação
Integrar desktop, notebook e futuros computadores em uma estação de trabalho, usando um único mouse e teclado, sem trocar periféricos ou recorrer ao touchpad do notebook. A ideia nasce da dificuldade de utilizar Mouse Without Borders. Cada computador continua executando seus próprios programas e SO. Não é streaming de tela nem KVM de vídeo.

## Requisitos e experiência
- Mouse e teclado compartilhados pela LAN: cursor cruza a borda configurada, foco passa ao dispositivo remoto e teclado acompanha; retorno imediato ao host.
- Clipboard bidirecional de texto e imagens, com opt-in, deduplicação e bloqueio por dispositivo.
- Transferência de arquivos/pastas (inclusive copiar/colar quando viável), progresso, confirmação, cancelamento e verificação de integridade.
- Canvas visual de topologia com múltiplos monitores por máquina, posições relativas (esquerda/direita/acima/abaixo), DPI, resolução, offsets e hotplug; não interferir entre monitores locais.
- Descoberta automática, pareamento confirmado, conexão manual quando descoberta falhar, reconexão, autostart opcional, status/latência, dispositivos confiáveis, toggles e botão de desconexão.
- Perfis de workspace, atalhos de troca, suporte a mais de dois computadores; Windows primeiro, Linux e macOS depois.
- Operação independente de internet, AI e Nexus; integração opcional com Central (interface/lançamento) e Control (estado técnico, sem conteúdo de clipboard).

## Arquitetura proposta
Tauri 2, React/TypeScript, Rust, APIs nativas de entrada e clipboard por SO, TCP/TLS autenticado, mDNS/Bonjour para descoberta, SQLite ou armazenamento local equivalente e cofre de credenciais do SO. Separar protocolo, transporte, sessão, topologia, adaptadores nativos e UI. Host captura eventos, cliente injeta somente em sessão autorizada; evitar eco/loops. Canal de eventos de baixa latência separado de transferências grandes, filas limitadas, backpressure e sequência. Liberar teclas/modificadores/botões após perda de foco ou desconexão; atalho de emergência local. Avaliar Raw Input, hooks e SendInput/UIPI no Windows; Wayland e permissões macOS exigem pesquisa. Não exigir administrador por padrão.

## Segurança
Pareamento com confirmação local e identidade criptográfica verificada; mDNS não implica confiança. TLS, revogação, autorização por capacidade, proteção contra replay e limites de taxa/tamanho. Não capturar teclas permanentemente, registrar clipboard ou contornar UAC/tela segura. Nenhum input remoto antes do consentimento. Arquivos com destino controlado, saneamento de nomes, proteção contra path traversal/symlinks e sobrescrita acidental, hash e escrita atômica. Não abrir portas públicas. Auditar IPC, CSP e capabilities Tauri. Testar rede hostil, impostores e desconexão.

## Roadmap
1. Fundação Windows, pareamento e transporte autenticado.
2. Mouse e teclado, bordas, recuperação de foco, emergência.
3. Layout visual multimonitor, DPI, hotplug e perfis.
4. Clipboard texto/imagem e privacidade.
5. Arquivos/pastas, cancelamento e integridade.
6. Reconexão, carga, segurança, instalador e autostart.
7. Linux/macOS após pesquisa.
8. Integração opcional Central/Control.

## Validação
Desktop e notebook reais, múltiplos monitores, DPI, Wi-Fi/Ethernet, perda de rede, suspensão, reinício, teclas presas, clipboard concorrente, dispositivos não pareados, transferência interrompida. Medir latência/jitter e CPU antes de prometer metas. MVP: Windows↔Windows estável. Não antecipar integrações.

## Referências e decisões pendentes
- [Deskflow](https://github.com/deskflow/deskflow): referência de input/clipboard multiplataforma.
- [PowerToys](https://github.com/microsoft/PowerToys): Mouse Without Borders, UX e arquivos.
Avaliar licença, manutenção, ameaças e compatibilidade antes de reutilizar código. Protocolo final, biblioteca TLS, política de clipboard, UX de pareamento, licença e integração nativa de arquivos ainda em aberto. Não publicar dados pessoais ou detalhes de redes privadas.
