# Roadmap — Aurora Connect

Baseado no roadmap original do README. Cada ciclo só começa com autorização explícita após a
revisão do ciclo anterior. Os ciclos futuros são acompanhados como issues no GitHub
(rótulo `roadmap`).

| Ciclo | Tema | Issue | Estado |
|---|---|---|---|
| 01 | Fundação Windows, pareamento e transporte autenticado | [#2](https://github.com/LeonardoSSm/aurora-connect/issues/2) | **Em revisão** (este PR) |
| 02 | Mouse e teclado, bordas, recuperação de foco, emergência | [#3](https://github.com/LeonardoSSm/aurora-connect/issues/3) | Planejado |
| 03 | Layout visual multimonitor, DPI, hotplug e perfis | [#4](https://github.com/LeonardoSSm/aurora-connect/issues/4) | Planejado |
| 04 | Clipboard texto/imagem e privacidade | [#5](https://github.com/LeonardoSSm/aurora-connect/issues/5) | Planejado |
| 05 | Arquivos/pastas, cancelamento e integridade | [#6](https://github.com/LeonardoSSm/aurora-connect/issues/6) | Planejado |
| 06 | Reconexão avançada, carga, segurança, instalador e autostart | [#7](https://github.com/LeonardoSSm/aurora-connect/issues/7) | Planejado |
| 07 | Linux/macOS após pesquisa | [#8](https://github.com/LeonardoSSm/aurora-connect/issues/8) | Planejado |
| 08 | Integração opcional Central/Control | [#9](https://github.com/LeonardoSSm/aurora-connect/issues/9) | Planejado |

## Ciclo 01 — Fundação e conectividade

Ver [`cycle-01.md`](cycle-01.md).

## Ciclo 02 — Mouse e teclado

- Input Manager com adaptadores Windows (Raw Input / hooks de baixo nível / `SendInput`), UIPI.
- Capacidade `input` por dispositivo e consentimento antes do primeiro input remoto.
- Transição pela borda configurada, foco remoto, retorno imediato ao host.
- Liberação de teclas, modificadores e botões em perda de foco/desconexão; atalho de emergência.
- Evitar eco/loops; canal de eventos de baixa latência (avaliar codificação binária e revisão do
  rate limit); medir latência/jitter e CPU antes de definir metas.

## Ciclo 03 — Topologia multimonitor

- Canvas de computadores e monitores (rota "Topologia" já reservada na UI).
- Posições relativas, DPI, resolução, offsets, hotplug; perfis de workspace.

## Ciclo 04 — Clipboard

- Texto e imagens, opt-in, deduplicação, bloqueio por dispositivo, nunca registrar conteúdo.

## Ciclo 05 — Arquivos

- Canal separado, progresso, confirmação, cancelamento, hash, escrita atômica, saneamento de
  nomes, proteção contra path traversal/symlinks.

## Ciclo 06 — Robustez e distribuição

- Reconexão avançada e autoconexão, testes de carga e rede hostil, instalador assinado,
  autostart opcional, `cargo audit`/`cargo deny`/`npm audit` no CI, fuzzing do decodificador.

## Ciclo 07 — Linux e macOS

- Pesquisa de Wayland/X11 e permissões de acessibilidade do macOS; adaptadores de plataforma.

## Ciclo 08 — Integrações opcionais

- Aurora Central (interface/lançamento) e Aurora Control (estado técnico, sem conteúdo de
  clipboard). Sempre opcionais; o Connect continua funcionando sozinho.
