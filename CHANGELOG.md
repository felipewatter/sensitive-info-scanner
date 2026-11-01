# Changelog

## 1.1.0 — 2026-10-31

- Implementadas assinaturas de AWS, GitHub, Slack, Stripe, Google API, chaves privadas e segredos genéricos.
- Melhorada a detecção por nomes de arquivos potencialmente sensíveis.
- Resultados estruturados com regra, caminho relativo e número da linha, sem imprimir correspondências.
- Scanner offline com limites de arquivos, tamanho, profundidade, bytes globais e volume de resultados.
- Tratamento de links simbólicos, binários e pastas de dependências e build.
- Padrões literais customizados em JSON, com validação de formato e tamanho (sem execução de regex arbitrária).
- CLI TypeScript/Node.js funcional com saída texto/JSON, códigos 0/1/2 e compatibilidade da função scanDir.
- Testes automatizados, CI Node 22/24 em Ubuntu, Windows e macOS; documentação e políticas de segurança.

## 1.0.0

- Versão inicial, com padrões demonstrativos e varredura recursiva sem limite.
