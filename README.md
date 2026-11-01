# Sensitive Info Scanner

[![CI](https://github.com/felipewatter/sensitive-info-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/felipewatter/sensitive-info-scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Scanner **offline** de padrões de credenciais acidentalmente incluídas em diretórios de projetos, com resultados **sem exibir os segredos encontrados**. Escrita em TypeScript/Node.js, a ferramenta oferece códigos de saída para CI/CD, limites explícitos de leitura e tratamento preventivo de links simbólicos.

## Funcionalidades da v1.1.0

- Identifica padrões conhecidos de credenciais AWS, GitHub, Slack, Stripe e Google, blocos de chave privada e determinadas atribuições genéricas de segredos.
- Reconhece nomes suspeitos como `.env`, `.env.production`, `id_rsa`, `*.key`, `*.p12` e `credentials.json`; ignora arquivos exemplo `.env.example`.
- Resultados mostram **regra, caminho relativo e número da linha**, nunca o trecho de texto nem a credencial encontrada.
- Varredura determinística de diretórios, ignorando `.git`, `node_modules`, `dist`, `build`, `vendor` e outros artefatos comuns.
- Ignora links simbólicos e binários com NUL detectado, registrando contagem de itens ignorados.
- Limites de arquivos, bytes por arquivo, bytes acumulados, profundidade e volume de findings. Limite excedido **interrompe** a análise com código 2 para não indicar falso resultado limpo.
- Padrões adicionais em JSON por busca de **texto literal**, não regex arbitrária. Isso evita regex customizada catastrófica (ReDoS).

## Instalação

Requer **Node.js 22 ou 24**, npm.

```bash
git clone https://github.com/felipewatter/sensitive-info-scanner.git
cd sensitive-info-scanner
npm install
npm run build
node dist/bin/index.js --help
```

Instalação global opcional a partir do checkout compilado: `npm install -g .`.

**Importante:** esta atualização é do repositório GitHub. Não presuma que exista a versão atualizada no registro npm. Para utilização direta do código:

```bash
node dist/bin/index.js ./meu-projeto --format json
```

## Comandos

```bash
node dist/bin/index.js ./meu-projeto
node dist/bin/index.js --path ./meu-projeto --format json
node dist/bin/index.js ./meu-projeto --max-file-bytes 1048576 --max-files 20000
node dist/bin/index.js ./meu-projeto --pattern-file ./scanner-patterns.json
```

| Opção | Padrão | Significado |
|---|---|---|
| `--path DIR` ou argumento posicional | obrigatório | Raiz do projeto |
| `--format text\|json` | text | Formato do relatório |
| `--pattern-file FILE` | nenhum | Padrões **literais** personalizados |
| `--max-file-bytes N` | 1048576 | Máximo 8 MiB por arquivo |
| `--max-files N` | 20000 | Quantidade máxima de arquivos |
| `--max-depth N` | 24 | Profundidade máxima, até 64 |
| `--max-total-bytes N` | 67108864 | Orçamento global de 64 MiB, máximo 512 MiB |

### Códigos de saída

- **0** — scanner concluiu a inspeção prevista sem detecção de padrões.
- **1** — detectou um ou mais possíveis segredos ou arquivos sensíveis.
- **2** — erro ou varredura incompleta (falha de acesso, orçamento excedido, JSON inválido, diretório inexistente). **Não confunda com análise limpa**.

Exemplo de relatório (sem dados sensíveis):

```text
Sensitive Info Scanner v1.1.0
Files scanned: 2
Binary files skipped: 0
Symbolic links skipped: 0
Ignored directories: 1
Potential findings: 1
[HIGH] aws-access-key @ src/settings.txt:3
```

## Padrões adicionais seguros

Crie `scanner-patterns.json`:

```json
{
  "patterns": [
    {"id": "internal-credential-marker", "literal": "EXAMPLE-SECRET-MARKER"},
    {"id": "internal-token-prefix", "literal": "example_company_auth_", "caseSensitive": false}
  ]
}
```

Até 20 expressões **literais** por arquivo, de 4 a 128 caracteres. O arquivo é JSON, não um script executável. `id` deve ser único e conter letras minúsculas, números ou hífen.

## Execução em pipelines

```yaml
- name: Inspect secrets before publishing
  run: node ./dist/bin/index.js . --format json
```

Compile o scanner antes dessa etapa e execute no repositório a verificar. Não envie o relatório a endpoints externos sem revisar o conteúdo dos caminhos de arquivos.

## Segurança, escopo e limitações

**O scanner não garante ausência de segredos.** Regex e literais têm falsos negativos e falsos positivos, não reconhecem todos os formatos, hashes, credenciais derivadas ou senhas embutidas em binários. Binários e links simbólicos não são inspecionados. Diretórios ignorados (como `node_modules`) também ficam fora da cobertura.

A varredura ocorre **somente no diretório atual do sistema de arquivos**. Não inspeciona automaticamente histórico Git, commits antigos, repositórios remotos ou objetos Git descartados. Se um segredo foi publicado, é necessário revogá-lo e realizar tratamento do histórico conforme sua política de segurança.

Para projetos adversariais que possam modificar os arquivos **durante** a análise, execute em snapshot/container isolado e imutável. As verificações `lstat` e `realpath` reduzem o risco de atravessar links existentes, mas não eliminam completamente condições de corrida do sistema de arquivos.

A ferramenta não faz requisições externas nem valida a autenticidade das chaves encontradas. Use os resultados apenas como indicadores para revisão humana.

Consulte [SECURITY.md](SECURITY.md) e [CHANGELOG.md](CHANGELOG.md). Licença MIT.
