# Política de segurança — Sensitive Info Scanner

Reporte falhas de forma privada via GitHub Security Advisories quando disponível. Nunca envie chaves reais nem tokens em issues ou registros públicos.

## Modelo de segurança

- Operação **offline**: o scanner não envia conteúdo analisado a APIs.
- Resultados mostram apenas identificadores de regra, caminhos relativos e linhas. Não imprimem valores, trechos de código ou a correspondência encontrada.
- Links simbólicos são ignorados; diretórios de dependências/artefatos são omitidos; existem limites de quantidade, tamanho, profundidade e volume de findings.
- Excesso de limites ou erros de leitura causam **código de saída 2**. A ferramenta não transforma inspeção parcial em estado limpo.
- Arquivos binários com NUL detectado são ignorados e contados; isso não garante inspeção de todos os dados binários.
- Padrões personalizados são **buscas literais** em vez de aceitar regex não confiável, diminuindo o risco de ReDoS.

## Riscos e limites conhecidos

- Arquivos podem ser alterados entre as operações de lstat, realpath e readFile (TOCTOU). Para dados de terceiros, use um snapshot imutável, contêiner com montagem somente leitura e permissões mínimas; não confie apenas na detecção de links.
- Valores podem estar codificados, em arquivos binários, no histórico do Git ou em diretórios ignorados. Esta ferramenta **não** garante cobertura total e não substitui revisão manual, detecção especializada de segredos ou ferramentas SAST/SCA.
- Caminhos de arquivo podem identificar informações internas; evite publicar relatórios sem revisão.
- Falsos positivos são possíveis. Não desative padrões de maneira generalizada para silenciar avisos.
- No caso de segredo real exposto, **revogue e gire a credencial**; remover um arquivo ou commit pode não tornar o segredo seguro.
- Não execute como administrador/root contra diretórios de origem não confiável.

## Saídas para CI

0 = limpo nos arquivos inspecionados; 1 = possível achado; 2 = erro ou cobertura incompleta.
