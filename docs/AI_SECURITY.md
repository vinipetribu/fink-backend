# Segurança da IA do SecureFINK

Este documento atualiza exclusivamente o item de IA que estava marcado como pendente em `SECURITY_ANALYSIS.md`.

## Finalidade e escopo

O recurso sugere uma categoria para a descrição de cada transação validada em `POST /api/v1/uploads/csv`. A resposta serve apenas para revisão humana: não altera saldo, cria movimentação, persiste o CSV ou executa decisões.

## Modelo e dados

- Algoritmo: `TfidfVectorizer` com unigramas e bigramas, seguido de `LogisticRegression` (`solver=lbfgs`, `C=8`, `random_state=42`).
- Treinamento: pequeno CSV versionado em `app/ai/data/training_transactions.csv`, composto exclusivamente por descrições fictícias.
- Categorias permitidas: Alimentação, Transporte, Moradia, Saúde, Educação, Lazer e Outros.
- Execução: o modelo é treinado uma vez por processo somente com o conjunto versionado. Arquivos enviados não são incorporados ao treinamento.
- Métricas: não foi calculada nem declarada acurácia, pois o conjunto pequeno foi criado para demonstração e não constitui uma base independente de avaliação.

## Limitações e risco

O vocabulário é pequeno e não representa a diversidade de descrições bancárias reais. Abreviações, erros de digitação, contexto insuficiente e termos pertencentes a várias categorias podem produzir classificação incorreta. O impacto atual é uma sugestão enganosa na interface; não há efeito financeiro automático.

O cenário de risco é **evasão ou manipulação da entrada**: uma descrição ambígua, desconhecida ou deliberadamente estranha pode tentar induzir uma categoria incorreta. Prompt injection não é o conceito aplicável, porque este fluxo não usa LLM, instruções em linguagem natural ou ferramentas autônomas.

## Mitigações implementadas

- allowlist imutável com as sete categorias;
- descrição obrigatória e limitada a 255 caracteres;
- `revisao_necessaria=true` quando a confiança é inferior a 0,55, quando menos da metade dos termos analisados pertence ao vocabulário ou quando a descrição é vazia/desconhecida;
- confiança apresentada como estimativa do classificador, sem promessa de acurácia;
- mensagem explícita de que toda categoria é uma sugestão sujeita à revisão humana;
- treinamento isolado dos uploads e ausência de persistência de arquivos ou classificações.

O limite de 0,55 é um controle operacional conservador: exige que uma classe concentre mais da metade da probabilidade estimada, bem acima da distribuição uniforme entre sete classes. Ele não foi derivado de uma medição de acurácia e deve ser recalibrado antes de qualquer uso real.

## Demonstração

Na apresentação, `examples/transacoes_exemplo.csv` demonstra sugestões para descrições claras. Em seguida, `examples/transacoes_risco_ia.csv` mostra termos sem sentido e descrições que misturam categorias; esses casos devem aparecer como **Revisão necessária**. A demonstração encerra confirmando que a resposta é temporária e que o conjunto de treinamento permanece inalterado.
