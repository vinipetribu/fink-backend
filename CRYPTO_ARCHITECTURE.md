# FINK SecureAI Lab — Arquitetura criptográfica e contratos da API

**Estado:** as Etapas 1, 2, 3 e 4 foram concluídas e validadas para demonstração local. A arquitetura, o AES-256-GCM, a cifra didática e a esteganografia PNG estão documentados abaixo, com suas evidências e limitações. As Etapas 5 (ataques controlados) e 6 (detecção de anomalias com dados sintéticos) foram implementadas e validadas no Docker local, com as limitações registradas nas respectivas seções. A persistência de eventos e o dashboard permanecem futuros.  
**Escopo:** backend FINK existente, branch `secureai-lab`; textos financeiros fictícios em UTF-8.  
**Referência:** `../secureai_lab_projeto_2_especificacao.md` e diagnóstico do Projeto 1. Os contratos e limites abaixo registram decisões do projeto; não são todos exigências literais da professora.

## 1. Objetivo e fronteiras

A FINK continua sendo a aplicação principal. O módulo possui um fluxo de demonstração com AES-256-GCM da biblioteca `cryptography` e, em outra fronteira, uma cifra simétrica **didática, reversível e insegura**. A cifra experimental implementada demonstra XOR, substituição, permutação, confusão e difusão; seu desenho reversível em blocos está documentado na seção 4.4. Ela jamais protegerá dados reais ou substituirá o AES.

O fluxo inicial aceita apenas texto fictício, sem gravá-lo em movimentações, perfis ou outras entidades da FINK. Os endpoints do laboratório não são públicos. A implementação é um **laboratório local**, desabilitado por padrão e indisponível em produção, inclusive operações AES, pois as chaves são efêmeras. A escolha do AES-GCM para esse laboratório não implica que a gestão de chaves proposta seja adequada para produção.

A Etapa 4 acrescenta esteganografia PNG para envelopes AES já cifrados. O serviço AES valida a propriedade da chave antes de inserir ou entregar um envelope extraído; a chave precisa permanecer disponível em memória. As Etapas 5 e 6 acrescentaram os experimentos de ataque controlado e a detecção de anomalias sobre dados sintéticos. Persistência de eventos e interface continuam futuras.

## 2. Organização do módulo

```text
app/
  crypto_lab/
    __init__.py
    schemas.py          # contratos Pydantic e validação dos limites
    routes.py           # roteador FastAPI e dependências de autenticação
    aes_service.py      # cifra/decifra autenticada e tratamento de falhas
    key_store.py        # chaves, associação ao usuário, prazo e capacidade em memória
    envelope.py         # formato, serialização e AAD versionado
    toy_cipher.py       # cifra experimental, operações inversas e serviço isolado
    steganography.py    # codec PNG e quadro LSB
    middleware.py       # limites, disponibilidade e sanitização
    metrics.py          # contadores agregados efêmeros e allowlist de métricas
    errors.py           # erros internos e mapeamento seguro para a API
```

O roteador está registrado em `app/main.py`, sob `/api/v1/crypto-lab`. `app/api/deps.py` fornece `get_current_user` e `require_admin`; `app/core/settings.py` contém as configurações de habilitação e limites, sem chaves. O mecanismo de logs existente permanece separado, preservando seu esquema de quatro eventos e seu contrato. Os testes estão em `tests/`.

Separar os serviços AES e experimental impede a escolha acidental do algoritmo didático em fluxos de proteção. O middleware do laboratório aplica o limite de corpo HTTP **antes** do parsing e da validação JSON, inclusive quando `Content-Length` está ausente, e rejeita o fluxo ao ultrapassar o limite. As duas rotas de esteganografia têm limite próprio; os limites globais da FINK não foram alterados.

## 3. Gestão de chaves e nonce

### 3.1 Fluxo efêmero local implementado

1. Em cada `encrypt`, gerar **uma nova chave independente de 256 bits** com `AESGCM.generate_key(bit_length=256)` da `cryptography` e um `key_id` UUID aleatório independente, sem relação com o material da chave.
2. Criar também um nonce aleatório de 12 bytes com fonte criptograficamente segura. Cada chave é usada **uma única vez para cifrar**: ela é criada especificamente para aquela operação e nunca é oferecida novamente ao cifrador. A descriptografia pode ser repetida enquanto a chave existir. Isso evita reutilização do par chave/nonce por desenho; não depender de sorte ao gerar nonces sob uma chave reutilizada.
3. Guardar chave, `key_id`, UUID do proprietário, hora de criação e expiração em um repositório privado em memória, com acesso sincronizado. A chave é associada ao usuário autenticado no servidor, nunca a uma identidade enviada pelo cliente. O registro só fica disponível após a cifragem e o armazenamento serem bem-sucedidos; falhas limpam o estado parcial e não retornam envelope.
4. Para descriptografar, procurar o `key_id` **dentro do escopo do usuário autenticado**, validar prazo e usar a chave encontrada. Qualquer usuário, inclusive administrador, só recupera suas próprias chaves neste contrato. A posse do envelope ou de seu `key_id` não concede acesso.
5. Prazo fixo: **60 minutos após a criação**, sem renovação por acesso. Capacidade: **500 chaves por processo**. Remover registros expirados antes de admitir uma nova chave; se não houver vaga, recusar novas cifragens com 503, sem remover chave ainda válida silenciosamente. A limpeza também ocorre nas consultas; não há rotina periódica de limpeza. Rotação equivale a gerar uma chave nova por cifragem; chaves existentes ficam disponíveis somente até seu próprio vencimento.
6. Não persistir chave em banco, arquivo, cache externo, variável de ambiente, payload ou resposta. Reinício, encerramento ou falha do processo apaga as chaves: **os envelopes tornam-se irrecuperáveis**. A implementação não deverá prometer apagamento seguro da memória: Python, bibliotecas, dump de memória e sistema operacional podem manter cópias. Desabilitar dumps em ambientes de demonstração quando viável e restringir acesso ao processo.

A demonstração exige **uma única instância e um único worker**: repositórios em memória de processos diferentes são independentes. O laboratório deve falhar fechado se uma configuração explicitamente conhecida indicar múltiplos workers/instâncias; essa verificação não pode garantir detecção de toda topologia externa, que deve ser validada operacionalmente. Autoscaling, balanceamento e reinício tornam a recuperação não confiável. Nunca usar essa arquitetura para dados reais nem apresentá-la como solução de produção. Uma futura alternativa durável exige decisão própria sobre armazenamento protegido, acesso, backup, recuperação, rotação, auditoria e risco de comprometimento — não basta gravar a chave junto ao ciphertext.

### 3.2 Envelope e integridade

Envelope `v1`, codificado em JSON: `version`, `algorithm`, `key_id`, `nonce`, `ciphertext`. `nonce` e `ciphertext` são **Base64 padrão canônico com padding**; `ciphertext` contém os bytes cifrados seguidos da tag GCM de 16 bytes retornada por `AESGCM.encrypt`. O nonce não é segredo e deve acompanhar o envelope, mas não será gravado em logs ou consultas de métricas. A saída JSON não será embutida em logs; protegê-la em trânsito e na aplicação cliente.

O AAD é formado internamente por codificação inequívoca e versionada dos campos `version`, `algorithm`, `key_id` e UUID do usuário autenticado, com campos UTF-8 de comprimentos prefixados e prefixo fixo `FINK-CRYPTO-V1`. A regra binária exata implementada e testada está descrita na seção 8. O nonce é verificado implicitamente pelo GCM. Na recuperação, reconstruir o AAD a partir do envelope validado e da identidade autenticada, nunca de um `user_id` fornecido pelo cliente. O formato e o AAD têm testes e não podem mudar em silêncio: mudanças incompatíveis exigem nova versão.

A alteração de ciphertext, tag, nonce ou metadados autenticados deve impedir a recuperação. Não reutilizar nonce/chave em uso real. Experimentos que controlem nonce terão harness exclusivo e isolado, sem conexão com chaves ou operações reais.

### 3.3 Segredos e observabilidade

Nunca registrar ou retornar chaves AES. Não registrar plaintext, conteúdo do envelope, ciphertext, tag, nonce, tokens, credenciais ou a chave didática. Sem corpos HTTP em logs, traces, erros, auditoria, proxy ou APM; cabeçalhos de autenticação também devem ser omitidos. Não usar exceções Pydantic padrão que devolvam `input` contendo plaintext/envelope: sanitizar respostas 422 e logs **apenas das novas rotas**. Erros internos e stack traces não vão para o cliente; exceções não devem incluir dados recebidos. Debug e ferramentas de captura de corpo devem estar desativados na demonstração.

A resposta de cifragem inclui o envelope por necessidade do contrato; a de descriptografia inclui o texto solicitado. Portanto, respostas são sensíveis mesmo com dados fictícios. Todas as respostas das rotas usarão `Cache-Control: no-store`; transporte autenticado deve usar TLS fora de localhost. O uso do token Bearer em `localStorage` é uma limitação existente e não é resolvido nesta etapa.

## 4. Contratos da API

### 4.1 Convenções e limites

- Prefixo `/api/v1/crypto-lab`; `Content-Type: application/json`; autenticação `Authorization: Bearer <token>`.
- Modelos Pydantic v2 com `extra='forbid'`, tipos estritos e sem coerção silenciosa. Validar o tamanho em **bytes UTF-8**, não apenas caracteres; não normalizar, remover espaços ou alterar o texto. Texto vazio é inválido; espaços isolados são aceitos e preservados. Não há dados reais nesta demonstração.
- Até **4.096 bytes UTF-8** de texto, calculados após decodificação JSON. Máximo do corpo HTTP para as rotas AES e didática: **16.384 bytes**, contado nos bytes recebidos antes do parsing; as rotas de esteganografia têm limite próprio, descrito na Etapa 4. Esse teto também se aplica a JSON com escapes; corpo maior retorna 413, mesmo que o texto resultante seja menor. Codificação UTF-8 inválida retorna 400.
- Base64 deve ser canônico, sem espaços nem quebras, com padding correto. O nonce decodificado tem exatamente 12 bytes (`16` caracteres); ciphertext+tag tem de **17 a 4.112 bytes**, ou seja, texto não vazio até 4.096 bytes e tag de 16 bytes; sua representação Base64 tem no máximo **5.484 caracteres**. `key_id` e `operation_id` são UUIDs válidos e serializados em formato textual padrão.
- Respostas de erro JSON têm a forma `{"detail":"mensagem genérica"}`. 401 inclui `WWW-Authenticate: Bearer`, seguindo o padrão existente. 400, 413, 422 e 503 não refletem dados de entrada. `Cache-Control: no-store` também é aplicado a erros.
- 400: JSON/UTF-8 malformado ou envelope impossível de recuperar; 401: sessão ausente/inválida; 403: usuário sem privilégio; 413: corpo além do limite; 422: esquema ou campo inválido; 503: laboratório desabilitado ou capacidade esgotada. 500: erro inesperado com mensagem genérica. No caso de produção, as rotas não devem ser registradas, retornando 404. Falhas de `key_id` inexistente, expirado ou pertencente a outro usuário e falha de autenticação GCM são **indistinguíveis: 400 `Não foi possível descriptografar o payload`**. O cliente não pode distinguir qual causa ocorreu.
- Um envelope sintaticamente inválido gera 422; um envelope estruturalmente válido com bytes adulterados ou dados de autenticação inválidos gera 400 genérico. Não expor detalhes de decodificação ou da biblioteca.

### 4.2 Cifrar texto

`POST /api/v1/crypto-lab/encrypt` — usuário autenticado (`get_current_user`), somente laboratório habilitado.

**Pydantic:** `EncryptRequest(text: str)`; `EncryptResponse(operation_id: UUID, envelope: CryptoEnvelope)`.

```json
{"text":"Compra fictícia no mercado: R$ 42,00"}
```

Resposta **200** (valores ilustrativos; não são um vetor criptográfico):

```json
{
  "operation_id": "3493126e-28d3-4aaa-9543-01e12607b900",
  "envelope": {
    "version": 1,
    "algorithm": "AES-256-GCM",
    "key_id": "00ac635a-67f2-4aa6-8c74-718c71f4d7b9",
    "nonce": "AAECAwQFBgcICQoL",
    "ciphertext": "AAAAAAAAAAAAAAAAAAAAAAAA"
  }
}
```

`CryptoEnvelope` tem `version: Literal[1]`, `algorithm: Literal["AES-256-GCM"]`, `key_id: UUID`, `nonce: str`, `ciphertext: str`. Campos acima são obrigatórios e seguem os limites da seção 4.1. Não retornar chave, fingerprint de chave ou material que permita reconstruí-la. O `operation_id` aleatório identifica somente a operação e não autoriza acesso. Não garante recuperação da chave.

### 4.3 Descriptografar envelope

`POST /api/v1/crypto-lab/decrypt` — usuário autenticado, somente laboratório habilitado.

**Pydantic:** `DecryptRequest(envelope: CryptoEnvelope)`; `DecryptResponse(operation_id: UUID, text: str)`. Enviar o objeto `envelope` integral retornado pela cifragem. Retorno **200** com `operation_id` novo e `text` original. Não expor plaintext parcialmente se a autenticação falhar ou os bytes recuperados não forem UTF-8 válido; tratar ambos como falha genérica 400. Não retornar a chave.

### 4.4 Cifra experimental isolada — implementação da Etapa 3

`POST /api/v1/crypto-lab/experimental/run` — acesso restrito a ADMIN, em ambiente de desenvolvimento/teste/local, apenas com `CRYPTO_LAB_ENABLED=true` e `CRYPTO_LAB_EXPERIMENTAL_ENABLED=true` (ambas desabilitadas por padrão); `DEBUG=false`, worker e instância únicos. As rotas do laboratório não são registradas em produção. Não usar dados reais.

A proposta anterior previa `toy_key` de 16 bits fornecida pelo cliente. **A implementação foi alterada:** a chave de 16 bits é gerada dinamicamente no servidor em cada cifragem e não é retornada. Um `key_id` UUID é retornado para recuperar a chave temporária; ela fica em um repositório separado do AES, associado ao administrador que cifrou, com expiração de 60 minutos, capacidade máxima de 500 chaves válidas e perda no reinício. Como o espaço é de apenas 65.536 chaves, colisões são possíveis e esperadas em volume suficiente. A chave didática é fraca mesmo usando uma fonte aleatória segura.

Cifrar (texto fictício de 1 a 4.096 bytes UTF-8):

```json
{"action":"encrypt","text":"Compra fictícia de café"}
```

Retorno HTTP 200: `operation_id`, `algorithm` igual a `TOY-V1-INSECURE`, `key_id`, `ciphertext` em Base64 canônico e `warning` com aviso de insegurança. Guardar o `key_id` e o `ciphertext` para a demonstração, sem registrar seus valores em logs. A chave em si não aparece na resposta.

Descriptografar usando os valores recebidos, com a **mesma conta ADMIN**:

```json
{"action":"decrypt","key_id":"UUID-RETORNADO","ciphertext":"BASE64-RETORNADO"}
```

Retorno HTTP 200: `operation_id`, `algorithm`, `text` e `warning`. Os campos extras são rejeitados. O ciphertext deve ter entre 8 e 4.104 bytes decodificados, ser múltiplo de 8 e estar em Base64 canônico de até 5.472 caracteres. Usuário não autenticado recebe 401; sem privilégio recebe 403; flag desabilitada recebe 503; formato inválido recebe 422 sanitizado; chave inexistente, expirada ou de outro usuário e falha de padding/UTF-8 recebem 400 genérico. Todas as respostas passam pelo middleware de `no-store` e sanitização já existente.

**Algoritmo didático:** texto UTF-8, padding PKCS#7 com blocos de 8 bytes; cada bloco é processado independentemente em quatro rodadas. Em cada rodada: (1) XOR com 8 bytes derivados da chave de 2 bytes e do número da rodada por SHA-256; (2) substituição reversível dos dois nibbles de cada byte pela S-box `(12,5,6,11,9,0,10,13,3,14,15,8,4,7,1,2)`; (3) permutação das posições de bytes `(2,5,0,7,4,1,6,3)`; (4) mistura cumulativa por XOR, em que cada byte a partir do segundo é combinado com o resultado anterior. A descriptografia inverte essas operações em ordem e remove o padding validado. A substituição e a dependência da chave ilustram confusão; a permutação e a mistura entre posições ilustram difusão. Os testes observam propriedades específicas, sem reivindicar avalanche ideal.

**Não é criptografia segura:** chave de 16 bits é exaustivamente pequena; blocos idênticos sob a mesma chave produzem blocos cifrados idênticos, revelando padrões; a cifra não usa nonce nem autenticação. Chave errada ou ciphertext adulterado podem produzir saída com padding e UTF-8 válidos sem aviso. Regras de tamanho e padding não garantem integridade. Não empregar em dados da FINK nem dados sensíveis. SHA-256 no escalonamento não aumenta a entropia dos 16 bits nem transforma a cifra em segura.

O armazenamento e o semáforo de até 10 operações simultâneas são separados dos do AES; o resumo administrativo compartilha apenas os contadores agregados `experimental_success` e `experimental_failure`. Não registrar plaintext, chave, ciphertext ou token. Requisições rejeitadas por autenticação, validação, flag e capacidade não são contadas como falhas criptográficas.

### 4.5 Informações não sensíveis

`GET /api/v1/crypto-lab/operations/summary` — **somente ADMIN**, laboratório habilitado. Resposta 200, `OperationsSummaryResponse`:

```json
{
  "scope": "current_process",
  "since": "2026-11-15T12:00:00Z",
  "counts": {
    "aes_encrypt_success": 0,
    "aes_decrypt_success": 0,
    "aes_decrypt_failure": 0,
    "experimental_success": 0,
    "experimental_failure": 0
  }
}
```

`scope: Literal["current_process"]`; `since: datetime` UTC da inicialização; contadores inteiros não negativos, simultaneamente seguros, sem segmentação por usuário, sem payload, conteúdo, chaves, nonce ou identificadores de operação. Eles são zerados no reinício e não equivalem a logs persistentes nem a processamento de Big Data. Requisições rejeitadas por autenticação/autorização continuam tratadas pelo logger existente, não por esses contadores. Não oferecer consulta individual por ID nesta versão; `operation_id` é apenas correlação efêmera para a resposta e não é armazenado neste resumo.

## 5. Integração e regras de segurança

- Usar `get_current_user` no AES e `require_admin` nas rotas experimentais e no resumo. A verificação de proprietário da chave ocorre dentro do serviço mesmo para administrador. O frontend pode ocultar telas, mas não é a barreira de autorização.
- Preservar login, sessões, Argon2id, CSV, pessoas, logs e demais rotas. Não reaproveitar hashes de senhas ou tokens como chaves AES. Não substituir nem quebrar o endpoint atual `/api/v1/security-logs`.
- O router deve ser opcional e falhar fechado: configuração específica desligada por padrão; em produção, não registrar rotas. Limitar corpo, tamanho, duração e concorrência das operações; os limites de concorrência e os mecanismos de recusa implementados são descritos nas seções 4.4, 8 e Etapa 4. Não iniciar tarefas de força bruta no endpoint da cifra; esses experimentos terão contrato próprio, limites e isolamento em etapa posterior.
- A especificação de texto fictício é regra de uso: o servidor não consegue comprovar que o usuário não digitou dados reais. A interface deverá sinalizar isso quando existir.
- O retorno de erros precisa manter autenticação e controle de acesso mesmo quando houver dados inválidos; a implementação deve testar a ordem real de validação do FastAPI, evitando que respostas exponham campos antes da autorização.

## 6. Plano histórico de testes

Este plano foi elaborado antes da implementação. As validações efetivamente executadas nas Etapas 2, 3 e 4 estão registradas nas respectivas seções de validação; itens abaixo descrevem o plano original e não afirmam, isoladamente, que cada cenário foi executado. Usar chaves e textos fictícios, com armazenamento e relógio controlados, sem dependência de serviços externos.

1. **AES:** round-trip com acentos, caracteres multibyte, espaços e limite de 4.096 bytes; vetor conhecido AES-256-GCM da biblioteca/padrão, incluindo tag e AAD; comparação byte a byte sem normalização.
2. **Chaves:** duas cifragens geram chaves e identificadores independentes, mesmo para texto igual. Mockar a busca para retornar chave errada e confirmar erro genérico sem plaintext. Testar expiração, reinício simulado, capacidade esgotada, ausência de remoção antecipada e isolamento por usuário.
3. **Adulteração:** modificar separadamente ciphertext, tag, nonce e metadados autenticados; a recuperação deve falhar com 400 genérico. IDs inexistentes, expirados e de outro usuário têm a mesma resposta. Estrutura malformada recebe 422 sanitizado.
4. **Nonce e concorrência:** cada chave é usada para cifrar exatamente uma vez; nonce tem 12 bytes e vem da fonte segura. Testar chamadas concorrentes e controle atômico do repositório; forçar falhas de geração/armazenamento e colisões de ID para garantir ausência de estado parcial. Não provar unicidade criptográfica apenas comparando algumas amostras aleatórias.
5. **Autorização e ambiente:** anônimo 401; USER pode usar AES e só sua própria chave; USER em rotas administrativas 403; ADMIN pode acessar resumo e sua própria chave; flags desligadas bloqueiam rotas; produção retorna 404. Cobrir falhas com dados malformados, múltiplos workers detectados e condição de capacidade.
6. **Validação:** corpo exato no limite e acima dele, inclusive sem `Content-Length`; UTF-8 inválido, texto vazio, multibyte acima do limite, campos extras, tipos incorretos, UUID inválido, algoritmo/versão desconhecidos, Base64 não canônico, nonce e tag fora do tamanho; dados de entrada nunca aparecem em erro 422.
7. **Exposição:** inspecionar respostas, headers, logs capturados, métricas e exceções de sucesso/erro; provar que não há chave AES, chave didática, texto, token, nonce ou envelope em logs e resumo; respostas só retornam os campos previstos. Verificar `no-store` inclusive em erros.
8. **Experimental:** round-trip e reversibilidade das transformações, limites, aviso obrigatório, restrições de ambiente e permissões. Documentar que adulteração ou chave errada podem não ser detectadas.
9. **Regressão:** executar a suíte existente de senhas, autenticação/autorização, logs, CSV, IA e health; atualizar somente expectativas de inventário de rotas quando a implementação exigir, preservando a matriz de acesso. Fazer testes de integração com o frontend quando houver interface.

## 7. Questões históricas levantadas antes da implementação

Os itens abaixo preservam as decisões e pendências levantadas na Etapa 1. As decisões de escopo local, limites e gestão efêmera foram aprovadas e implementadas; as seções de implementação registram os detalhes. A confirmação dos critérios específicos com a professora e uma eventual arquitetura durável permanecem questões distintas.

1. Aprovar o **prazo de 60 minutos**, limite de **500 chaves por processo**, recusa quando cheio e perda irrecuperável no reinício; confirmar se uma demonstração exclusivamente local, com um worker, é suficiente.
2. Aprovar laboratório desabilitado por padrão e ausente em produção, inclusive AES, e se ADMIN deve ser o único perfil autorizado para a cifra experimental e métricas.
3. Aprovar limite de **4.096 bytes UTF-8** para texto e **16.384 bytes** para o corpo HTTP, além das regras de erro e do formato versionado do envelope.
4. Definir antes de programar os limites de concorrência e tempo, a configuração de execução de worker único e a codificação binária definitiva do AAD; a validação de implantação deve assumir que o código não detecta toda topologia externa.
5. Confirmar com a professora se é esperada uma cifra própria e quais critérios de XOR, substituição, permutação e blocos ela avaliará. Desenhar e revisar o algoritmo experimental antes de implementá-lo.
6. Caso a demonstração precise sobreviver a reinícios ou funcionar em múltiplos processos, revisar integralmente a gestão de chaves; não adicionar persistência de segredos por conveniência sem uma decisão de segurança específica.


## 8. Implementação da Etapa 2 e diferenças

- O módulo AES e os três endpoints foram adicionados. Na Etapa 2, a cifra experimental, seu endpoint, os ataques e a esteganografia ainda não estavam implementados. A Etapa 3 implementou a cifra experimental e seus contadores; a Etapa 4 implementou a esteganografia. Os ataques foram implementados posteriormente na Etapa 5.
- O AAD v1 é exatamente o prefixo ASCII `FINK-CRYPTO-V1` seguido de quatro campos UTF-8 nesta ordem: versão decimal (`1`), algoritmo (`AES-256-GCM`), UUID canônico da chave e UUID canônico do usuário. Cada campo é precedido por seu comprimento em bytes como inteiro sem sinal de 4 bytes, big-endian.
- O limite concorrente é de **10 operações AES por processo**, adquirido sem espera; capacidade ocupada retorna 503. O serviço executa cifragem e descriptografia em thread pool. Não foi definido timeout: as entradas são limitadas, mas a duração de execução não é garantida.
- `CRYPTO_LAB_ENABLED` é `false` por padrão. Para execução, usar `ENVIRONMENT=development`, `DEBUG=false`, `CRYPTO_LAB_ENABLED=true`, `CRYPTO_LAB_WORKERS=1`, `CRYPTO_LAB_INSTANCES=1`. O laboratório aceita ambientes `development`, `test`, `testing` ou `local`; não registra rotas se iniciado em `production`. Debug habilitado, declaração diferente de uma instância/worker ou `WEB_CONCURRENCY`, `UVICORN_WORKERS`, `--workers`/`-w` e `GUNICORN_CMD_ARGS` incompatíveis fazem as requisições falharem com 503. Isso não detecta toda topologia externa; a implantação deve garantir um único processo e instância. O processo deve ser reiniciado após qualquer alteração de ambiente.
- A sanitização de erro 422 e o limite de corpo são aplicados somente ao prefixo do laboratório, antes do parsing. JSON/UTF-8 inválido e corpo acima do limite são recusados antes da autenticação; respostas não incluem os dados recebidos.
- As chaves expiram 3.600 segundos após inserção no repositório por relógio monotônico. A limpeza acontece nas próximas inserções e consultas, não por tarefa periódica; nenhuma chave válida é removida para abrir espaço. O armazenamento é por processo e a expiração elimina a possibilidade de recuperar o texto.
- `cryptography` foi declarado diretamente no `pyproject.toml`. Historicamente, o `poetry.lock` ainda precisava ser atualizado naquele momento; posteriormente foi atualizado e passou a conter `cryptography` 46.0.7, conforme registrado na validação da Etapa 2.
- O código trata erros inesperados na fronteira ASGI sem registrar seu conteúdo. Isso não controla logs de infraestrutura, proxy, APM, dumps de memória ou depuradores externos. Não colocar dados sensíveis em URLs nem habilitar captura de corpos.
- As validações HTTP e de regressão das Etapas 2, 3 e 4 estão registradas nas respectivas seções abaixo.

## Validação da Etapa 2 — AES-256-GCM

### Resultados observados

A suíte automatizada completa foi executada em um contêiner Docker a partir da imagem `fink-backend-api`, **sem montagem do código local**. O resultado registrado foi **116 testes aprovados, 0 falhas e cobertura geral de 67%**; foram exibidos 11 avisos. A suíte executada inclui testes do módulo criptográfico e testes de funcionalidades anteriores da FINK. A cobertura geral descreve a execução registrada e não comprova ausência de vulnerabilidades. O código testado era o contido na imagem, que pode diferir de alterações locais feitas após seu build.

O teste HTTP de ponta a ponta foi executado com `scripts/crypto_http_smoke.py`, usando duas contas fictícias, contra uma instância local da API com o Crypto Lab habilitado. Os resultados relatados foram:

| Cenário | Resultado esperado | Resultado observado |
|---|---|---|
| Suíte automatizada | Todos os testes aprovados | 116 aprovados, 0 falhas; cobertura geral de 67% |
| Criptografia autenticada | HTTP 200 | HTTP 200 |
| Descriptografia pelo mesmo usuário | HTTP 200 e texto idêntico | HTTP 200; texto recuperado idêntico |
| Requisição sem autenticação | HTTP 401 | HTTP 401 |
| Envelope adulterado | HTTP 400 | HTTP 400 |
| Descriptografia por outro usuário | HTTP 400 | HTTP 400 |
| Cache nas respostas HTTP testadas | `Cache-Control: no-store` | `Cache-Control: no-store` nas respostas testadas |
| Valores sensíveis nos logs inspecionados | Nenhum dos valores verificados encontrado | Nenhum dos valores verificados apareceu nos logs inspecionados |

A verificação de logs examinou a saída capturada do contêiner de teste para a mensagem fictícia, senha fictícia, dois tokens, nonce e ciphertext daquele teste. Ela não comprova ausência de dados sensíveis em todos os logs, em outros períodos ou em componentes externos.

### Reprodução dos testes automatizados

A imagem da API não traz `pytest` por padrão. Na execução observada, usou-se um contêiner descartável criado diretamente da imagem, sem montar o diretório local. As versões efetivamente instaladas naquela execução foram `pytest==9.2.0`, `pytest-asyncio==1.5.0`, `pytest-cov==7.1.0`, `coverage==7.17.3`, `iniconfig==2.3.1`, `pluggy==1.7.0` e `pygments==2.21.0`; `packaging==26.3` e `typing-extensions==4.15.0` já estavam presentes. Para tentar reproduzir com essas versões explícitas, com Docker e acesso ao repositório de pacotes disponíveis:

```bash
docker run --rm --entrypoint sh fink-backend-api -lc \
  'pip install pytest==9.2.0 pytest-asyncio==1.5.0 pytest-cov==7.1.0 coverage==7.17.3 iniconfig==2.3.1 pluggy==1.7.0 pygments==2.21.0 packaging==26.3 typing-extensions==4.15.0 && python -m pytest -p no:cacheprovider'
```

A instalação ocorre somente no contêiner descartável, não no Mac nem na imagem original. O comando não monta o código local nem instala Poetry no Mac. Para comparar com o resultado anterior, é necessário usar a mesma imagem e dependências de base; a tag `fink-backend-api` pode ser reconstruída ou apontar para outra imagem, e o identificador imutável da imagem usada não foi registrado. Portanto, fixar essas versões não garante reprodução integral. Alterações locais posteriores só serão testadas se forem incluídas em uma imagem apropriada antes da execução. Não assumir que uma nova execução produzirá exatamente os mesmos resultados.

### Reprodução do teste HTTP local

O teste observado usou o PostgreSQL existente e uma instância separada da API em `127.0.0.1:18000`, com um worker e `--lifespan off`. Essa opção evita executar o seed de desenvolvimento, que recria a conta demo e seus dados relacionados. O banco de desenvolvimento precisa estar disponível e já possuir as tabelas necessárias. A instância depende da imagem local da API e das configurações do Compose; não usa o ambiente de produção.

Na raiz do backend:

```bash
docker compose up -d postgres
docker compose ps postgres
```

Após o serviço estar saudável, se não houver outro contêiner com o mesmo nome nem serviço na porta 18000, iniciar a API de teste:

```bash
docker compose run -d --no-deps \
  --name fink-crypto-http-local \
  --entrypoint python \
  -p 127.0.0.1:18000:8000 \
  -e ENVIRONMENT=development \
  -e DEBUG=false \
  -e CRYPTO_LAB_ENABLED=true \
  -e CRYPTO_LAB_WORKERS=1 \
  -e CRYPTO_LAB_INSTANCES=1 \
  api -m uvicorn app.main:app \
  --host 0.0.0.0 --port 8000 --workers 1 --lifespan off
```

```bash
curl -i http://127.0.0.1:18000/health
python3 scripts/crypto_http_smoke.py
```

O script cria **duas novas contas fictícias e sessões no banco de desenvolvimento a cada execução**; elas permanecem no banco. Ele não deve ser executado contra dados reais ou em produção. Após o teste, para apenas parar essa instância sem apagar volumes:

```bash
docker stop fink-crypto-http-local
```

### Limitações e atualização do registro anterior

- A validação ocorreu apenas em ambiente local de desenvolvimento; os testes não substituem auditoria de segurança.
- As chaves são temporárias, armazenadas na memória do processo. O reinício elimina as chaves e impede recuperar os respectivos textos cifrados.
- O teste HTTP criou duas contas fictícias no banco de desenvolvimento. A inspeção de logs foi limitada ao contêiner e aos valores verificados naquela execução.
- A seção 8 registra uma situação anterior em que o `poetry.lock` ainda precisava ser atualizado. No estado atual do arquivo local, o lockfile já contém `cryptography` 46.0.7; este registro não afirma que a imagem usada nos testes corresponda ao lockfile ou à árvore de trabalho atuais.


## Demonstração e validação da Etapa 3

Para testar por HTTP, usar uma instância de desenvolvimento isolada, banco de teste já preparado e uma conta ADMIN fictícia existente. Além das configurações locais documentadas na validação da Etapa 2, adicionar `-e CRYPTO_LAB_EXPERIMENTAL_ENABLED=true` ao comando `docker compose run` e manter `--lifespan off` para evitar que o seed recrie dados demo. Usar um único worker. No Swagger em `http://127.0.0.1:18000/docs`, autenticar com o Bearer da conta ADMIN fictícia, abrir `POST /api/v1/crypto-lab/experimental/run`, enviar o JSON de cifragem da seção 4.4 e então enviar o JSON de descriptografia com o `key_id` e ciphertext retornados. Não compartilhar token, conteúdo ou chave em capturas. Os resultados são efêmeros: ao reiniciar o contêiner, as chaves são perdidas.

Os testes novos são `tests/test_toy_cipher_unit.py` (propriedades e serviço) e `tests/test_toy_cipher_api.py` (API e isolamento). `python3 -m unittest tests.test_toy_cipher_unit -v` executa a parte sem dependências adicionais no Python local. Para a suíte completa em Docker sem montar o diretório local, primeiro criar uma imagem que inclua estas alterações; executar o procedimento de versões fixas da seção de validação da Etapa 2. Uma tag antiga não testa o código atual. Os resultados HTTP e de regressão efetivamente observados para a Etapa 3 constam na seção de validação seguinte.

## Validação da Etapa 3 — Cifra Didática

A validação registrada nesta seção foi realizada em ambiente local de desenvolvimento. O build Docker da API foi concluído, e a suíte completa executada na imagem reconstruída, sem montagem do código local, apresentou **143 testes aprovados, 0 falhas e cobertura geral de 70%**. O identificador informado para a imagem utilizada no teste HTTP foi `sha256:db88205697d4decd6eafbd3f103ed0671073d3b941d76d4674296ae7e923143b`.

O script `scripts/toy_cipher_http_smoke.py` executou **11 cenários HTTP, todos aprovados**, usando a aplicação e contas fictícias. Os resultados observados estão abaixo:

| Cenário | Resultado esperado | Resultado observado |
|---|---|---|
| Suíte automatizada | Testes aprovados sem falhas | 143 aprovados, 0 falhas; cobertura geral de 70% |
| AES antes da cifra didática | Cifrar e recuperar o texto | Cifragem e recuperação aprovadas |
| Flags omitidas | Endpoint desabilitado | HTTP 503 |
| Apenas a flag geral habilitada | Endpoint desabilitado | HTTP 503 |
| Apenas a flag experimental habilitada | Endpoint desabilitado | HTTP 503 |
| Requisição anônima | Acesso rejeitado | HTTP 401 |
| USER autenticado | Acesso rejeitado | HTTP 403 |
| ADMIN com ambas as flags | Cifragem realizada | HTTP 200 |
| Reversibilidade da cifra didática | Recuperar o texto original | HTTP 200; texto idêntico |
| AES após a cifra didática | Recuperar o mesmo envelope gerado antes | Mesmo envelope recuperado |
| Valores sensíveis nos logs inspecionados | Nenhum dos valores verificados encontrado | Texto fictício, credenciais e ciphertext verificados ausentes |
| Campos explícitos de chave nos logs inspecionados | Nenhum campo explícito encontrado | Nenhum campo explícito encontrado; valor interno não verificável diretamente via HTTP |

A verificação de logs cobriu os valores e contêineres inspecionados pelo script. **Não foi possível verificar diretamente, via HTTP, a ausência do valor interno da chave didática nos logs**, pois a API não o disponibiliza ao cliente. O resultado também não comprova ausência de dados sensíveis em outros logs ou componentes.

A cifra é de **uso exclusivo em laboratório** e trabalha com chave didática de **16 bits**. Ela é deliberadamente vulnerável: seu espaço de chaves é pequeno, blocos iguais podem revelar padrões e não existe autenticação do conteúdo cifrado. Os testes demonstram o comportamento observado e não constituem auditoria de segurança nem prova de segurança criptográfica.

O teste HTTP criou duas contas fictícias e sessões no banco de desenvolvimento. Uma conta recebeu privilégio ADMIN temporariamente e foi rebaixada para USER ao final; **as contas e sessões permanecem no banco**. As instâncias de teste usam chaves em memória, que são perdidas quando o processo é encerrado ou reiniciado.

### Comandos utilizados

Na raiz do backend, o build e a suíte automatizada foram executados com:

```bash
docker compose build api
```

```bash
docker run --rm --entrypoint sh fink-backend-api -lc 'pip install pytest==9.2.0 pytest-asyncio==1.5.0 pytest-cov==7.1.0 && python -m pytest -p no:cacheprovider -q'
```

O segundo comando instala os três pacotes de teste com versões fixadas em um contêiner descartável; suas dependências transitivas podem variar. Ele usa o código contido na imagem, sem montar o diretório local. Para repetir uma validação equivalente, é necessário garantir que a tag corresponda à imagem esperada; reconstruí-la pode mudar seu identificador e suas dependências.

Para o teste HTTP observado, o PostgreSQL de desenvolvimento foi iniciado e o script executado com:

```bash
docker compose up -d postgres
python3 scripts/toy_cipher_http_smoke.py
```

O script cria instâncias temporárias locais para verificar as combinações de flags e usa `--lifespan off`, evitando o seed de desenvolvimento. A execução requer a imagem da API correspondente ao código local, Docker disponível e um banco de desenvolvimento já preparado; cada nova execução cria outras contas fictícias e sessões. Não usar em produção nem com dados reais.

Os resultados da validação da Etapa 3 referem-se à imagem e às execuções observadas, não a alterações posteriores.


## Etapa 4 — Esteganografia PNG LSB

**Estado:** implementada e validada para demonstração local por testes automatizados e HTTP, conforme o registro de validação abaixo. A cifra experimental permanece separada e os contratos AES existentes não mudam.

### Fluxo e endpoints

1. Usar `POST /api/v1/crypto-lab/encrypt` com texto fictício e guardar temporariamente o envelope AES retornado.
2. `POST /api/v1/crypto-lab/steganography/embed` aceita JSON `{"image_png":"BASE64_PNG","envelope":{...}}`, com Base64 padrão canônico e o envelope AES completo. Exige Bearer e `CRYPTO_LAB_ENABLED=true`. A resposta HTTP 200 é `{"image_png":"BASE64_PNG_MODIFICADO"}`.
3. `POST /api/v1/crypto-lab/steganography/extract` aceita `{"image_png":"BASE64_PNG_MODIFICADO"}` e retorna HTTP 200 com `{"envelope":{...}}`. O cliente pode passar esse objeto para `/api/v1/crypto-lab/decrypt` com o mesmo usuário. Não são retornadas chaves.

Ambos exigem usuário autenticado e estão sujeitos aos controles já existentes do laboratório, incluindo ambiente local, flag geral, debug desabilitado e não registro em produção. Antes de inserir e antes de retornar um envelope extraído, o serviço AES verifica a tag GCM e a propriedade da chave do usuário; o texto resultante dessa verificação não é devolvido pela esteganografia nem registrado. A verificação usa `CryptoService.decrypt` e, portanto, atualiza os contadores de descriptografia AES existentes. Outro usuário, chave expirada/inexistente, tag inválida, imagem ou estrutura inválida resultam em HTTP 400 genérico; dados de esquema/Base64 inválidos retornam 422 sanitizado; anônimo recebe 401; corpo excessivo recebe 413; capacidade de execução cheia recebe 503. Respostas do laboratório têm `Cache-Control: no-store`. Duas operações de esteganografia podem executar simultaneamente por processo; o limite AES também continua em vigor.

### Técnica, formato e limites

Aceita PNG estático de cor verdadeira RGB (tipo PNG 2) ou RGBA (tipo 6), com profundidade 8 ou 16 bits, entrelaçado ou não. Cada dimensão é limitada a 256 pixels (até 65.536 pixels), o PNG de entrada e de saída a 1.048.576 bytes e o corpo JSON das duas rotas a 1.420.000 bytes; o limite anterior de 16.384 bytes permanece nas demais rotas. PNG animado e transparência `tRNS` são rejeitados. A saída é PNG não entrelaçado; metadados e outros chunks auxiliares são removidos. PNGs malformados, CRC inválido, formatos de cor não suportados, tamanho excessivo e dados comprimidos incompatíveis são rejeitados. O codec usa apenas a biblioteca padrão Python, sem acrescentar dependência ou modificar o lockfile.

O envelope AES é serializado em JSON UTF-8 e encapsulado como `FSL1` (4 bytes), comprimento do JSON (4 bytes, inteiro sem sinal big-endian), SHA-256 do JSON (32 bytes) e JSON (1 a 8.192 bytes). Os bits são inseridos sequencialmente, do bit mais significativo para o menos significativo de cada byte do quadro, no bit menos significativo dos canais R, G e B dos pixels em ordem de leitura. Em canais de 16 bits, altera-se o bit menos significativo do byte menos significativo de cada canal. O canal alfa é preservado integralmente. Capacidade: `floor(largura * altura * 3 / 8) - 40` bytes para o JSON; a inserção falha se o envelope completo não couber. A extração valida identificador, comprimento, capacidade e checksum antes de validar o esquema e autenticar com AES-GCM.

O SHA-256 do quadro **não é autenticado** e apenas ajuda a detectar corrupção estrutural acidental; um atacante pode recalculá-lo. A integridade e confidencialidade do envelope dependem de AES-GCM e da gestão de chaves. Esteganografia não substitui criptografia: LSB pode ser detectada, e regravação com perda, redimensionamento, recorte ou filtros podem destruir o conteúdo. O PNG produzido não deve ser usado para dados reais ou sensíveis.

### Testes da Etapa 4

Foram acrescentados testes locais do codec, integração com AES e testes HTTP de autorização, limites, isolamento e regressão. A suíte completa em Docker e os testes HTTP foram executados; os resultados estão na seção de validação seguinte. Para uma nova execução sem montagem do código local, reconstruir a imagem com as alterações desejadas e usar o procedimento documentado abaixo.

## Validação da Etapa 4 — Esteganografia PNG

A validação foi realizada em ambiente local de desenvolvimento. Na suíte completa executada na imagem Docker reconstruída, sem montagem do projeto local, foram observados **158 testes aprovados, 0 falhas e 1 teste ignorado**, com **72% de cobertura geral** e **89% de cobertura do módulo `app/crypto_lab/steganography.py`**. O teste ignorado na suíte foi o de compatibilidade opcional com Pillow; ele foi executado separadamente com sucesso.

A imagem informada para a validação HTTP foi `sha256:f58fe90e8a9903b302f4aa96f3c3cb1daff8b9360d2f467fa51f2afb804a60c5`.

O script `scripts/steganography_http_smoke.py` apresentou **22 cenários HTTP aprovados**. Os fluxos RGB e RGBA inseriram e recuperaram o envelope AES, com recuperação de mensagem idêntica e preservação do canal alfa. O teste rejeitou PNG inválido, dimensão acima do limite, capacidade insuficiente e adulteração do conteúdo oculto. Também rejeitou acesso anônimo e extração por usuário diferente do proprietário. O AES-256-GCM e a cifra didática funcionaram antes e depois da esteganografia; as respostas HTTP verificadas apresentaram `Cache-Control: no-store`.

A interoperabilidade com Pillow foi confirmada no teste HTTP, ao abrir as imagens RGB e RGBA resultantes, e também em execução separada do teste unitário dentro de contêiner Docker com Pillow 10.0.1: **`Ran 1 test` / `OK`**. A instalação foi feita no contêiner descartável, sem adicionar Pillow às dependências de produção.

Os valores sensíveis conhecidos verificados não apareceram nos logs inspecionados. **A ausência dos valores internos das chaves não pôde ser confirmada diretamente**, pois eles não são retornados pela API. Essa inspeção ficou limitada aos valores, contêiner e período considerados pelo script; não comprova ausência em outros logs ou componentes.

O teste HTTP criou duas contas fictícias e sessões que permanecem no banco de desenvolvimento. Uma conta recebeu ADMIN temporariamente e foi rebaixada para USER ao final. As validações não substituem auditoria de segurança. Permanecem as limitações da seção anterior: LSB pode ser detectada e alterações na imagem podem destruir o conteúdo oculto; esteganografia não substitui criptografia. A validação registrada refere-se à imagem e às execuções observadas, não a alterações posteriores.

### Comandos de reprodução

Na raiz do backend, com Docker e rede disponíveis, a suíte foi executada após reconstruir a imagem:

```bash
docker compose build api
```

```bash
docker run --rm --entrypoint sh fink-backend-api -lc 'pip install pytest==9.2.0 pytest-asyncio==1.5.0 pytest-cov==7.1.0 coverage==7.17.3 iniconfig==2.3.1 pluggy==1.7.0 pygments==2.21.0 && python -m pytest -p no:cacheprovider -q'
```

O contêiner usa o código contido na imagem, sem montagem do diretório local. Uma reconstrução pode produzir outra imagem; as versões dos pacotes explicitados estão fixadas, mas isso não garante reprodução integral de todas as dependências do ambiente anterior.

Para o teste HTTP, com o PostgreSQL de desenvolvimento disponível e as tabelas existentes:

```bash
docker compose up -d postgres
python3 scripts/steganography_http_smoke.py
```

O script usa instância local temporária, `--lifespan off` e dados fictícios. Cada execução cria novas contas e sessões no banco de desenvolvimento; não usar em produção ou com dados reais.

Para executar separadamente a verificação opcional de interoperabilidade com Pillow em um contêiner descartável:

```bash
docker run --rm --entrypoint sh fink-backend-api -lc 'pip install Pillow==10.0.1 && python -m unittest tests.test_steganography_unit.SteganographyUnit.test_pillow_can_open_output_if_available -v'
```

Este registro documenta os resultados observados na Etapa 4. As limitações técnicas da LSB e do gerenciamento de chaves continuam aplicáveis.

## Planejamento da Etapa 5 — Ataques Criptográficos Controlados

**Registro histórico do planejamento.** A implementação e a validação da Etapa 5 estão documentadas nas seções seguintes. Esta numeração segue as etapas efetivamente registradas neste documento; o plano incremental histórico da especificação do Projeto 2 usa outra numeração. Os quatro experimentos utilizam exclusivamente `TOY-V1-INSECURE` e dados sintéticos gerados no laboratório. Não atacam AES-256-GCM, esteganografia, autenticação nem funcionalidades reais da FINK. Valores abaixo são parâmetros propostos ou propriedades esperadas, não resultados observados.

### 1. Arquitetura proposta

- Criar um pacote isolado `app/crypto_lab/attacks/`: `fixtures.py` para amostras sintéticas versionadas, `brute_force.py`, `statistics.py`, `differential.py`, `avalanche.py` para os experimentos, `runner.py` para orçamento e execução, e `results.py` para modelos e agregação. Usar diretamente `encrypt_block`/`encrypt_bytes` da cifra didática; não acessar `ToyService`, seus repositórios ou o serviço AES. Criar novas chaves didáticas somente dentro de cada execução; nunca aceitar `key_id`, chave, plaintext, ciphertext ou alvo arbitrário da API.
- Acrescentar roteador e schemas próprios para experimentos, fora das rotas de cifragem existentes. Um coordenador admite o trabalho e um processo filho descartável executa a carga de CPU, sem bloquear o event loop nem ocupar o pool de threads da API. O processo filho recebe apenas o identificador da amostra e gera seus próprios dados; não recebe stores, credenciais ou contexto da requisição. Usar método de criação que não herde memória da API, sem rede ou banco no trabalho, e limpar referências ao finalizar. Encerramento forçado deve ser comprovado na plataforma local; se não for possível garantir isolamento e prazo, falhar fechado e não habilitar o endpoint.
- Armazenar somente estado e resultados agregados em memória por processo da API, com associação ao ADMIN solicitante; reinício os elimina. Sem persistência, fila externa, acesso a arquivos de usuários ou alteração dos contadores AES/didáticos existentes. Identificador aleatório não é credencial: toda consulta exige autenticação, ADMIN e propriedade. Cancelamento pelo usuário fica fora do escopo inicial; timeout e encerramento da aplicação devem terminar e recolher o processo filho.
- A cifra possui blocos independentes de 64 bits, quatro rodadas e padding PKCS#7 que sempre acrescenta pelo menos um byte, inclusive um bloco inteiro quando o comprimento é múltiplo de oito. Os ensaios em bloco usam `encrypt_block` para evitar confundir padding com difusão; quando `encrypt_bytes` for usado, identificar o bloco de padding e não contar suas alterações como alterações de dados.

### 2. Metodologia e métricas

**Amostras e reprodução.** Definir catálogo interno `synthetic-v1`, sem entrada livre: blocos de 8 bytes compostos de zeros, sequências e padrões repetidos; mensagens de 32 bytes com quatro blocos iguais e outras com quatro blocos distintos; mais 32 blocos sintéticos distintos gerados por regra determinística documentada no código futuro. Usar 32 chaves didáticas independentes geradas no processo de experimento para os ensaios estatístico, diferencial e avalanche; comparar pares sob a mesma chave quando especificado. Gerar chaves com fonte segura, sem publicá-las, persistí-las ou registrar semente que permita reconstruí-las. Catálogo e posições dos bits são reproduzíveis; resultados exatos variam com as chaves e ambiente. Registrar versão do catálogo, tamanho, quantidade de chaves e amostras, método de amostragem, versão da cifra e limites, sem dados brutos. Cada execução é independente; não tratar medições correlacionadas como amostras independentes para inferência.

**Força bruta.** Gerar uma chave didática alvo efêmera e um par conhecido fictício de um bloco de 8 bytes; obter o ciphertext internamente com `encrypt_block`. Percorrer em ordem crescente todos os inteiros de 0 a 65.535, convertidos em dois bytes big-endian, cifrando o mesmo bloco e comparando os 8 bytes completos. Não parar na primeira correspondência: contar todas as candidatas que produzem o par e verificar internamente se a chave alvo está entre elas. Candidatas adicionais são colisões para esse par, não necessariamente chaves equivalentes em todas as entradas. Um segundo bloco fictício distinto, cifrado sob a mesma chave e avaliado para as candidatas, reduz a ambiguidade; informar contagem após cada par, sem afirmar equivalência global nem unicidade além dos pares verificados. Não retornar candidatas, chave alvo, pares, hashes ou identificadores derivados da chave.

Medir tentativas como chaves efetivamente testadas no primeiro par, duração com relógio monotônico e taxa `tentativas / segundos` quando duração > 0; informar separadamente verificações do segundo par. Informar `completed`, espaço total, contagens de candidatas e se a chave original foi encontrada, apenas quando o percurso terminou. O sucesso refere-se à inclusão da chave alvo, não à prova de identificação única. Em timeout ou falha, registrar estado inconclusivo e duração, sem alegar fracasso criptográfico; parciais só podem ser retornados se recebidos com segurança e identificados como parciais. Espera-se que um percurso completo encontre a chave gerada; duração e número de colisões dependem da execução.

**Estatística.** Para cada chave, cifrar os quatro blocos repetidos e os quatro distintos, além dos 32 blocos sintéticos; analisar os blocos de dados, separadamente para cada chave. Contar bytes por valor 0–255 e frequências relativas `contagem / total de bytes`; incluir contagens agregadas e denominador, sem histogramas de ciphertext individual. Contar blocos totais, distintos, excedentes repetidos `total - distintos` e fração `excedentes / total`, por conjunto e chave; resumir distribuição dessas frações entre chaves. Comparar também o número de posições iguais nos quatro blocos repetidos e nos distintos. Espera-se que blocos iguais sob uma mesma chave tenham ciphertext igual e revelem repetição; não comparar igualdade entre chaves como se fosse mesma condição. Histograma aparentemente uniforme não comprova segurança, e a amostra é pequena e dependente da seleção de entrada.

**Diferencial.** Para cada uma das 32 chaves e 32 amostras de bloco, alterar separadamente cada uma das 64 posições de bit do plaintext, mantendo chave e comprimento: 65.536 pares de blocos. Para cada par, calcular XOR das saídas e distância de Hamming (soma dos bits 1), entre 0 e 64; agregar histograma de distâncias e frequência de alteração de cada uma das 64 posições de saída, com denominador 65.536. Para propagação, aplicar separadamente os 256 flips possíveis aos 32 bytes de cada mensagem de quatro blocos distintos, sob cada chave: comparar blocos correspondentes e contar mudanças por posição de bloco relativamente ao bloco alterado. Usar blocos de dados diretamente, ou excluir explicitamente o bloco de padding inalterado de `encrypt_bytes`. Espera-se ausência de propagação para outros blocos pela independência da implementação. A distribuição medida descreve este conjunto de diferenças; não é prova formal de vulnerabilidade diferencial nem recuperação de chave.

**Avalanche.** Reutilizar os pares de bloco da análise diferencial para o cenário de bit do plaintext, sem recalculá-los desnecessariamente. Para alteração de chave, para cada uma das 32 chaves e 32 amostras, inverter separadamente cada um dos 16 bits da chave e comparar com a saída original para o mesmo bloco: 16.384 pares. Para cada par calcular `100 × Hamming / 64`; publicar número de pares, média, mínimo, máximo e desvio-padrão **populacional** dos percentuais, separadamente por cenário. Publicar também histograma 0–64 de bits alterados e frequência por bit de saída com respectivos denominadores. Para mensagens multibloco, apresentar propagação por bloco separadamente: não diluir o resultado do bloco alterado em blocos independentes ou padding. A referência de aproximadamente 50% é comparativa para saídas ideais sob esse protocolo, não uma meta garantida nem prova isolada de segurança; pequenas amostras e correlação limitam conclusões.

### 3. Contratos propostos e integração futura

Propor `POST /api/v1/crypto-lab/attacks/runs` com Bearer ADMIN e JSON estrito `{"experiment":"brute_force"}`; valores permitidos também `statistics`, `differential`, `avalanche`. O servidor escolhe `synthetic-v1` e todos os parâmetros; campos extras, inclusive alvo, chave e URL, são rejeitados. Retorno **202** com `run_id` UUID aleatório, `status: "running"` e `algorithm: "TOY-V1-INSECURE"`. `GET /api/v1/crypto-lab/attacks/runs/{run_id}` retorna somente ao mesmo ADMIN `run_id`, `algorithm`, `experiment`, `status` (`running`, `completed`, `timed_out`, `failed`), versão de schema e catálogo, parâmetros públicos, duração e `metrics` agregadas específicas acima quando disponíveis. Uma execução inexistente, expirada ou de outro proprietário retorna o mesmo 404 genérico. Falhas não devolvem rastros ou exceções. Todos os retornos e erros levam `Cache-Control: no-store`.

Respostas 401 para sessão ausente/inválida, 403 para não ADMIN, 404 em produção (rotas não registradas), 413 para corpo excessivo, 422 sanitizado para esquema inválido, 429 para limite de frequência e 503 para flags/ambiente inválidos ou capacidade ocupada. JSON/UTF-8 malformado recebe 400 genérico. O limite de corpo atua antes do parsing e da autenticação, como no middleware atual; testar que nenhum erro reflete entrada, inclusive quando a requisição não está autenticada. Nenhuma operação começa antes das verificações de ambiente, autenticação, autorização, validação, frequência e capacidade.

Para a Etapa 7, os resultados completos podem alimentar gráficos de tentativas/tempo, frequências de bytes e blocos, histograma de Hamming e estatísticas de avalanche. Versionar schema (`1`), algoritmo, catálogo, experimento, unidade, denominadores, parâmetros, estado e duração; limitar rótulos a uma allowlist. Esses dados são efêmeros e por execução, não um histórico nem Big Data. Persistência, retenção, agregação entre execuções e autorização do dashboard exigem projeto posterior; nunca inferir resultados concluídos de execuções interrompidas. Sem expor pares, chaves, tokens, conteúdos ou dados financeiros.

### 4. Limites operacionais e isolamento

- Rotas somente em `development`, `test`, `testing` ou `local`, em loopback local, com `DEBUG=false`, um worker e uma instância; produção não registra rotas. Exigir `CRYPTO_LAB_ENABLED=true`, `CRYPTO_LAB_EXPERIMENTAL_ENABLED=true` e nova `CRYPTO_LAB_ATTACKS_ENABLED=true`, todas desligadas por padrão. Validar condições a cada requisição e falhar fechado; verificar operacionalmente a topologia e a escuta em loopback, que não podem ser garantidas só por variáveis declaradas.
- Por processo da API: no máximo **uma execução ativa**, sem fila e sem espera por vaga; recusar concorrentes com 503. Limitar início a **uma requisição aceita por ADMIN a cada 60 segundos** e **10 por processo em janela móvel de uma hora**, com verificações atômicas; excedente 429. Consultas GET: máximo de 60 por ADMIN em janela móvel de um minuto, 429 acima disso. Estado dos limites é efêmero e é reiniciado com o processo; não alegar limite distribuído.
- Corpo de POST e GET limitado a **1.024 bytes recebidos antes do parsing**, inclusive sem `Content-Length`; parâmetros e amostras são fixos, sem upload. Cada execução tem prazo de **120 segundos de relógio monotônico**, incluindo inicialização; ao expirar, terminar e recolher o processo, liberar a vaga e marcar `timed_out`. Não confiar apenas no cancelamento de uma coroutine ou thread. Desligamento e falha também devem recolher o filho; limites de tentativas e amostras acima continuam válidos independentemente do prazo.
- Manter no máximo **10 resultados** por processo por **15 minutos após término**; remover expirados e, se necessário, o resultado concluído mais antigo, nunca uma execução ativa. Sem lista global de resultados. Tamanho agregado por resultado limitado a **64 KiB serializados**; ao ultrapassar, falhar com erro genérico sem truncar silenciosamente métricas. Não registrar corpos, respostas, chaves, pares, tokens ou dados sensíveis em logs, traces, proxy e APM; mensagens e métricas têm allowlist. Restringir dumps e depuradores conforme seção 3.3.

### 5. Testes e validação futuros

- Unitários determinísticos com chaves e vetores fictícios exclusivos de teste, relógio e processo controlados: enumeração inclusiva de 65.536 candidatos, contagem correta, recuperação interna, colisões simuladas e filtragem pelo segundo par; timeout parcial jamais apresentado como completo. Conferir histogramas, denominadores, Hamming, desvio-padrão populacional e limites; testar blocos iguais, ausência de propagação entre blocos e tratamento do padding. Não exigir 50% nem um valor de tempo específico.
- Integração: substituir dependências de AES e stores por sentinelas que falham se acessadas; comprovar ausência de chamadas e alterações nos contadores existentes. Verificar processo separado, responsividade da API, limites de trabalho, concorrência, frequência, término forçado, recolhimento e liberação da vaga em sucesso, timeout, falha e desligamento; testar expiração, capacidade e isolamento entre proprietários. Verificar sanitização de respostas, exceções e logs com valores fictícios conhecidos, inclusive chave interna injetada em teste, sem registrá-la de fato.
- HTTP local com banco e contas de teste isolados: produção 404; combinações das três flags e ambientes inválidos; anônimo 401, USER 403, ADMIN autorizado 202 e consulta própria, outro ADMIN 404; schema inválido 422, JSON inválido 400, corpo no limite e acima com e sem `Content-Length`, 429 e 503; `no-store` em sucesso e erro. Exercitar conclusão, timeout e falha sem expor entradas ou segredos. Confirmar que as rotas AES e didática continuam funcionando antes e depois e executar a suíte de regressão existente. Registrar ambiente, revisão, comandos e resultados realmente observados, sem tratar a inspeção de logs limitada como prova universal.

### 6. Critérios objetivos de conclusão

1. Os quatro experimentos executam somente sobre amostras internas e `TOY-V1-INSECURE`, com contratos e métricas desta seção; força bruta completa percorre 65.536 chaves ou declara explicitamente timeout inconclusivo, e uma execução completa demonstra recuperação interna sem expor chaves.
2. Resultados distinguem pares completos e parciais, colisões por par, contagens e denominadores; incluem distribuições e estatísticas especificadas, versão e unidades, sem apresentar observações inventadas nem segurança comprovada por avalanche.
3. Autorização, flags, isolamento do processo, prazos, limites de capacidade/frequência/volume, limpeza e ausência de segredos passam nos testes de unidade, integração e HTTP descritos; nenhum experimento bloqueia a API durante a validação.
4. Regressões das funcionalidades existentes passam; resultados efetivamente observados, limitações e procedimento reproduzível são documentados. O formato agregado versionado fica disponível para consumo futuro, sem antecipar persistência ou dashboard.

**Decisões a confirmar antes da implementação:** adequação dos 120 segundos ao equipamento local e eventual ajuste após medições controladas; viabilidade do processo filho sem herança de memória e sua terminação nas plataformas de demonstração; necessidade de histórico persistente ou exportação para a Etapa 7. A confirmação não transforma os limites propostos em resultados observados.

## Implementação da Etapa 5 — situação e validação

A implementação acrescenta `app/crypto_lab/attacks/fixtures.py`, `brute_force.py`, `statistics.py`, `differential.py`, `avalanche.py`, `results.py`, `runner.py`, `worker.py` e `routes.py`, além de `__init__.py`. Configuração, montagem das rotas, encerramento e limite de corpo foram integrados a `app/core/settings.py`, `app/main.py` e `app/crypto_lab/middleware.py`. Os testes novos são `tests/test_attacks_stage5.py` e `tests/test_attacks_api.py`. O código executa apenas operações de bloco da cifra didática, com amostras internas e chaves efêmeras; não consulta os serviços ou repositórios de chaves AES e didático.

As rotas implementadas são `POST /api/v1/crypto-lab/attacks/runs` e `GET /api/v1/crypto-lab/attacks/runs/{run_id}`, conforme o contrato proposto. Exigem ADMIN e as flags `CRYPTO_LAB_ENABLED`, `CRYPTO_LAB_EXPERIMENTAL_ENABLED` e `CRYPTO_LAB_ATTACKS_ENABLED` habilitadas. Todas são desabilitadas por padrão. `CRYPTO_LAB_ATTACKS_TIMEOUT_SECONDS` tem padrão 120 e aceita valor maior que zero e até 120. Resultados, acesso por proprietário e cotas ficam apenas na memória do processo; não sobrevivem a reinício. O middleware geral mantém a indisponibilidade em produção e ambientes incompatíveis. A publicação da porta em loopback e a topologia de instância única continuam sendo verificações operacionais: as flags não comprovam que a rede esteja isolada.

Os blocos sintéticos adicionais são as representações big-endian de oito bytes dos inteiros de 0 a 31. Cada execução estatística, diferencial ou avalanche usa 32 chaves novas. A força bruta percorre os 65.536 valores, avalia todas as candidatas contra o segundo par e retorna somente contagens e sucesso interno. A análise estatística agrega frequência de bytes e repetição por grupo e chave; a diferencial conta distâncias de Hamming e propagação por deslocamento de bloco; a avalanche reutiliza a função da análise diferencial e agrega média, extremos e desvio-padrão populacional para alterações de plaintext e de chave. Blocos de padding não entram nas medidas. São dados experimentais de uma cifra deliberadamente insegura: frequências ou proximidade de 50% não provam segurança, e colisão em um par não estabelece equivalência global.

A execução é admitida apenas em Linux; em outros sistemas recebe 503. No Docker Linux, cada trabalho inicia um interpretador novo, com ambiente mínimo e sem contexto da requisição, usando `exec` em processo separado. O filho exige `prctl` com sinal de morte do pai, confere o PID do pai, aplica temporizador monotônico independente e limites de 120 segundos de CPU, 256 MiB de espaço de endereçamento e 32 descritores; falhas de preparação encerram o trabalho sem resultado. O coordenador impõe prazo configurável, encerra e aguarda o filho em timeout ou desligamento. Esses controles não são uma sandbox geral de sistema operacional: a implantação deve manter a API e seus dados de teste isolados e limitar publicação de rede. A execução deve ser feita em ambiente Docker local apropriado, e não diretamente no macOS.

Aplicam-se um trabalho ativo sem fila, um início por ADMIN a cada 60 segundos, dez inícios por processo por hora e 60 consultas por ADMIN por minuto. O corpo é limitado a 1.024 bytes; resultados a 64 KiB; até dez resultados são mantidos durante 15 minutos após o término. As cotas e os resultados são locais ao processo, sem coordenação distribuída. A saída é versionada (`schema_version: 1`, `catalog_version: synthetic-v1`) e contém unidades e denominadores para futura apresentação; ainda não existe histórico persistente nem dashboard nesta etapa.

### Validação registrada

A suíte foi executada em contêiner descartável da imagem local `fink-backend-api`, com o diretório atual montado somente para leitura e ferramentas de teste instaladas dentro do contêiner: **167 testes aprovados, 1 ignorado, 52 subtestes aprovados e 11 avisos**. Os testes incluíram as quatro execuções em processo Linux, percurso de 65.536 chaves, colisões simuladas, métricas, limite de tempo, concorrência, encerramento, acesso e validação HTTP em memória, além da regressão existente. A imagem forneceu as dependências de base; o código testado veio da montagem local. O teste ignorado é o de interoperabilidade opcional com Pillow. A instalação de ferramentas no contêiner não altera o Mac nem garante versões idênticas de dependências transitivas em execuções futuras.

A verificação HTTP usou transporte ASGI em memória e autenticação simulada: não substitui validação por rede com um banco de testes. A morte abrupta do processo pai, a ausência de dados sensíveis em infraestrutura externa e a publicação efetiva apenas em loopback não foram validadas nesta execução. A etapa não deve ser declarada integralmente validada em implantação até essas verificações e os demais cenários do plano serem realizados.

Para repetir a suíte completa no Terminal do Mac, a partir da raiz do backend, com Docker e rede para instalação das ferramentas no contêiner:

```bash
docker run --rm -v "$PWD:/workspace:ro" -w /workspace --entrypoint sh fink-backend-api -lc 'pip install pytest==9.2.0 pytest-asyncio==1.5.0 pytest-cov==7.1.0 && python -m pytest -o addopts="" -p no:cacheprovider --no-cov -q'
```

A imagem precisa existir e conter as dependências compatíveis da aplicação. A montagem somente de leitura assegura que os testes usem os arquivos locais sem modificá-los; a instalação ocorre apenas no contêiner descartável. Usar banco e contas exclusivamente fictícios para qualquer validação HTTP adicional; não apagar volumes nem executar seeds sobre dados reais.

## Validação da Etapa 5 — Ataques Criptográficos Controlados

### Resultados observados

A suíte automatizada completa registrou **167 testes aprovados, 1 ignorado, 52 subtestes aprovados e 11 avisos**, conforme o procedimento e as condições descritos na seção anterior. Em seguida, `scripts/attacks_http_smoke.py` realizou a validação HTTP real em contêineres descartáveis, com dados fictícios, e terminou com **0 falhas e 2 cenários não verificados diretamente (SKIP)**. A imagem API informada na execução HTTP foi `sha256:b0ba55bd31c6690bc751bbb80ee6d20155be9e7cce3ca81c0e092c752d5dfda4`; o script confirmou a correspondência dos arquivos selecionados da imagem com os arquivos locais.

| Cenário | Resultado observado |
|---|---|
| Força bruta, análise estatística, análise diferencial e efeito avalanche | Os quatro experimentos HTTP terminaram com estado `completed` sobre a cifra didática `TOY-V1-INSECURE`. |
| Estrutura e métricas | As verificações do script para versão, estrutura, denominadores e consistência das métricas retornadas passaram. Na força bruta, foram verificadas 65.536 tentativas e a inclusão da chave alvo entre as candidatas. Na estatística, o denominador verificado foi 10.240 bytes; nas comparações por alteração de bit do plaintext, 65.536 pares; e, para alteração de bit da chave no avalanche, 16.384 pares. |
| Acesso e flags | O acesso ADMIN permitiu iniciar as execuções; requisições anônimas e de USER receberam 401 e 403. Cada uma das três flags obrigatórias desabilitada individualmente bloqueou a execução com 503. |
| Entrada e concorrência | Campo extra foi rejeitado com 422 sem refletir o conteúdo fictício; corpo acima de 1.024 bytes recebeu 413; uma segunda execução durante trabalho ativo recebeu 503. |
| Rede e portas | O script criou uma rede Docker dedicada aos contêineres de teste e conferiu, pela inspeção Docker, que as portas publicadas das APIs temporárias estavam vinculadas exclusivamente a `127.0.0.1`. O PostgreSQL de teste usou armazenamento temporário em memória; a validação não usou o banco nem a API existentes da FINK. A rede dedicada utilizada não foi configurada como rede Docker `--internal`, portanto essa observação não comprova bloqueio geral de saída para outras redes. |
| Timeout e encerramento abrupto | Com prazo de teste reduzido e o processo filho observado, a execução retornou `timed_out` e o filho terminou. Em outro contêiner descartável, o filho também terminou após `SIGKILL` da API temporária, enquanto o contêiner permanecia ativo. |
| Regressão dos fluxos existentes | AES-256-GCM, cifra didática e esteganografia continuaram funcionando após os experimentos; a força bruta e a recuperação dos dados fictícios foram exercitadas na mesma instância temporária. Nenhum ataque foi executado contra o AES. |
| Limpeza | O script informou remoção dos contêineres e da rede temporários. Não foi necessário apagar volumes. |

As evidências disponíveis registram a aprovação das verificações de consistência, mas não preservam os valores observados de duração, taxa de força bruta ou percentuais de avalanche. Esses números não são inferidos aqui. Os resultados dizem respeito às execuções e ao ambiente de teste registrados, não constituem prova formal de segurança ou auditoria de implantação.

### Limitações da validação HTTP

1. **Sistema não Linux:** a rejeição foi verificada por simulação da plataforma no coordenador; não houve execução em outro sistema operacional real.
2. **Chaves internas e logs:** não foi possível procurar diretamente os valores internos das chaves nos logs, pois eles não são expostos ao cliente. Os demais valores sensíveis conhecidos usados na execução estavam ausentes dos logs dos contêineres inspecionados. A verificação não cobre logs externos, dumps ou valores internos desconhecidos.

### Comandos de reprodução

Na raiz do backend, com Docker disponível, imagem local `fink-backend-api` compatível com o código e imagem `postgres:16` já disponível, executar a validação HTTP:

```bash
python3 scripts/attacks_http_smoke.py
```

O script usa uma rede dedicada, portas efêmeras publicadas em loopback, PostgreSQL temporário em `tmpfs` e contas fictícias; ao final, remove seus contêineres e sua rede. Os cenários apresentam `PASS`, `FAIL` ou `SKIP`. A rede dedicada não substitui controles de implantação nem garante, por si só, ausência de acesso externo.

Para reproduzir a suíte automatizada completa no Terminal do Mac, com acesso à rede para instalar as ferramentas apenas no contêiner descartável:

```bash
docker run --rm -v "$PWD:/workspace:ro" -w /workspace --entrypoint sh fink-backend-api -lc 'pip install pytest==9.2.0 pytest-asyncio==1.5.0 pytest-cov==7.1.0 && python -m pytest -o addopts="" -p no:cacheprovider --no-cov -q'
```

A montagem somente de leitura usa o código local; a imagem fornece as dependências de base. A reprodução depende das imagens e dependências disponíveis e pode produzir resultados ou tempos diferentes.

## Planejamento da Etapa 6 — Detecção de Anomalias com IA

**Registro histórico do planejamento.** A implementação e a validação da Etapa 6 estão documentadas nas seções seguintes. Esta etapa usa exclusivamente eventos e rótulos sintéticos gerados dentro do laboratório. Nenhum modelo foi treinado ou avaliado neste planejamento; números de volume, divisão e limiar abaixo são parâmetros propostos, não medições. A numeração segue a deste documento e coincide aqui com a etapa de IA da especificação do Projeto 2. O objetivo é demonstrar detecção experimental e comparação com um método de referência, sem acionar bloqueios, alterar contas ou tomar decisões de segurança reais.

### 1. Diagnóstico dos dados existentes e fronteira da proposta

O código atual em `app/core/security_logging.py` emite JSON para stdout e guarda os **200 eventos mais recentes por processo** em um buffer limitado, sincronizado e efêmero. Os campos permitidos são `timestamp` UTC, `event`, `result`, `method`, `route` como template de rota e `user_id` opcional; os quatro tipos são `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `ACCESS_DENIED` e `ADMIN_ACCESS`, respectivamente com resultados `SUCCESS`, `FAILURE`, `DENIED` e `ALLOWED` nos pontos de emissão atuais. `GET /api/v1/security-logs/` exige `require_admin`, retorna uma cópia em ordem mais recente primeiro e `no-store`; consultar esse endpoint é uma exceção ao registro de `ADMIN_ACCESS` em `require_admin`. O middleware registra 401/403 fora da rota de login como `ACCESS_DENIED`. A falha de login não inclui identidade do usuário submetido. `ADMIN_ACCESS` registra autorização concedida, não necessariamente conclusão bem-sucedida da operação.

Esses eventos **não são um log completo de requisições**: não permitem reconstruir a frequência de todas as chamadas, associar falhas de login à mesma pessoa, nem inferir IP, dispositivo ou intenção. O buffer pode perder eventos antigos e é separado por processo. Os contadores de `app/crypto_lab/metrics.py` agregam operações AES e didáticas, sem sequência temporal individual ou contagem geral de requisições; não servem como dataset de eventos. O classificador existente `app/ai/transaction_classifier.py` usa TF-IDF e regressão logística para descrições de transações, não para anomalias; não reutilizar seu dataset ou integrá-lo a esta análise. `scikit-learn` já está declarado no `pyproject.toml`; a execução futura deve confirmar disponibilidade e versão efetiva na imagem, sem presumir que a faixa declarada garanta reprodução idêntica.

Não consumir `get_security_logs()`, stdout, o endpoint de logs, métricas reais ou banco da FINK na geração, treinamento ou inferência desta etapa. O gerador deve produzir registros sintéticos em estrutura própria, derivados da *forma* dos eventos atuais, sem alterar o logger existente nem emitir eventos falsos para ele. Os eventos administrativos reais causados pelo uso dos novos endpoints continuam sujeitos ao mecanismo de autorização existente, mas não alimentam o modelo: isso evita realimentação por consultas. Não usar dados pessoais reais, endereços IP, nomes, e-mails, senhas, tokens, chaves, payloads ou dados financeiros; IDs fictícios do gerador não representam usuários reais.

### 2. Arquitetura e dados sintéticos

Propor pacote independente `app/crypto_lab/anomaly_lab/` com `generator.py` (cenários e catálogo versionado), `features.py` (janelas e agregação), `models.py` (Isolation Forest e baseline), `evaluation.py` (limiar e métricas), `runner.py` (execução limitada), `schemas.py` e `routes.py`. Manter coordenador e repositório de resultados separados das rotas de criptografia e dos stores AES/didático; não alterar o contrato `/api/v1/security-logs/`. Integração administrativa usa `require_admin`, nunca autorização apenas na interface. Os módulos e endpoints abaixo eram propostas na época do planejamento.

Gerar `synthetic-security-v1` com semente inteira **fixa e pública** para reprodução dos dados fictícios, catálogo de cenários e versões explícitas. A semente não é segredo nem fonte de chaves criptográficas. Cada evento sintético tem `schema_version`, `timestamp` sintético UTC, `event`, `result`, `method` e `route` de allowlists; `synthetic_stream_id` e `episode_id` são identificadores arbitrários gerados apenas para delimitar janelas e divisões, nunca atribuídos a pessoas nem expostos como features ou resultados. `user_id` real não existe no dataset; não simular que uma falha de login possa ser atribuída a um usuário real. `scenario_family` e rótulo de referência existem somente em metadados de geração/avaliação e nunca são atributos de entrada do modelo.

Além dos quatro eventos atuais, o gerador inclui um evento **exclusivamente sintético** `SYNTHETIC_REQUEST_OBSERVED` com resultado e rota de categorias fixas, para experimentar frequência total de requisições. Ele não representa evento atualmente registrado pela FINK e não deve ser escrito no logger de segurança nem apresentado como telemetria observada. A análise de frequência total depende desse sinal adicional; sem ele, somente frequência dos eventos efetivamente capturados poderia ser avaliada em eventual integração futura. O dataset não pressupõe identidade de origem nas falhas de login: repetições são contadas por janela de fluxo sintético, não por conta ou IP.

Usar janelas UTC fixas e **não sobrepostas de cinco minutos por fluxo sintético**, com até 32 eventos cada. Cada janela é unidade de classificação e possui um rótulo binário sintético: normal ou anômalo, atribuído pela regra de geração da janela, mais família do cenário em metadados de avaliação. Gerar catálogo de **6.000 janelas**, limitado a **192.000 eventos** antes da agregação; nenhum dado bruto é devolvido ao cliente ou persistido. Há distribuições variadas e sobrepostas: comportamento normal inclui logins falhos ocasionais, negações justificadas, variação de carga e operações administrativas legítimas; anomalias incluem surtos de falhas de login, de acessos negados, de volume de requisições sintéticas e de atividade administrativa atípica. Misturar exemplos ambíguos e variar horários, intensidades, frequências e composição; não codificar o rótulo como uma propriedade sempre exclusiva de um único tipo de evento. Reservar variantes de cada família para avaliação e descrever os parâmetros e a prevalência escolhidos: os rótulos expressam apenas a intenção do gerador, não a verdade sobre tráfego real.

**Features por janela**, todas contagens ou razões numéricas com limites conhecidos: total de eventos observados, total de `SYNTHETIC_REQUEST_OBSERVED`, contagens por cada um dos quatro tipos, proporções de login falho entre tentativas de login e de negações entre eventos, contagem de acessos administrativos, quantidade de categorias de rota da allowlist e requisições administrativas sintéticas fora de um horário UTC de referência definido no catálogo. Denominador zero produz razão zero e uma flag explícita de ausência de denominador; hora usa apenas o relógio sintético. Não incluir timestamp absoluto, IDs, nomes de cenário, índice da janela, semente, partição ou rótulos como features. Os agregados devem ser derivados somente dos eventos da própria janela; o modelo nunca recebe rótulos. A janela de fluxo é um artefato experimental, não uma afirmação de que o logger atual permite reconstruí-la.

### 3. Modelo, baseline e prevenção de vazamento

**Recomendação:** `IsolationForest` de `scikit-learn`, não supervisionado, com `random_state` fixo, número de árvores e demais hiperparâmetros explícitos e versão da biblioteca registrados. Ele identifica observações raras segundo os dados e features fornecidos, exige poucos rótulos para treinamento e está disponível na dependência declarada. Seu score é relativo ao modelo e à amostra, **não é probabilidade de ataque**, e não identifica causas nem comprova comportamento malicioso. Comparar com baseline estatístico simples: para cada feature numérica, usar centro e escala robustos calculados apenas no treino normal; escore é o maior desvio absoluto padronizado, com tratamento documentado para escala zero. Aplicar o mesmo particionamento e orçamento aos dois métodos.

Particionar **antes de ajustar transformações, calcular limiares ou produzir agregados que cruzem janelas**, separando episódios e fluxos sintéticos sem sobreposição entre conjuntos. Usar períodos sintéticos cronologicamente distintos, com espaços de separação de pelo menos uma janela, e geradores/variantes de cenário independentes por partição: **4.200 janelas normais de treino**, **600 normais de calibração**, **600 de validação** e **600 de teste final**; nas duas últimas propor **540 normais e 60 anômalas cada**, distribuídas entre as quatro famílias e variantes não idênticas. Não copiar episódios ou amostras entre divisões e usar subfluxos aleatórios independentes; testar sua separação. Vetores agregados iguais podem ocorrer naturalmente e não devem, por si só, ser tratados como cópias ou como prova de vazamento. O número de janelas e a prevalência são construções sintéticas, não estimativas do mundo real. Repetir futuramente com sementes e prevalências alternativas pré-definidas para avaliar sensibilidade, sem escolher a melhor após observar o teste.

Ajustar o Isolation Forest e quaisquer transformações somente no treino normal. Fixar parâmetros antes da avaliação; inverter o sentido de `score_samples` quando necessário para que **maior score signifique mais anômalo**. Definir para cada método o limiar como percentil 99 dos scores das 600 janelas normais de calibração, usando convenção de quantil documentada; classificar como anômala somente se `score > limiar`, e relatar empates e fração calibrada observada. Isso define uma referência de aproximadamente 1% de alertas na calibração, sujeita a empates e tamanho amostral, **não uma garantia de falso positivo no teste**. O baseline calcula centro/escala no treino e limiar na mesma calibração, sem usar rótulos da validação ou teste para escolher o corte.

A validação oferece comparação de diagnóstico e revisão metodológica; qualquer mudança após inspecioná-la exige congelar novamente o protocolo e obter um novo conjunto de teste independente. O conjunto final de teste é usado apenas depois de fixados features, modelo, limiares e regras. Comparar ambos no mesmo teste e registrar versões do gerador, biblioteca e configuração; uma semente fixa permite reprodução condicionada a essas versões, não garante bit a bit entre plataformas. Para explicar um alerta experimental, apresentar apenas score, limiar e indicadores agregados relevantes em relação às referências do treino, explicitamente como **evidência contextual e não atribuição causal ou explicação interna exata do Isolation Forest**. Para proteção de dados, a API inicial retorna apenas sínteses por conjunto e família sintética, sem listar eventos ou janelas individuais.

### 4. Avaliação e interpretação

No teste rotulado sintético, publicar para ambos os métodos matriz de confusão com convenção explícita (linha = rótulo real, coluna = predição; `TN`, `FP`, `FN`, `TP`), suporte normal/anômalo, prevalência, precisão `TP/(TP+FP)`, recall `TP/(TP+FN)`, F1 `2TP/(2TP+FP+FN)` e taxa de falsos positivos `FP/(FP+TN)`. Definir divisões por zero como `null` com motivo e denominador, nunca inventar zero ou sucesso; reportar também total de alertas e contagens por família sintética, com suporte, para identificar cenários não detectados. A agregação por família usa apenas o rótulo de geração, após predição. Opcionalmente calcular PR-AUC e ROC-AUC no teste apenas quando ambas as classes existirem, com biblioteca e convenção documentadas; precisão/recall dependem da prevalência sintética escolhida.

Reportar resultados de treino, calibração, validação e teste em seções claramente separadas: os números do treino não são generalização. Falsos positivos significam janelas sinteticamente normais sinalizadas; falsos negativos, anomalias sintéticas não sinalizadas. Quantificar ambos e discutir impacto hipotético, custo operacional e desbalanceamento; não chamar os rótulos sintéticos de incidentes confirmados. Resultados por família com suporte pequeno são instáveis; se forem usados intervalos, calcular por episódios independentes, não por eventos correlacionados, e informar método e incerteza. Não publicar qualquer valor de desempenho como observado antes da execução.

### 5. API proposta, limites e segurança

Todos os endpoints propostos usam prefixo `/api/v1/crypto-lab/anomalies`, Bearer e `require_admin`, com `CRYPTO_LAB_ENABLED=true` e nova `CRYPTO_LAB_ANOMALY_ENABLED=true`, ambas `false` por padrão. Não exigir flags da cifra ou dos ataques: os controles são independentes. Restringir a `development`, `test`, `testing` ou `local`, `DEBUG=false`, um worker e uma instância; não registrar rotas em produção. A publicação efetiva deve ser apenas em `127.0.0.1` e verificada operacionalmente; flags não garantem topologia nem bloqueiam acesso de rede por si sós.

- `POST /datasets` aceita somente `{"profile":"synthetic-security-v1"}` com tipos estritos e `extra='forbid'`; não aceita upload, logs, seed livre, identidade, URL ou features. Retorna 202 com `job_id` aleatório e `status: "running"`. A geração deve produzir os agregados e rótulos em memória, sem persistir eventos brutos; o resultado concluído inclui um `dataset_id` aleatório e apenas metadados agregados de versão, partições, volumes e parâmetros.
- `POST /runs` aceita apenas `{"dataset_id":"UUID"}` de dataset próprio, completo e não expirado; agenda o ajuste, a calibração e a avaliação de ambos os métodos. Retorna 202 com `job_id` e estado. O cliente não fornece código, modelo, hiperparâmetros, limiar ou dados arbitrários.
- `GET /jobs/{job_id}` retorna estado `running`, `completed`, `timed_out` ou `failed`, tipo do trabalho, duração monotônica e, quando concluído, `dataset_id` ou `result_id`. `GET /results/{result_id}` retorna somente ao mesmo ADMIN `schema_version`, `scope: "synthetic_only"`, versões, configuração, divisão, suporte, estado, duração e métricas agregadas por conjunto e método, limiares e contagens por família; `null` e motivos para métricas indefinidas. UUID não é autorização: objeto alheio, inexistente ou expirado recebe o mesmo 404. Sem listagem global ou acesso a dados individuais.

Modelos, datasets agregados, jobs e resultados são **efêmeros em memória por processo** e isolados por proprietário; reinício os elimina. Limite proposto: um dataset de até 6.000 janelas e **5 MiB serializados** por processo, até 10 resultados agregados de no máximo **64 KiB cada**, todos com expiração de **15 minutos** após conclusão; limpar expirados e não remover trabalho ativo silenciosamente. No máximo um trabalho de geração ou análise ativo por processo, sem fila, e orçamento compartilhado com trabalhos de ataque da Etapa 5 para evitar cargas pesadas simultâneas; o coordenador compartilhado é proposta de integração futura, a ser testada sem mudar os contratos dos ataques. Uma geração ou análise em processo filho novo, sem herdar memória dos stores de segredos e sem acesso a serviços de aplicação, recebe somente parâmetros permitidos ou features/rótulos sintéticos limitados; não recebe tokens ou contexto HTTP. Executar fora do event loop e fora do pool compartilhado da API, sem rede nem banco no trabalho. Impor **120 segundos de relógio monotônico**, configurável para valor positivo até esse teto, e limites iniciais de **512 MiB de memória e um núcleo/threads numéricas limitadas a 1**, além dos limites de amostras; confirmar implementação e compatibilidade da imagem antes de habilitar. Timeout, falha, parada e morte do pai devem encerrar e recolher o filho; se o isolamento, os limites ou a limpeza não puderem ser garantidos, falhar fechado. Não desserializar `pickle` ou modelos enviados por clientes; não exportar modelos nesta etapa.

Corpo HTTP máximo **1.024 bytes antes do parsing**, inclusive sem `Content-Length`; até **uma criação aceita por ADMIN a cada 60 segundos**, **10 trabalhos por processo por hora** e **60 consultas por ADMIN por minuto**, com estado atômico e efêmero; excedente 429, capacidade ocupada ou configuração inválida 503. Uma implementação pode adotar limites mais conservadores se necessário, documentando-os. Para rotas novas: 400 JSON/UTF-8 malformado; 401 sem autenticação; 403 sem ADMIN; 404 em produção ou objeto não acessível; 413 corpo excessivo; 422 entrada inválida sanitizada; 429 frequência; 503 indisponibilidade/capacidade; 500 genérico para erro inesperado. Aplicar `Cache-Control: no-store` em respostas e erros, inclusive rejeições anteriores à autenticação. Não refletir entrada, tokens ou stack traces; proibir captura de corpo e cabeçalhos sensíveis em logs, proxy e APM. O limite de 1.024 bytes é novo para esse prefixo e deve ser implementado sem alterar o limite atual dos demais endpoints.

Para a Etapa 7, manter contrato agregado versionado, rótulos sintéticos, denominadores, modelos, versões, limiares, matriz de confusão, alertas e métricas por partição e família. O dashboard poderá exibir resultados efetivamente calculados, distinguidos de dados reais e de treinamento; não armazenar histórico, construir frontend, emitir alerta operacional ou alegar Big Data nesta etapa. Caso posteriormente se deseje persistir dados, consumir logs reais ou executar inferência contínua, isso requer desenho separado de privacidade, coleta completa, retenção, acesso, custos, avaliações com rótulos confiáveis e governança.

### 6. Estratégia futura de testes e critérios de conclusão

- **Unitários:** testar geração reprodutível com semente fixa, valores e tipos permitidos, ausência de PII/segredos, limites e cenários mistos; partições cronológicas, separação de episódios/fluxos, amostras copiadas e variantes; cálculo das janelas, features e razões sem denominador; sentido de score, limiar/empates, baseline com escala zero e cálculo de matriz, precisão, recall, F1, falsos positivos e negativos, inclusive classes ou denominadores ausentes. Confirmar que mudanças em rótulos de teste não alteram o ajuste nem os limiares.
- **Integração:** provar que gerador e detector não acessam logger real, stores de chaves, serviço AES, modelo de transações nem banco financeiro; que métricas e logs existentes mantêm seus contratos; que payloads extras, dados arbitrários e modelos externos são recusados. Verificar reprodutibilidade com versões registradas, propriedade e expiração dos objetos, limite de memória/volume e de saída, concorrência compartilhada, indisponibilidade fora do ambiente permitido, timeout, término e recolhimento do filho inclusive em morte abrupta do pai, sem bloquear a API. Inspecionar resultados, erros e logs com marcadores fictícios e segredos de teste conhecidos, sem extrapolar a inspeção para infraestrutura externa.
- **HTTP e regressão:** usar API, banco de autenticação e contas fictícias isolados; validar flag geral e específica desligadas isoladamente, produção 404, anônimo 401, USER 403, ADMIN autorizado, objeto de outro ADMIN 404, 400/413/422 sanitizados, 429/503, `no-store`, timeout e recuperação de resultados somente após conclusão. Conferir publicação Docker efetiva em loopback, recursos e limpeza, sem usar dados nem volumes reais. Repetir os fluxos e testes existentes de autenticação, logging, AES, cifra didática, esteganografia e experimentos criptográficos antes/depois; observar que o orçamento compartilhado pode recusar concorrência pesada sem alterar resultados ou contratos previamente concluídos.
- **Conclusão objetiva:** (1) geração e análise executam somente sobre o catálogo sintético, dentro dos limites, com isolamento e autorização comprovados; (2) separação de dados, ajuste, calibração, avaliação e comparação com baseline seguem o protocolo e são verificáveis; (3) métricas reais, denominadores, falsos positivos/negativos e limitações são registrados sem inventar desempenho ou exigir um valor mínimo arbitrário; (4) testes unitários, de integração, HTTP e regressão passam e respectivas evidências são documentadas; (5) resultado agregado versionado é adequado ao futuro dashboard e não contém dados sensíveis. Falhas, cenários não executados e limitações permanecem explícitos.

### 7. Decisões pendentes antes da implementação

Confirmar a aprovação do uso **exclusivamente sintético**, inclusive o evento adicional de requisição que não existe nos logs atuais; a definição de janela, orçamento de 6.000 janelas e prevalência proposta de 10% nas partições rotuladas; o Isolation Forest com baseline e calibração pelo percentil 99; e os limites operacionais, inclusive o compartilhamento da vaga com a Etapa 5. Validar a disponibilidade e o custo de CPU/memória da versão efetiva de `scikit-learn` na imagem e a viabilidade de processo isolado e término forçado no Docker local. Definir se a professora exige volume maior, métricas adicionais ou alguma forma de persistência: qualquer ampliação de escopo, consumo de eventos reais ou retenção durável requer desenho próprio antes da implementação.

## Implementação da Etapa 6 — Detecção de Anomalias com IA

A Etapa 6 acrescenta `app/crypto_lab/anomaly_lab/` com `generator.py`, `features.py`, `models.py`, `evaluation.py`, `worker.py`, `runner.py`, `schemas.py`, `routes.py` e `__init__.py`. `app/crypto_lab/heavy_capacity.py` fornece uma vaga não bloqueante compartilhada pelos coordenadores de ataques e anomalias; a admissão e a liberação da Etapa 5 foram adaptadas em `attacks/runner.py`, sem alteração do contrato de seus endpoints. A montagem das rotas e a finalização foram integradas em `app/main.py`; `settings.py` e `middleware.py` receberam a flag, o timeout e o limite de corpo próprios. O logger de segurança existente não foi modificado nem é fonte de dados para o detector.

### Dataset e método efetivamente implementados

O catálogo `synthetic-security-v1` usa semente pública `20261116`, subfluxos aleatórios independentes por partição e eventos fictícios criados internamente; não há ingestão de logs, uploads ou dados financeiros. Cada fluxo/episódio sintético contém uma janela de cinco minutos, com tempos UTC artificiais sem sobreposição e até 32 eventos. As partições têm 4.200 janelas normais de treino, 600 normais de calibração, 540 normais e 60 anômalas na validação e a mesma composição no teste. As quatro famílias são falhas de login, acessos negados, volume de requisições e atividade administrativa. Os cenários de validação e teste variam suas intensidades. O evento `SYNTHETIC_REQUEST_OBSERVED` é criado somente no gerador e não existe no logger real. Os eventos são convertidos em contagens e razões por janela; os dados brutos não são retornados nem persistidos.

O Isolation Forest usa `n_estimators=100`, `max_samples=256`, `contamination="auto"`, `max_features=1.0`, `bootstrap=false`, `n_jobs=1` e `random_state=42`. O baseline usa mediana e desvio absoluto mediano do treino, escala `1.4826 * MAD` e substituição de escala zero por 1; seu escore é o maior desvio absoluto padronizado. Cada modelo ajusta seus parâmetros apenas no treino normal. O limiar é o percentil 99 dos scores da calibração normal, com interpolação linear; score estritamente maior que o limiar gera alerta. O resultado registra empates e fração de alertas na calibração, matriz de confusão com linhas reais e colunas preditas, suporte, prevalência, precisão, recall, F1, taxa de falsos positivos e contagens por família. Razões indefinidas retornam `null`, denominador e motivo.

**Limitações:** a divisão por tempo, fluxo e episódio evita compartilhamento de registros entre partições, mas o teste continua vindo do mesmo gerador sintético; não mede generalização para logs reais, fontes desconhecidas ou tráfego de produção. O score não é probabilidade de ataque nem atribuição causal. O limite de 32 eventos por janela e as distribuições do catálogo são decisões de simulação, não estatísticas da FINK. Não se realiza detecção operacional nem bloqueio automático.

### Endpoints e isolamento implementados

Com `CRYPTO_LAB_ENABLED=true` e `CRYPTO_LAB_ANOMALY_ENABLED=true`, em ambiente local permitido, `DEBUG=false` e instância/worker únicos, os endpoints ADMIN são:

- `POST /api/v1/crypto-lab/anomalies/datasets`, corpo `{"profile":"synthetic-security-v1"}`, retorna 202 com `job_id` e estado.
- `POST /api/v1/crypto-lab/anomalies/runs`, corpo `{"dataset_id":"UUID"}`, retorna 202 com `job_id` e estado.
- `GET /api/v1/crypto-lab/anomalies/jobs/{job_id}` retorna estado, versão, escopo, duração e, após sucesso, identificador do dataset com metadados ou identificador do resultado.
- `GET /api/v1/crypto-lab/anomalies/results/{result_id}` retorna `result_id` e `result`, com `schema_version`, `scope: "synthetic_only"`, versões, catálogo, features, parâmetros, limiares e métricas agregadas por partição e método. Objetos de outro proprietário, ausentes ou expirados retornam 404.

A flag de anomalias é desabilitada por padrão e independe das flags da cifra e dos ataques. Em produção as rotas não são registradas. Respostas seguem sanitização e `no-store` do middleware do laboratório; corpos dessas rotas são limitados a 1.024 bytes. O estado é somente em memória por processo, com um dataset de até 5 MiB, até 10 resultados de até 64 KiB e expiração de 15 minutos. Há um trabalho pesado por processo entre Etapas 5 e 6, sem fila; a Etapa 6 limita inícios a um por ADMIN por 60 segundos e dez por hora no processo, além de 60 consultas por ADMIN por minuto. Assim, após criar um dataset, aguardar o cooldown antes de solicitar sua análise.

A execução é limitada a Docker Linux e acontece em novo processo com ambiente mínimo, threads numéricas limitadas a uma e `IsolationForest.n_jobs=1`, teto de 512 MiB de espaço de endereçamento e prazo configurável `CRYPTO_LAB_ANOMALY_TIMEOUT_SECONDS` maior que zero e até 120 segundos. O filho instala temporizador, limite de CPU e sinal de morte do pai; `libseccomp.so.2` é necessária para recusar chamadas de socket, falhando o trabalho se a configuração não puder ser aplicada. A API retorna estado de falha genérico se a preparação ou a execução falhar. O processo não herda os stores da API, mas o mecanismo não é uma sandbox geral de arquivos: manter implantação, permissões e ambiente Docker isolados. A publicação em loopback e a topologia precisam de verificação operacional. O processo não grava modelo em disco nem aceita modelos serializados do cliente.

### Resultados efetivamente observados e validação

Em execução sintética local dentro de contêiner descartável, com limite de 512 MiB e sem rede, a imagem disponível carregou **scikit-learn 1.9.1 e NumPy 2.4.6**. O gerador produziu **78.760 eventos**. No conjunto de teste de 600 janelas, com 540 normais e 60 anômalas, foram observados:

| Método | Matriz `[[TN, FP], [FN, TP]]` | Precisão | Recall | F1 |
|---|---:|---:|---:|---:|
| Isolation Forest | `[[527, 13], [59, 1]]` | 0,0714 | 0,0167 | 0,0270 |
| Baseline robusto | `[[533, 7], [24, 36]]` | 0,8372 | 0,6000 | 0,6990 |

Os limiares observados nessa execução foram aproximadamente 0,645262 para o Isolation Forest e 3,0 para o baseline. Esta comparação resulta de uma única configuração sintética; em particular, o baixo recall do Isolation Forest deve ser relatado, não corrigido por ajuste ao teste nem generalizado para dados reais. A execução que produziu esta tabela chamou gerador e análise diretamente no contêiner, não foi uma medição HTTP.

A suíte completa executada em Docker, com código local montado somente para leitura, apresentou **175 testes aprovados, 1 ignorado, 52 subtestes aprovados e 11 avisos**. Incluiu geração e análise em processos isolados, testes da API via transporte ASGI em memória, timeout e limpeza, bloqueio de sockets, compartilhamento de capacidade e regressão das etapas anteriores. Não foi realizada nesta execução uma validação HTTP por rede com banco e contas de teste, nem foi testada diretamente a morte abrupta do pai para a Etapa 6; esses cenários foram exercitados posteriormente na validação HTTP descrita abaixo. A inspeção de logs e isolamento de infraestrutura externa também não foi uma auditoria de segurança.

Para validar a suíte no Terminal do Mac, na raiz do backend, com a imagem `fink-backend-api` disponível e acesso à rede para instalar ferramentas apenas no contêiner descartável:

```bash
docker run --rm -v "$PWD:/workspace:ro" -w /workspace --entrypoint sh fink-backend-api -lc 'pip install pytest==9.2.0 pytest-asyncio==1.5.0 pytest-cov==7.1.0 && OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python -m pytest -o addopts="" -p no:cacheprovider --no-cov -q'
```

A montagem somente de leitura usa o código local, enquanto dependências de base vêm da imagem; a versão de `libseccomp`, biblioteca numérica e dependências transitivas pode variar. Não executar seeds sobre banco principal nem usar dados reais. A validação HTTP descrita abaixo usou banco e contas descartáveis, publicação conferida em `127.0.0.1`, flags apropriadas e limpeza de recursos sem apagar volumes.

## Validação da Etapa 6 — Detecção de Anomalias com IA

A suíte completa no Docker registrou **175 testes aprovados, 1 ignorado, 52 subtestes aprovados e 11 avisos**, sem falhas. A execução HTTP posterior de `scripts/anomaly_http_smoke.py` no Docker local terminou com **0 FAIL e 2 SKIP**. O script verificou a correspondência dos arquivos selecionados da imagem com o código local. A imagem usada foi `sha256:87679b1a41ba254ed41f2a8d66617b38e14160459dfcbc83d678d7e9f691d4bf`.

A geração do dataset e a avaliação dos dois métodos foram concluídas por HTTP. O script conferiu versões, partições, denominadores e consistência das métricas retornadas, incluindo a taxa de falsos positivos. No teste sintético de 600 janelas (540 normais e 60 anômalas), foram observados os seguintes resultados.

| Método | Matriz `[[TN, FP], [FN, TP]]` | Precisão | Recall | F1 |
|---|---|---:|---:|---:|
| Isolation Forest | `[[527, 13], [59, 1]]` | 0,07142857 | 0,01666667 | 0,02702703 |
| Baseline robusto | `[[533, 7], [24, 36]]` | 0,83720930 | 0,6 | 0,69902913 |

Passaram as verificações de autorização (anônimo, USER e ADMIN), desativação individual das flags geral e de anomalias, limites de entrada, isolamento de objetos entre administradores e recusa de trabalhos concorrentes entre as Etapas 5 e 6 nos dois sentidos. O processo filho terminou no teste de timeout e após `SIGKILL` da API descartável, enquanto o contêiner permanecia ativo. Os fluxos de AES-256-GCM, cifra didática, esteganografia e ataques didáticos funcionaram após a análise. A inspeção confirmou a publicação das portas em `127.0.0.1`. Os contêineres e a rede temporários foram removidos.

1. **SKIP — ausência de vazamento no ajuste e na calibração.** A auditoria do catálogo da imagem verificou a separação de partições, episódios e fluxos. O HTTP expõe somente agregados e não permite comprovar independentemente quais registros foram usados internamente no ajuste e na calibração.
2. **SKIP — valores internos das chaves nos logs.** Os valores internos das chaves não são expostos ao cliente. Os valores sensíveis fictícios conhecidos estavam ausentes dos logs dos contêineres inspecionados.

As métricas descrevem exclusivamente o catálogo e a configuração sintéticos avaliados. O resultado do baseline e o baixo recall do Isolation Forest nessa execução não permitem estimar o desempenho em tráfego ou incidentes reais.

Para reproduzir, executar na raiz do backend com Docker e as imagens locais `fink-backend-api` e `postgres:16` disponíveis.

```bash
python3 scripts/anomaly_http_smoke.py
```

## Camada persistente e ingestão sintética controlada

A migração `20261117_secureai_events.py` cria `lab_events` e `lab_anomaly_runs`. A fila operacional limitada registra metadados permitidos sem bloquear as operações; falhas de banco ou encerramento abrupto podem causar perda de eventos. O histórico de análises armazena apenas resultados agregados e parâmetros, em gravação independente e de melhor esforço. Os datasets, modelos treinados e resultados temporários das rotas existentes continuam em memória; o histórico agregado em PostgreSQL é uma funcionalidade posterior às descrições de armazenamento exclusivamente temporário das etapas acima.

Em ambiente local autorizado, com `CRYPTO_LAB_ENABLED=true`, `CRYPTO_LAB_EVENT_STORE_ENABLED=true`, `DEBUG=false` e ADMIN autenticado, estão disponíveis:

- `GET /api/v1/crypto-lab/events`: eventos paginados por cursor, filtros de período, origem, tipo e resultado; até 100 por página.
- `GET /api/v1/crypto-lab/events/summary`: agregações SQL pelos mesmos filtros; período máximo de 31 dias e distribuição por dia UTC.
- `GET /api/v1/crypto-lab/anomalies/history`: histórico agregado paginado, filtrável por período e estado; requer também `CRYPTO_LAB_ANOMALY_ENABLED=true`.
- `POST /api/v1/crypto-lab/events/synthetic-ingestions`: corpo estrito `{"count":600}`; gera eventos sanitizados com origem `synthetic`, categorias fixas e identificador de execução. O volume é configurável de 1 a 10.000 por chamada; há uma ingestão por processo, lotes de até 250, prazo de três segundos por lote e orçamento total de 20 segundos. Não utiliza a fila operacional nem modifica o gerador de treinamento.

A resposta da ingestão informa `requested`, `generated`, `persisted_confirmed`, `failed_or_unconfirmed`, `not_generated`, duração e estado. Lotes são confirmados separadamente: se a conexão falhar durante o commit, o lote é contado como não confirmado, pois pode ou não ter sido gravado. Para conferir o total e as categorias, consultar o resumo com `origin=synthetic` e o período apropriado; ele inclui também outras ingestões sintéticas desse período, se existirem. Não há endpoint de escrita arbitrária. Identificadores de execução distinguem os lotes na listagem.

Exemplo de demonstração em uma API local já configurada com banco de laboratório e credencial ADMIN obtida pelo fluxo existente (não registrar o token):

```bash
curl -sS -X POST 'http://127.0.0.1:8000/api/v1/crypto-lab/events/synthetic-ingestions' \
  -H "Authorization: Bearer $LAB_ADMIN_TOKEN" -H 'Content-Type: application/json' -d '{"count":600}'
curl -sS 'http://127.0.0.1:8000/api/v1/crypto-lab/events/summary?origin=synthetic' \
  -H "Authorization: Bearer $LAB_ADMIN_TOKEN"
```

### Validação observada

Em PostgreSQL 16 descartável, com rede própria, dados em `tmpfs` e somente a migração do laboratório aplicada após conferir banco e usuário de teste, uma ingestão ADMIN solicitou, gerou e confirmou **600 eventos**, sem lote falho ou não confirmado. O resumo SQL retornou **600**, sendo **150** em cada uma das quatro categorias sintéticas. Uma cifragem AES-256-GCM real de texto fictício produziu um evento `AES_ENCRYPT` observado, confirmado após nova conexão; o marcador fictício não apareceu no campo de operação. Anônimo e USER foram rejeitados e o corpo com campo extra ou volume acima do limite foi recusado.

Foram executados 12 testes direcionados: um teste integrado de ingestão e AES, um da fila e PostgreSQL, um de consultas, um de histórico de IA e oito de emissão; todos passaram. Os testes HTTP usaram transporte ASGI e autenticação por serviço de sessão simulado, não uma API de rede ou contas reais. Cada teste PostgreSQL recebeu banco vazio próprio; a cadeia histórica de migrações não foi executada.

Para reproduzir na raiz do backend, com Docker e imagens locais `fink-backend-api` e `postgres:16`, o trecho abaixo cria apenas recursos temporários próprios e não monta código com permissão de escrita:

```bash
set -eu
net="lab-volume-test-$$"
db="lab-volume-pg-$$"
cleanup() { docker rm -f "$db" >/dev/null 2>&1 || true; docker network rm "$net" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker network create --internal "$net" >/dev/null
for module in tests.test_synthetic_ingestion_postgres tests.test_event_store_postgres tests.test_event_query_postgres tests.test_anomaly_history_postgres; do
  docker run -d --name "$db" --network "$net" --network-alias lab-disposable --tmpfs /var/lib/postgresql/data \
    -e POSTGRES_USER=labtest -e POSTGRES_PASSWORD=labtest -e POSTGRES_DB=lab_disposable postgres:16 >/dev/null
  for i in $(seq 1 60); do
    if docker exec "$db" pg_isready -U labtest -d lab_disposable >/dev/null 2>&1; then break; fi
    if [ "$i" = 60 ]; then exit 1; fi
    sleep 1
  done
  docker run --rm --network "$net" -v "$PWD:/workspace:ro" -w /workspace \
    -e LAB_DISPOSABLE_DATABASE_URL=postgresql+asyncpg://labtest:labtest@lab-disposable:5432/lab_disposable \
    --entrypoint python fink-backend-api -m unittest "$module" -v
  docker rm -f "$db" >/dev/null
done
docker run --rm --network none -v "$PWD:/workspace:ro" -w /workspace \
  --entrypoint python fink-backend-api -m unittest tests.test_event_emission -v
```

O volume é experimental e exclusivamente sintético; não comprova escalabilidade distribuída nem desempenho em produção. **Ainda não há retenção automática nem limite global de armazenamento**: sucessivas ingestões podem aumentar o banco. A fila e o histórico de melhor esforço também não garantem durabilidade em falhas abruptas. O contador `failed_or_unconfirmed` não determina o resultado de um commit interrompido.
