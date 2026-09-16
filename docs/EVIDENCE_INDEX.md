# SecureFINK - Índice de evidências

Inspeção: 2026-09-16. Backend: `2e4df81`; frontend: `d31b098`, ambos na branch `secureai-lab`.

Origem confirmada pelo responsável: `../prints relatorio/`, não `evidencias-securefink`. Foram copiados **12 arquivos (9 PNGs e 3 TXT)** para `docs/evidence/`, preservando nomes. Após a sanitização feita pelo responsável na origem, as cópias foram atualizadas e reinspecionadas. Cada cópia atual coincide em bytes com sua versão na origem (`cmp`); esta operação não alterou nem apagou os arquivos de origem.

Fonte dos requisitos: `Relatório Projeto - SecureAI Lab - Cibersegurança.pdf`, seções “requisitos obrigatórios”, “correção”, “integridade”, “segurança da IA” e “entrega”. A numeração abaixo corresponde aos 12 requisitos obrigatórios do PDF. Não se trata de evidência de HTTPS ou de segurança de produção.

## 1. Resultado da reinspeção de sanitização

Os nove PNGs foram inspecionados visualmente e os três TXT foram lidos integralmente e pesquisados por padrões sensíveis.

- Não foram encontrados senha em texto claro, hash completo de senha ou credencial Pluggy. A captura `07` mostra o prefixo/parâmetros Argon2id e início de salt, mas não um hash completo verificável.
- Usuário real do Mac, hostname e caminhos pessoais foram ocultados/removidos. Os TXT usam `$PROJECT_ROOT`, caminhos relativos e `/tmp`, sem caminhos de usuário reais.
- Não foram encontrados favoritos, abas de navegador ou informações pessoais sem relação com o projeto. As abas do DBeaver visíveis em `07` se referem à tabela do projeto.
- As pessoas e transações exibidas são as contas/dados declarados fictícios do laboratório. UUID nos logs é pseudônimo, não anonimização. SHA-256 do CSV é metadado de integridade, não credencial.
- **Exceção aceita pelo responsável em 2026-09-16:** `06-admin-200.png` mantém alguns caracteres iniciais do valor após `Authorization: Bearer`; o restante está oculto. O fragmento não é um token completo e, sozinho, não permite autenticar. O responsável autorizou manter a captura e prosseguir. Isso não equivale à ausência literal de qualquer trecho de token. Nenhum valor foi reproduzido, usado ou validado nesta inspeção.

Os alertas anteriores de hostname/caminhos foram resolvidos; a captura de Argon2id não expõe um hash completo. O conjunto foi aprovado pelo responsável para commit local, com a exceção explícita acima. Nenhum código foi alterado; push não foi autorizado nesta etapa.

## 2. Relação entre arquivos, requisitos e resultados

“Teste executado” descreve a ação registrada no arquivo, não uma nova execução feita nesta inspeção. Os testes automatizados relacionados estão identificados na seção 3 e pertencem à suíte existente. Uma captura de interface não comprova, por si só, todas as propriedades do backend. Os TXT foram sanitizados pelo responsável: caminhos são representações normalizadas e `09` é um resumo da saída, não o registro bruto integral.

| Arquivo | Requisito do PDF | Teste executado / relacionado | Resultado observado | Conclusão técnica |
|---|---|---|---|---|
| [01-perfil-user.png](evidence/01-perfil-user.png) | 1 autenticação; 5 dados fictícios; 8 autorização; aplicação funcional | Visualização do perfil da conta USER; T-A (perfil próprio). Frontend `614cc53`. | Perfil exibe Fulano, campos pessoais e avatar genérico; upload disponível. | Evidência visual da identidade fictícia conectada ao fluxo de perfil, sem identidade hardcoded de Gabriel. A captura não mostra a requisição nem comprova limpeza da sessão/troca de conta. |
| [02-upload-normal-ia.png](evidence/02-upload-normal-ia.png) | 6 arquivos; 10 hash; 11 IA | Upload de `examples/transacoes_exemplo.csv`; T-U e T-I. | 3 registros; Alimentação, Transporte e Educação, um de cada; confiança 75,8%, 70,9% e 73,2%; nenhuma linha sinalizada; SHA-256 exibido. | Upload e sugestão local integrados à interface. Esses números são saídas de confiança do modelo, não acurácia medida. |
| [03-risco-ia.png](evidence/03-risco-ia.png) | 11 IA; cenário de risco e mitigação de IA | Upload de `examples/transacoes_risco_ia.csv`; T-I. | 4 registros, todos com “Revisão necessária”; confiança 0%, 20,8%, 64,7% e 0%; resumo Outros 2, Alimentação 1, Saúde 1. | Desconhecimento/ambiguidade são sinalizados, inclusive quando a confiança supera 55%. Mitigação exige revisão humana, mas não garante categoria correta; risco é evasão/manipulação de entrada, não prompt injection de LLM. |
| [04-anonimo-401.png](evidence/04-anonimo-401.png) | 1 autenticação; 4 API; 8 acesso; reteste | `curl -i http://localhost:8000/api/v1/pessoas/`, sem Authorization; T-A. | `401 Unauthorized`, challenge Bearer e mensagem de token ausente/inválido. | A lista de pessoas não é mais acessível anonimamente. Evidência do estado posterior à correção de SB-02. |
| [05-user-403.png](evidence/05-user-403.png) | 2 privilégios; 8 autorização; reteste | Leitura da lista administrativa no Swagger, identificada como USER pelo responsável; T-A. | `/api/v1/pessoas/` retorna `403`, “Acesso exclusivo para administradores”. | Bloqueio de usuário não administrador. A captura recorta o contexto de login; a identidade/flag do solicitante é corroborada pelo teste automatizado, não exibida nela. |
| [06-admin-200.png](evidence/06-admin-200.png) | 2 privilégios; 4 API; 5 dados fictícios; 8 autorização | `GET /api/v1/pessoas/` com Bearer administrativo parcialmente oculto; T-A. | `200`, lista com dados fictícios de Fulano/Sicrano; nenhum campo senha/hash visível na resposta. | A rota continua funcional para ADMIN. O `admin: false` do primeiro objeto é da pessoa listada, não do solicitante. Os caracteres iniciais remanescentes não equivalem a token utilizável; sua manutenção foi explicitamente aceita pelo responsável. |
| [07-argon2-dbeaver.png](evidence/07-argon2-dbeaver.png) | 3 banco; 9 proteção criptográfica; proteção de senhas e reteste | Inspeção de `pessoa` no DBeaver; T-P. | Coluna `senha_hash` com prefixo `$argon2id$`, versão 19 e parâmetros `m=65536,t=3,p=4` em três contas. | Persistência usa formato Argon2id, em lugar do campo semântico `senha`. A captura é truncada: não comprova digest completo, salts distintos ou login; T-P cobre essas propriedades. |
| [08-logs-seguranca.txt](evidence/08-logs-seguranca.txt) | 12 eventos de segurança; pseudonimização/proteção de dados | Registro sanitizado de `docker compose logs --since 30m api` filtrado pelos quatro eventos; T-L. | LOGIN_SUCCESS, LOGIN_FAILURE, ACCESS_DENIED e ADMIN_ACCESS, com timestamp, resultado, método/rota e UUID quando disponível. | Os eventos exibidos não contêm senha/token/email/telefone/conteúdo financeiro. UUID é pseudônimo, não anonimização. O filtro não comprova ausência de dados em todos os access logs. |
| [09-testes-73-passed.txt](evidence/09-testes-73-passed.txt) | Correção, reteste e entrega de resultados | Resumo sanitizado da execução de `docker compose run --rm api sh -lc 'poetry install --with dev --no-interaction && poetry run pytest'`. | **73 passed, 11 warnings in 5.10s**; cobertura global registrada de 61%; avisos resumidos pelo responsável. | Suíte completa daquele estado aprovada; avisos de depreciação permanecem. Cobertura não mede ausência de vulnerabilidades. O resumo concorda com a verificação final anterior, mas não preserva a saída individual dos avisos/casos. |
| [10-integridade-sha256-og.png](evidence/10-integridade-sha256-og.png) | 6 arquivos; 10 integridade | Upload do CSV original; T-U. | 3 registros; SHA-256 começa por `f208efea` e termina por `5ae36a0`. | Digest da API coincide com o original registrado no TXT e com `shasum` executado nesta inspeção. |
| [10-integridade-sha256-alterado.png](evidence/10-integridade-sha256-alterado.png) | 10 integridade; demonstração de alteração | Upload do CSV com descrição alterada; T-U. | 3 registros; SHA-256 começa por `484f6094` e termina por `ac701a6`, diferente do original. | A mudança de bytes é detectável comparando os digests, mesmo com a mesma contagem de linhas. A aplicação não rejeita automaticamente um arquivo por diferir de outro e não verifica autoria. |
| [10-integridade-sha256.txt](evidence/10-integridade-sha256.txt) | 10 função hash e demonstração de alteração | Cópia local do exemplo, substituição de `restaurante` por `restaurante alterado` e `shasum -a 256` nos dois arquivos. | Dois digests completos distintos, correspondentes às capturas original/alterada. | Corrobora o SHA-256 retornado pela API sobre bytes originais. O arquivo alterado não faz parte deste pacote; a sequência de comandos registra como reproduzir a alteração. |

## 3. Testes e commits existentes que corroboram as capturas

- **T-P - `tests/test_password_security.py`:** `test_persisted_password_differs_from_plaintext`, `test_persisted_password_uses_argon2id_format`, `test_same_password_receives_distinct_salted_hashes`, `test_login_accepts_correct_password`, `test_login_rejects_incorrect_password`, `test_registration_response_never_contains_password_hash` e `test_public_registration_rejects_admin_field`. Correção `5ec2982` (Argon2id, schemas, serviços, seed e migração Alembic).
- **T-A - `tests/test_access_control_characterization.py`:** `test_administrative_people_list_matches_secureai_matrix` com anônimo `401`, USER `403` e ADMIN `200`; `test_own_profile_matches_secureai_matrix`, `test_other_users_profile_matches_secureai_matrix` e `test_only_documented_public_endpoints_lack_authentication`. Caracterização `94dc435`; correção `ed6a91d`, mantendo booleano `admin` e usando `get_current_user`/`require_admin`.
- **T-U - `tests/test_csv_upload.py`:** `test_valid_upload_returns_metadata_and_preview`, `test_returned_sha256_matches_the_original_bytes`, `test_upload_without_authentication_returns_401`, validações de extensão/tamanho/encoding/cabeçalhos/linhas/contagem, ausência de dados nos logs e `test_upload_does_not_modify_or_expand_training_data`. Upload `88e18ef`; integração IA `1568edc`.
- **T-I - `tests/test_ai_classifier.py`:** `test_representative_descriptions_receive_coherent_categories`, `test_result_is_deterministic`, `test_category_always_belongs_to_allowlist` e `test_unknown_ambiguous_or_empty_description_requires_review`. Backend `1568edc`; exibição frontend `e6e84c7`. Treino fictício versionado, não alimentado por uploads.
- **T-L - `tests/test_security_logging.py`:** `test_login_success_is_structured_and_redacted`, `test_login_failure_is_structured_and_redacted`, `test_access_denied_event_is_emitted_for_anonymous_request` e `test_admin_access_event_contains_only_admin_id_and_route`. Correção `f2fe8bf`.
- **Fechamento:** `c3ba1a9` desabilita Pluggy e restringe solicitações de pagamento a ADMIN; `tests/test_lab_hardening.py` acrescenta os 16 casos que levam a suíte de 57 a 73 testes. `2e4df81` atualiza análise/uso de IA. Frontend `d31b098` remove dados pessoais hardcoded legados.

O TXT da suíte é um resumo sanitizado de uma execução agregada: não contém uma saída individual de cada caso. Nesta organização/reinspeção não foram reexecutadas a suíte nem a aplicação vulnerável; foram inspecionados registros, código histórico e testes existentes.

## 4. Três demonstrações: antes, correção e reteste

### 4.1 SB-01: senha em texto claro -> Argon2id

1. **Antes:** `SECURITY_BASELINE.md`, SB-01, registra consulta mascarada sobre `pessoa.senha`: sete caracteres, sem prefixo hash. O código-base `fb0aea8` persiste a entrada e compara `pessoa.senha != senha`. A senha clara não deve ser mostrada no relatório.
2. **Correção:** `5ec2982`; coluna `senha_hash`, Argon2id com salt, migração dos registros legados, cadastro/login/seed atualizados e hash excluído da resposta.
3. **Reteste:** captura `07` mostra o formato persistido; T-P, incluído nos 73 testes aprovados do arquivo `09`, comprova diferença da entrada, formato, salts distintos, login correto/incorreto e resposta sem hash.
4. **Limite:** o pacote não contém screenshot do banco vulnerável; a evidência anterior é textual no baseline e verificável pelo código histórico. A captura `07` não exibe hashes completos e não comprova, isoladamente, a verificação de senha ou salts distintos.

### 4.2 SB-02: acesso anônimo 200 -> 401

1. **Antes:** `SECURITY_BASELINE.md`, SB-02, registra `200` para `GET /api/v1/pessoas/` sem Authorization. Em `94dc435`, `list_pessoas` não possui guarda de autenticação; o caso anônimo que espera `401` é `XFAIL` estrito.
2. **Correção:** `ed6a91d`; rota passa a exigir `require_admin`, que resolve o usuário autenticado antes de verificar o papel.
3. **Reteste:** mesma leitura sem Bearer na captura `04` retorna `401`; T-A confirma esse caso na suíte `09`. ADMIN continua com `200` na captura `06`.
4. **Limite:** não há screenshot do `200` anterior neste pacote; usar o registro real do baseline, sem apresentar a captura `04` como evidência de exploração anterior.

### 4.3 SB-03: USER em rota administrativa 200 -> 403

1. **Antes:** `SECURITY_BASELINE.md`, SB-03, registra que `admin=false` não impede alcançar operações administrativas. Em `94dc435`, `list_pessoas` ignora token/papel e retorna a lista; a caracterização USER que espera `403` é `XFAIL` estrito. Com a lista fictícia da fixture, esse handler retorna `200`, tal como para anônimo/ADMIN.
2. **Correção:** `ed6a91d`; `require_admin` verifica o booleano existente e nega acesso a usuário não administrador, sem enum ou nova migração.
3. **Reteste:** captura `05` mostra `403`; T-A verifica explicitamente USER `403` e ADMIN `200`, agora sem `XFAIL`, na suíte `09`. A captura `06` corrobora o sucesso administrativo.
4. **Limite:** não há captura/resposta HTTP arquivada de USER `200` antes da correção. O comportamento anterior é sustentado pelo handler e fixture históricos, não por uma nova execução ou screenshot. Um `XFAIL` isolado não prova seu motivo; por isso o índice o cruza com o código. Não inventar uma captura anterior na apresentação.

Essas três demonstrações não substituem a análise de acesso a recurso de outro usuário, registrada em `SECURITY_ANALYSIS.md`; o reteste representativo de perfil está em T-A e o reteste específico de propriedade de sessões continua pendente.

## 5. Reteste reproduzível no estado corrigido

Com Docker local disponível, o mesmo conjunto automatizado pode ser repetido sem Pluggy externa:

```bash
docker compose run --rm --no-deps api sh -lc 'poetry install --with dev --no-root && poetry run pytest tests/test_password_security.py tests/test_access_control_characterization.py'
curl -i http://localhost:8000/api/v1/pessoas/
shasum -a 256 examples/transacoes_exemplo.csv
```

O `curl` não envia credenciais e deve retornar `401`. Para demonstrar USER/ADMIN manualmente, autenticar contas fictícias locais no Swagger e mostrar apenas URL/status/body; ocultar o header Authorization e a resposta de login. Não inserir tokens no documento ou no Git. Nenhum ambiente vulnerável foi iniciado e nenhuma chamada externa foi realizada nesta organização de evidências.
