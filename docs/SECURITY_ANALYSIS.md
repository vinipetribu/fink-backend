# SecureFINK - Análise de Segurança

Data da atualização: 2026-09-16

Escopo: branches locais `secureai-lab` de backend e frontend, com dados fictícios e execução em `localhost`.

Este documento resume o threat modeling e as evidências que alimentam o relatório final do SecureAI Lab. As afirmações de implementação são limitadas ao código, commits e testes existentes. Itens ainda não entregues são marcados como **Pendente**.

## 1. Contexto e público-alvo

O SecureFINK é uma aplicação web de organização e educação financeira. O fluxo existente permite autenticar pessoas, consultar o próprio perfil, acompanhar metas e movimentações, administrar catálogos e validar um CSV de transações sem persistir o arquivo.

O público-alvo funcional é formado por pessoas que organizam informações financeiras fictícias no papel `USER` e por operadores do sistema no papel `ADMIN`. No contexto acadêmico, a aplicação também serve para demonstrar o ciclo vulnerabilidade, exploração local, correção e reteste exigido pelo SecureAI Lab.

## 2. Arquitetura resumida

```text
Navegador / Next.js
  |  Bearer token (localStorage - risco residual aceito temporariamente)
  v
FastAPI
  |-- autenticação, RBAC e regras de propriedade
  |-- upload CSV temporário, validado em memória
  |-- classificação local TF-IDF + regressão logística, somente sugestões
  |-- logs de segurança JSON no stdout
  v
PostgreSQL
  |-- pessoas, hashes de senha, hashes de sessão e dados da aplicação

Redis
  |-- provisionado pelo Docker, sem uso ativo encontrado no código atual

Pluggy
  |-- PLUGGY_ENABLED=false: cliente não inicializado e chamadas bloqueadas
```

- Frontend: Next.js; autentica, guarda temporariamente a sessão no `localStorage`, consulta perfil e envia `multipart/form-data`.
- Backend: FastAPI; expõe API, valida Bearer token e aplica `get_current_user` e `require_admin`.
- Banco: PostgreSQL; persiste pessoas, sessões e entidades financeiras da aplicação.
- Redis: contêiner, dependência e `REDIS_URL` existem, mas não há consumo comprovado pela aplicação.
- Upload: `POST /api/v1/uploads/csv`; processa o arquivo temporariamente, calcula SHA-256 dos bytes originais e não cria armazenamento permanente.
- IA: classifica descrições com dados fictícios versionados, retorna categoria, confiança, revisão e resumo; não aprende com uploads nem executa decisões financeiras.
- Pluggy: desabilitada por padrão na configuração e no código; rotas autenticadas retornam `503` sem acessar cliente externo quando desabilitada.
- Info público: `GET /api/v1/info` retorna somente nome e versão, sem debug ou ambiente.

## 3. Ativos e usuários

### Ativos

| Ativo | Valor de segurança |
|---|---|
| Credenciais | Senha recebida no login e hash Argon2id persistido |
| Sessões | Bearer token entregue uma vez ao cliente e `token_hash` no banco |
| Dados pessoais fictícios | Nome, email, telefone, nascimento, gênero e endereço |
| Dados financeiros fictícios | Metas, movimentações, assinaturas, solicitações e valores de CSV |
| CSV | Conteúdo temporário, nome original, SHA-256, contagem e prévia |
| API | Rotas, regras de autenticação, autorização e validação |
| PostgreSQL | Fonte persistente dos registros da aplicação |
| Logs | Evidência operacional e de eventos de segurança |
| Segredos de configuração | Credenciais e chaves destinadas ao ambiente local |

### Usuários e privilégios

| Ator | Acesso atual esperado |
|---|---|
| Anônimo | Health/info, cadastro, login e leitura de planos |
| `USER` | Rotas autenticadas e recursos próprios; não administra pessoas ou catálogos |
| `ADMIN` | Rotas administrativas de pessoas, planos, tipos e solicitações de pagamento; estas últimas estão fora do fluxo demonstrado e restritas integralmente a ADMIN |

O papel continua representado pelo booleano `admin`. O cadastro público rejeita esse campo.

## 4. Superfícies de ataque

| Superfície | Exposição relevante |
|---|---|
| Login | Tentativas de credencial, enumeração, força bruta e criação de sessão |
| API | Rotas públicas e autenticadas, entrada JSON, CORS e tratamento de erros |
| IDs de recursos | UUIDs/IDs em paths podem ser trocados para tentar acesso horizontal |
| Upload | Extensão, tamanho, encoding, cabeçalhos, linhas, quantidade e conteúdo malformado |
| `localStorage` | JavaScript executado na origem pode ler token e IDs da sessão |
| PostgreSQL | Concentra hashes, dados pessoais e entidades financeiras fictícias |
| Logs/stdout | Podem expor entradas, segredos ou dados pessoais se não houver allowlist |
| Pluggy | Código externo presente, mas bloqueado por `PLUGGY_ENABLED=false`; vínculo de IDs é obrigatório antes de habilitar |
| IA local | Descrições ambíguas ou manipuladas podem induzir uma sugestão incorreta |
| Redis | Serviço provisionado, embora sem uso ativo comprovado pela aplicação |

## 5. Dados tratados e confidencialidade

| Classe | Dados | Tratamento atual |
|---|---|---|
| Público | Health, info e leitura de planos | Rotas públicas documentadas em teste |
| Interno | Estrutura de rotas, métricas operacionais e configuração não secreta | Código e stdout local |
| Confidencial | Nome, email, telefone, nascimento, gênero, endereço e UUID | PostgreSQL; respostas sujeitas a autenticação/propriedade |
| Restrito | Senha em trânsito, hash Argon2id, Bearer token, `token_hash` e segredos | Senha transformada antes da persistência; token claro entregue ao cliente; segredos devem ficar em `.env` |
| Restrito | Metas, movimentações, pagamentos e valores do CSV | Dados fictícios; CSV sem persistência permanente |
| Confidencial | Logs de segurança com UUID | JSON no stdout, sem email, telefone, token ou conteúdo financeiro |

As classificações expressam a proteção necessária mesmo quando os dados usados na demonstração são fictícios.

## 6. Ameaças e tríade CIA

| Pilar | Ameaças no SecureFINK | Consequência |
|---|---|---|
| Confidencialidade | Roubo do token no `localStorage`, consulta anônima/IDOR, vazamento em logs ou banco e uso indevido da Pluggy | Exposição de identidade, sessão e dados financeiros |
| Integridade | Alteração administrativa sem RBAC, manipulação de IDs, CSV adulterado e evasão do classificador por descrição ambígua | Mudança indevida de dados ou sugestão de categoria incorreta |
| Disponibilidade | Arquivo excessivo, volume de tentativas de login, consultas custosas e falha de banco/integração externa | Esgotamento de recursos ou indisponibilidade da API |

O SHA-256 detecta se os mesmos bytes do CSV foram alterados, mas não prova autoria. O limite de 1 MB e 1.000 registros reduz abuso de recursos no upload. Não foi encontrado rate limiting de login; portanto esse controle permanece pendente.

## 7. Matriz de Riscos

Escala: probabilidade (`P`) e impacto (`I`) de 1 a 5. Resultado = `P x I`. Severidade: 1-4 baixa, 5-9 média, 10-16 alta, 17-25 crítica. Os valores representam risco inerente para priorização; não são uma medição quantitativa de risco residual.

| ID | Risco | P | I | Resultado | Severidade | Controle comprovado | Situação |
|---|---|---:|---:|---:|---|---|---|
| R-01 / SB-01 | Recuperação imediata de senhas persistidas em texto claro | 4 | 5 | 20 | Crítica | Argon2id com salt; `senha_hash`; hash omitido da API | Mitigado e retestado |
| R-02 / SB-02 | Uso anônimo de endpoints administrativos ou sensíveis | 5 | 5 | 25 | Crítica | Allowlist pública; `get_current_user`; `require_admin` | Mitigado e retestado |
| R-03 / SB-03 | Acesso ou alteração de recurso de outra pessoa por troca de ID | 4 | 4 | 16 | Alta | Identidade central e propriedade; solicitações de pagamento exclusivas de ADMIN | Reteste representativo e bloqueio de pagamentos; teste específico de sessão pendente |
| R-04 / SB-04 | Furto e reutilização do Bearer token por XSS | 3 | 5 | 15 | Alta | Servidor guarda `token_hash`; logout revoga sessão | **Risco residual aceito temporariamente** apenas no laboratório; correção futura |
| R-05 / SB-05 | Exposição de credenciais ou dados em logs | 4 | 4 | 16 | Alta | `echo=False`; eventos JSON com campos permitidos | Logger de segurança mitigado e retestado; access logs e retenção residuais |
| R-06 | Abuso, parser malformado ou consumo de recursos no upload | 3 | 4 | 12 | Alta | `.csv`, UTF-8, 1 MB, 1.000 linhas, schema e validação por linha | Mitigado e retestado |
| R-07 | Interceptação de credenciais/sessões em HTTP | 3 | 5 | 15 | Alta | Demonstração exclusivamente em localhost controlado | HTTPS não aplicado no lab; TLS em proxy reverso obrigatório na implantação |
| R-08 | Consulta de conta Pluggy sem vínculo local de propriedade | 3 | 5 | 15 | Alta | Flag desabilitada, nenhum cliente inicializado ou chamada externa | Bloqueado no laboratório; ownership e testes obrigatórios antes de habilitar |
| R-09 | Evasão/manipulação da descrição para classificação incorreta | 3 | 2 | 6 | Média | Allowlist, 255 caracteres, limiar 0,55, vocabulário conhecido e revisão humana | IA implementada e retestada; erro de classificação continua possível |
| R-10 | Exposição de segredo por configuração versionada | 3 | 5 | 15 | Alta | `.env` ignorado; campos Pluggy vazios no exemplo | Exemplo sanitizado; histórico ainda contém valores antigos e rotação se válidos permanece pendente |

R-09 foi reavaliado qualitativamente após ativar a IA local: entradas ambíguas são plausíveis (P=3), mas o impacto atual limita-se a sugestões sem persistência ou ação financeira (I=2). Não são métricas empíricas nem estimativas de acurácia.

## 8. Vulnerabilidades selecionadas para demonstração

### 8.1 Senha em texto claro

- Antes: `pessoa.senha` era persistida e comparada diretamente; a consulta local descrita em `SECURITY_BASELINE.md` demonstrava o valor legível.
- Impacto: comprometimento imediato das credenciais em caso de leitura do banco, backup ou log.
- Correção: commit `5ec2982`, com Argon2id, coluna `senha_hash`, migração Alembic, cadastro/login/seed atualizados e bloqueio do campo `admin` no cadastro público.
- Reteste: `tests/test_password_security.py` comprova hash diferente, prefixo `$argon2id$`, salts distintos, login válido/inválido e ausência do hash na resposta.

### 8.2 Endpoint administrativo sem autenticação/RBAC

- Antes: `GET /api/v1/pessoas/` retornava dados sem Bearer token e sem consultar `admin`.
- Impacto: enumeração de pessoas e quebra do menor privilégio.
- Evidência de caracterização: commit `94dc435`; os casos vulneráveis foram registrados como `XFAIL` estrito.
- Correção: commit `ed6a91d`, com `get_current_user`, `require_admin` e aplicação da allowlist pública.
- Reteste: a lista retorna `401` para anônimo, `403` para `USER` e `200` para `ADMIN`; os antigos `XFAIL` passaram normalmente.

### 8.3 Acesso a recurso de outro usuário

- Antes: `GET /api/v1/sessoes/pessoa/{id_pessoa}` aceitava um ID arbitrário sem autenticação ou propriedade. Outras rotas possuíam checagens locais inconsistentes.
- Impacto: exposição horizontal de metadados de sessão e risco de atuação sobre recursos alheios.
- Correção: commit `ed6a91d`; a sessão passa por `get_current_user` e compara o ID solicitado com o usuário atual, preservando bypass administrativo explícito.
- Reteste existente: a allowlist comprova que a rota deixou de ser pública, e `test_other_users_profile_matches_secureai_matrix` comprova `403` para `USER` e `200` para `ADMIN` no recurso representativo de pessoa.
- Limite da evidência: não existe teste automatizado específico de propriedade para a rota de sessões; esse reteste exato permanece **Pendente**.

Todas as demonstrações devem ocorrer apenas em `localhost`, com dados fictícios e sem chamar a Pluggy.

## 9. Categorias do PDF não escolhidas para exploração principal

| Categoria | Justificativa baseada no estado atual |
|---|---|
| Injeção | O acesso observado usa SQLAlchemy e consultas parametrizadas; não foi demonstrado vetor explorável. Isso não equivale a garantia de ausência. |
| XSS | Não foi identificado sink reproduzível no fluxo selecionado. O impacto sobre o token no `localStorage` permanece risco residual aceito temporariamente no lab. |
| Upload inseguro | O upload não existia no baseline; foi criado já com validação e testes, sem uma versão vulnerável para explorar. |
| Falha criptográfica/integridade | Foram demonstrados controles positivos com Argon2id e SHA-256; HTTPS ainda é uma lacuna, mas não foi simulado ataque de rede. |
| Gerenciamento de sessão | O `localStorage` é um risco conhecido, mas sua correção exige cookie `HttpOnly` e defesa CSRF, fora das correções já realizadas. |
| Exposição em logs | SB-05 foi corrigido e retestado, mas não integra as três demonstrações principais para manter o relatório curto. |
| IA | Não integra as três vulnerabilidades principais do baseline; possui cenário próprio de evasão com CSV ambíguo/adversarial e mitigação documentados em `AI_SECURITY.md`. Não usa LLM nem prompt injection. |

Falhas de API e controle de acesso não foram descartadas: elas são representadas diretamente pelas demonstrações SB-02 e SB-03.

## 10. Estratégia criptográfica

- **Senhas - implementado:** Argon2id via `argon2-cffi`, com salt gerado pela biblioteca. A aplicação persiste `senha_hash`, verifica pela biblioteca e nunca inclui o hash nos schemas de resposta.
- **Integridade do CSV - implementado:** SHA-256 é calculado sobre os bytes originais e retornado com os metadados. O hash permite comparar integridade, mas não autentica a origem do arquivo.
- **Sessões - risco residual aceito temporariamente:** o Bearer token aleatório é entregue em claro uma vez; somente seu SHA-256 (`token_hash`) é persistido. O `localStorage` continua acessível a JavaScript. A aceitação limita-se à demonstração controlada com dados fictícios, não a uma autorização de uso em produção; cookie HttpOnly/CSRF não foram implementados.
- **Dados em trânsito - escopo local:** HTTPS não foi aplicado porque a demonstração ocorre exclusivamente em `localhost` controlado, sem dados reais e sem acesso remoto. Isso não protege tráfego HTTP fora desse contexto. Na implantação, TLS/HTTPS em proxy reverso com certificado válido é requisito antes de expor a aplicação. Certificados usam criptografia assimétrica para autenticar o servidor; a transferência usa chaves simétricas negociadas pelo TLS.
- **Criptografia simétrica - proposta, não implementada:** se dados financeiros reais ou arquivos fossem persistidos, os campos mais sensíveis seriam cifrados com AEAD, por exemplo AES-GCM, antes da gravação. Chaves devem ficar fora do banco, em serviço de segredos/KMS, com rotação e controle de acesso.
- **Assinatura digital - não necessária no fluxo atual:** o CSV é enviado pelo próprio usuário e não é persistido nem distribuído como documento oficial. Não há requisito atual de autoria ou não repúdio. Se surgisse intercâmbio externo verificável, a assinatura de um manifesto seria reavaliada.
- **Segredos:** `.env` local permanece fora do Git e não foi alterado. Os campos `PLUGGY_CLIENT_ID` e `PLUGGY_CLIENT_SECRET` do exemplo foram esvaziados. Os valores antigos tinham aparência de credenciais reais, mas não foram usados nem validados. Sanitizar o arquivo atual não remove o histórico; revogar/rotacionar se forem válidos depende do responsável pela conta. `PLUGGY_ENABLED=false` impede uso acidental no laboratório.

Não há evidência de KMS, rotação automática de chaves ou TLS configurado; esses controles não são tratados como implementados.

## 11. LGPD e privacidade

- O laboratório usa exclusivamente pessoas e movimentações fictícias; não se deve inserir dados reais nas demonstrações.
- A tela de perfil foi reduzida aos campos retornados pelo backend e removeu CPF, renda, escolaridade, ocupação, estado civil e avaliação financeira hardcoded, aplicando minimização.
- A identidade, CPF e foto hardcoded da tela de contas foram removidos; a tela usa identidade explicitamente fictícia e avatar genérico, sem conexão nova com APIs. O arquivo de foto foi retirado da pasta pública, mas permanece recuperável no histórico Git.
- O CSV é validado temporariamente e fechado ao fim da requisição; não há tabela, bucket ou arquivo permanente.
- Logs usam UUID como pseudônimo. Isso reduz exposição direta, mas não é anonimização: o UUID pode ser relacionado ao banco.
- Os eventos `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `ACCESS_DENIED` e `ADMIN_ACCESS` usam allowlist e não incluem email, telefone, senha, hash, token, corpo de login ou conteúdo financeiro.
- O `echo` do SQLAlchemy está desativado para evitar parâmetros SQL no stdout.
- Esses testes cobrem o logger de segurança, não toda saída operacional: o access log padrão pode incluir o email da rota `/pessoas/by-email/{email}`. O backend ainda retorna endereço completo à própria pessoa/ADMIN; minimização adicional e redação de access logs permanecem fora deste fechamento.
- Retenção, descarte, atendimento a titulares e controle de acesso ao agregador de logs não estão implementados/documentados e permanecem **Pendentes** para um ambiente real.

## 12. Evidência, correção e reteste

| Risco | Evidência reproduzível | Correção existente | Reteste existente |
|---|---|---|---|
| R-01 / SB-01 | `SECURITY_BASELINE.md`, consulta mascarada e código do commit-base `fb0aea8` | `5ec2982` | `tests/test_password_security.py` |
| R-02 / SB-02 | `SECURITY_BASELINE.md`; `GET /api/v1/pessoas/` anônimo; caracterização `94dc435` | `ed6a91d` | `test_only_documented_public_endpoints_lack_authentication` e `test_administrative_people_list_matches_secureai_matrix` |
| R-03 / SB-03 | Sessões por ID no baseline; pagamento autenticado sem ownership na auditoria | `ed6a91d`; fechamento local restringe pagamentos a ADMIN | Perfil representativo e `test_payment_requests_deny_anonymous_and_user`; sessão específica pendente |
| R-04 / SB-04 | `fink-frontend/lib/hooks/sessoes/mutations/use-login.ts` grava `authToken` no `localStorage` | Nenhuma correção; risco aceito temporariamente no lab | Não existe reteste de cookie/CSRF |
| R-05 / SB-05 | Baseline registrou parâmetros SQL e prints de configuração | `f2fe8bf` | `tests/test_security_logging.py` testa quatro eventos e redação |
| R-06 | Casos de extensão, tamanho, encoding, headers, linha e contagem | `88e18ef` | `tests/test_csv_upload.py`, inclusive SHA-256 e ausência de dados nos logs |
| R-07 | URLs locais HTTP e ausência de certificados | Justificativa de localhost; TLS obrigatório na implantação | Não existe reteste HTTPS local |
| R-08 | IDs externos sem ownership | Fechamento local: `PLUGGY_ENABLED=false`, lifespan condicional e bloqueio `503` | `test_pluggy_is_disabled_by_default`, teste de lifespan e seis rotas sem cliente externo |
| R-09 | `examples/transacoes_risco_ia.csv` e classificador local | Backend `1568edc`, frontend `e6e84c7` | `tests/test_ai_classifier.py`, upload não altera treinamento, resposta e autenticação |
| R-10 | Exemplo antigo com valores não-placeholder | Fechamento local: campos vazios; `.env` ignorado e intocado | Inspeção sanitizada do diff; validade/rotação externas não verificadas |

Na auditoria após implementar IA, a suíte completa confirmou **57 testes aprovados**, com 11 avisos de depreciação. No fechamento de 2026-09-16, a suíte completa executada em container confirmou **73 testes aprovados**, com os mesmos 11 avisos: foram acrescentados 16 casos de Pluggy/pagamentos. Os testes e o Ruff dos arquivos backend alterados passaram novamente antes dos commits. O Ruff global anterior apontou nove erros preexistentes em arquivos não alterados (alertas, metas, seed e migrações). No frontend, os dois casts explícitos `any` de `AccountsSection.tsx` foram removidos mecanicamente, preservando a validação de string. O lint desse arquivo passou. O lint global anterior à correção apontou 17 erros e quatro avisos, incluindo esses dois; os demais problemas estão em arquivos não alterados. TypeScript e build passaram após regenerar os tipos duplicados da pasta ignorada `.next`; o build precisou de acesso às fontes Google existentes. Não foram corrigidas outras pendências de lint. O artefato `.coverage 2` foi removido e `.coverage*` foi confirmado no `.gitignore`.

## 13. Limites e pendências restantes

1. Entrega acadêmica: relatório de 6-10 páginas, screenshots, logs redigidos, evidências antes/depois, apresentação e demonstração; `AI_USAGE.md` registra uso e validação do Codex.
2. Implantação: TLS em proxy reverso; revisar o risco temporariamente aceito do `localStorage` e definir proteção de sessão adequada.
3. Antes de habilitar Pluggy: vínculo local/ownership de IDs, retestes e credenciais válidas geridas fora do Git. A integração fica desabilitada no laboratório.
4. Responsável pelas credenciais: confirmar e revogar/rotacionar valores antigos se válidos; sanitização atual não apaga histórico.
5. Riscos residuais: sem rate limiting/MFA, retenção/controle de logs, redação de access logs, minimização adicional de respostas e teste específico de ownership de sessões. Não foram implementados neste fechamento.
6. IA: sugestões continuam sujeitas a erro; limiar operacional não calibrado, base pequena e nenhuma métrica de acurácia declarada. Revisão humana obrigatória.

## Fontes locais

- `SECURITY_BASELINE.md` e commit-base `fb0aea8`.
- Commits `5ec2982`, `94dc435`, `ed6a91d`, `f2fe8bf`, `88e18ef` e `1568edc` do backend; fechamento mínimo em `fix(security): harden disabled integrations`.
- Commits `614cc53` e `e6e84c7` do frontend; remoção da identidade legada em `fix(accounts): remove hardcoded personal data`.
- Testes de senha, acesso, logs, upload, IA e `tests/test_lab_hardening.py`; `AI_SECURITY.md` e `AI_USAGE.md`.
- `Relatório Projeto - SecureAI Lab - Cibersegurança.pdf`.
