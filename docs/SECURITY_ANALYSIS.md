# SecureFINK - Análise de Segurança

Data da análise: 2026-09-15

Escopo: branches locais `secureai-lab` de backend e frontend, com dados fictícios e execução em `localhost`.

Este documento resume o threat modeling e as evidências que alimentam o relatório final do SecureAI Lab. As afirmações de implementação são limitadas ao código, commits e testes existentes. Itens ainda não entregues são marcados como **Pendente**.

## 1. Contexto e público-alvo

O SecureFINK é uma aplicação web de organização e educação financeira. O fluxo existente permite autenticar pessoas, consultar o próprio perfil, acompanhar metas e movimentações, administrar catálogos e validar um CSV de transações sem persistir o arquivo.

O público-alvo funcional é formado por pessoas que organizam informações financeiras fictícias no papel `USER` e por operadores do sistema no papel `ADMIN`. No contexto acadêmico, a aplicação também serve para demonstrar o ciclo vulnerabilidade, exploração local, correção e reteste exigido pelo SecureAI Lab.

## 2. Arquitetura resumida

```text
Navegador / Next.js
  |  Bearer token (localStorage - pendente de correção)
  v
FastAPI
  |-- autenticação, RBAC e regras de propriedade
  |-- upload CSV temporário, validado em memória
  |-- logs de segurança JSON no stdout
  v
PostgreSQL
  |-- pessoas, hashes de senha, hashes de sessão e dados da aplicação

Redis
  |-- provisionado pelo Docker, sem uso ativo encontrado no código atual

Pluggy
  |-- código de integração presente, mas desabilitado/não exercitado no laboratório
```

- Frontend: Next.js; autentica, guarda temporariamente a sessão no `localStorage`, consulta perfil e envia `multipart/form-data`.
- Backend: FastAPI; expõe API, valida Bearer token e aplica `get_current_user` e `require_admin`.
- Banco: PostgreSQL; persiste pessoas, sessões e entidades financeiras da aplicação.
- Redis: contêiner, dependência e `REDIS_URL` existem, mas não há consumo comprovado pela aplicação.
- Upload: `POST /api/v1/uploads/csv`; processa o arquivo temporariamente, calcula SHA-256 dos bytes originais e não cria armazenamento permanente.

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
| `ADMIN` | Rotas administrativas de pessoas, planos e tipos de pagamento; o papel não concede automaticamente acesso financeiro privado |

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
| Pluggy | Endpoints externos e IDs de conta/item; integração não exercitada no laboratório |
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
| Integridade | Alteração administrativa sem RBAC, manipulação de IDs, CSV adulterado e entradas malformadas | Mudança indevida de cadastros, catálogos ou dados processados |
| Disponibilidade | Arquivo excessivo, volume de tentativas de login, consultas custosas e falha de banco/integração externa | Esgotamento de recursos ou indisponibilidade da API |

O SHA-256 detecta se os mesmos bytes do CSV foram alterados, mas não prova autoria. O limite de 1 MB e 1.000 registros reduz abuso de recursos no upload. Não foi encontrado rate limiting de login; portanto esse controle permanece pendente.

## 7. Matriz de Riscos

Escala: probabilidade (`P`) e impacto (`I`) de 1 a 5. Resultado = `P x I`. Severidade: 1-4 baixa, 5-9 média, 10-16 alta, 17-25 crítica. Os valores representam risco inerente para priorização; não são uma medição quantitativa de risco residual.

| ID | Risco | P | I | Resultado | Severidade | Controle comprovado | Situação |
|---|---|---:|---:|---:|---|---|---|
| R-01 / SB-01 | Recuperação imediata de senhas persistidas em texto claro | 4 | 5 | 20 | Crítica | Argon2id com salt; `senha_hash`; hash omitido da API | Mitigado e retestado |
| R-02 / SB-02 | Uso anônimo de endpoints administrativos ou sensíveis | 5 | 5 | 25 | Crítica | Allowlist pública; `get_current_user`; `require_admin` | Mitigado e retestado |
| R-03 / SB-03 | Acesso ou alteração de recurso de outra pessoa por troca de ID | 4 | 4 | 16 | Alta | Identidade central, booleano `admin` e checagens de propriedade | Parcialmente retestado |
| R-04 / SB-04 | Furto e reutilização do Bearer token por XSS | 3 | 5 | 15 | Alta | Servidor guarda `token_hash`; logout revoga sessão | **Pendente:** token ainda no `localStorage` |
| R-05 / SB-05 | Exposição de credenciais ou dados em logs | 4 | 4 | 16 | Alta | `echo=False`; eventos JSON com campos permitidos | Mitigado e retestado |
| R-06 | Abuso, parser malformado ou consumo de recursos no upload | 3 | 4 | 12 | Alta | `.csv`, UTF-8, 1 MB, 1.000 linhas, schema e validação por linha | Mitigado e retestado |
| R-07 | Interceptação de credenciais/sessões em HTTP | 3 | 5 | 15 | Alta | Somente ambiente local | **Pendente:** HTTPS/TLS |
| R-08 | Consulta de conta Pluggy sem vínculo local de propriedade | 3 | 5 | 15 | Alta | Endpoints exigem autenticação; debug exige `ADMIN` | **Pendente:** vínculo de `item_id`/`account_id`; integração desabilitada no lab |
| R-09 | Prompt injection, vazamento ou resposta insegura de IA futura | 1 | 4 | 4 | Baixa no estado atual | Nenhum, pois não existe funcionalidade de IA | **Pendente antes de ativar IA** |
| R-10 | Exposição de segredo por configuração versionada | 3 | 5 | 15 | Alta | `.env` consta no `.gitignore` | **Pendente:** sanitizar valores não-placeholder de `.env.example` e rotacionar se válidos |

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
| XSS | Não foi identificado sink reproduzível no fluxo selecionado. O impacto potencial sobre o token no `localStorage` justifica manter SB-04 pendente. |
| Upload inseguro | O upload não existia no baseline; foi criado já com validação e testes, sem uma versão vulnerável para explorar. |
| Falha criptográfica/integridade | Foram demonstrados controles positivos com Argon2id e SHA-256; HTTPS ainda é uma lacuna, mas não foi simulado ataque de rede. |
| Gerenciamento de sessão | O `localStorage` é um risco conhecido, mas sua correção exige cookie `HttpOnly` e defesa CSRF, fora das correções já realizadas. |
| Exposição em logs | SB-05 foi corrigido e retestado, mas não integra as três demonstrações principais para manter o relatório curto. |
| IA | A aplicação ainda não possui IA; logo não há cenário real para explorar. Requisito e análise permanecem pendentes. |

Falhas de API e controle de acesso não foram descartadas: elas são representadas diretamente pelas demonstrações SB-02 e SB-03.

## 10. Estratégia criptográfica

- **Senhas - implementado:** Argon2id via `argon2-cffi`, com salt gerado pela biblioteca. A aplicação persiste `senha_hash`, verifica pela biblioteca e nunca inclui o hash nos schemas de resposta.
- **Integridade do CSV - implementado:** SHA-256 é calculado sobre os bytes originais e retornado com os metadados. O hash permite comparar integridade, mas não autentica a origem do arquivo.
- **Sessões - implementado parcialmente:** o Bearer token aleatório é entregue em claro uma vez; somente seu SHA-256 (`token_hash`) é persistido. O armazenamento do token no navegador continua pendente.
- **Dados em trânsito - pendente:** produção deve usar HTTPS/TLS. A criptografia assimétrica dos certificados autentica o servidor e participa do estabelecimento da sessão; a transferência usa chaves simétricas negociadas pelo TLS.
- **Criptografia simétrica - proposta, não implementada:** se dados financeiros reais ou arquivos fossem persistidos, os campos mais sensíveis seriam cifrados com AEAD, por exemplo AES-GCM, antes da gravação. Chaves devem ficar fora do banco, em serviço de segredos/KMS, com rotação e controle de acesso.
- **Assinatura digital - não necessária no fluxo atual:** o CSV é enviado pelo próprio usuário e não é persistido nem distribuído como documento oficial. Não há requisito atual de autoria ou não repúdio. Se surgisse intercâmbio externo verificável, a assinatura de um manifesto seria reavaliada.
- **Segredos:** devem residir em `.env` local, fora do Git. O `.gitignore` cobre `.env`; `.env.example` deve conter apenas placeholders. Como o arquivo versionado possui valores com aparência de credenciais, sua sanitização e eventual rotação estão pendentes.

Não há evidência de KMS, rotação automática de chaves ou TLS configurado; esses controles não são tratados como implementados.

## 11. LGPD e privacidade

- O laboratório usa exclusivamente pessoas e movimentações fictícias; não se deve inserir dados reais nas demonstrações.
- A tela de perfil foi reduzida aos campos retornados pelo backend e removeu CPF, renda, escolaridade, ocupação, estado civil e avaliação financeira hardcoded, aplicando minimização.
- O CSV é validado temporariamente e fechado ao fim da requisição; não há tabela, bucket ou arquivo permanente.
- Logs usam UUID como pseudônimo. Isso reduz exposição direta, mas não é anonimização: o UUID pode ser relacionado ao banco.
- Os eventos `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `ACCESS_DENIED` e `ADMIN_ACCESS` usam allowlist e não incluem email, telefone, senha, hash, token, corpo de login ou conteúdo financeiro.
- O `echo` do SQLAlchemy está desativado para evitar parâmetros SQL no stdout.
- Retenção, descarte, atendimento a titulares e controle de acesso ao agregador de logs não estão implementados/documentados e permanecem **Pendentes** para um ambiente real.

## 12. Evidência, correção e reteste

| Risco | Evidência reproduzível | Correção existente | Reteste existente |
|---|---|---|---|
| R-01 / SB-01 | `SECURITY_BASELINE.md`, consulta mascarada e código do commit-base `fb0aea8` | `5ec2982` | `tests/test_password_security.py` |
| R-02 / SB-02 | `SECURITY_BASELINE.md`; `GET /api/v1/pessoas/` anônimo; caracterização `94dc435` | `ed6a91d` | `test_only_documented_public_endpoints_lack_authentication` e `test_administrative_people_list_matches_secureai_matrix` |
| R-03 / SB-03 | Rota de sessões por ID no commit-base sem autenticação/propriedade | `ed6a91d` | Allowlist e teste representativo de outro perfil; teste específico de sessão **Pendente** |
| R-04 / SB-04 | `fink-frontend/lib/hooks/sessoes/mutations/use-login.ts` grava `authToken` no `localStorage` | Nenhuma correção; `614cc53` preserva conscientemente o fluxo | **Pendente** |
| R-05 / SB-05 | Baseline registrou parâmetros SQL e prints de configuração | `f2fe8bf` | `tests/test_security_logging.py` testa quatro eventos e redação |
| R-06 | Casos de extensão, tamanho, encoding, headers, linha e contagem | `88e18ef` | `tests/test_csv_upload.py`, inclusive SHA-256 e ausência de dados nos logs |
| R-07 | URLs locais usam `http://` e não existe configuração TLS no repositório | Nenhuma | **Pendente** |
| R-08 | Rotas Pluggy recebem `item_id`/`account_id`; baseline exige vínculo local | Autenticação em `ed6a91d`; debug restrito a `ADMIN` | Sem chamada externa; teste de propriedade **Pendente** |
| R-09 | Não existe módulo/rota de IA | Nenhuma | **Pendente** |
| R-10 | `.env` ignorado; `.env.example` rastreado com valores não-placeholder | Apenas exclusão de `.env` pelo Git | Sanitização e verificação de histórico **Pendentes** |

Na execução associada aos commits de segurança, a suíte completa alcançou 42 testes aprovados após a inclusão do upload. Esse número registra a evidência observada naquele estado; o relatório final deve anexar a saída de uma nova execução no momento da entrega.

## 13. Pendências para atender integralmente ao PDF

1. HTTPS/TLS fora de `localhost`.
2. Remoção do Bearer token do `localStorage`, adoção de cookie `HttpOnly`, `Secure`, `SameSite` e defesa CSRF compatível.
3. Rate limiting/MFA ou justificativa de escopo para o login.
4. Vínculo local e reteste de propriedade dos IDs da Pluggy antes de habilitar a integração.
5. Sanitização de `.env.example` e rotação de qualquer valor que seja confirmado como segredo válido.
6. Funcionalidade de IA, threat model específico, cenário de risco, mitigação e reteste.
7. Política operacional de acesso, retenção e descarte de logs.
8. Teste específico de propriedade para sessões e, antes de produção, ampliação dos testes por recurso.

## Fontes locais

- `SECURITY_BASELINE.md` e commit-base `fb0aea8`.
- Commits `5ec2982`, `94dc435`, `ed6a91d`, `f2fe8bf` e `88e18ef` do backend.
- Commit `614cc53` do frontend, que mantém temporariamente o `localStorage`.
- `tests/test_password_security.py`, `tests/test_access_control_characterization.py`, `tests/test_security_logging.py` e `tests/test_csv_upload.py`.
- `Relatório Projeto - SecureAI Lab - Cibersegurança.pdf`.
