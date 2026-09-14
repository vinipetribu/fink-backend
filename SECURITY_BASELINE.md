# SecureAI Lab - Security Baseline

Data do levantamento: 2026-09-14  
Branch: `secureai-lab`  
Base original do backend: `fb0aea8`

## Objetivo e limites

Este documento registra o comportamento de segurança da aplicação original antes de qualquer correção. As evidências abaixo foram obtidas exclusivamente em `localhost`, com dados fictícios criados pelo seed do projeto. Nenhum ataque, varredura ou chamada de teste foi dirigido à Pluggy ou a outro serviço externo.

Ambiente usado:

- API: `http://localhost:8000`
- frontend: `http://localhost:3000`
- PostgreSQL: contêiner `fink_pg`
- Redis: contêiner `fink_redis`

Para iniciar o ambiente:

```bash
cd fink-backend
docker compose up -d --build
curl --fail http://localhost:8000/health
```

Os arquivos `.env` e `.env.local` são locais, estão cobertos pelos respectivos `.gitignore` e não fazem parte deste baseline versionado.

## Resumo dos achados

| ID | Achado | Severidade inicial | Referências |
|---|---|---:|---|
| SB-01 | Senhas armazenadas e comparadas em texto claro | Crítica | CWE-256, CWE-916 |
| SB-02 | Endpoints administrativos e de dados acessíveis sem autenticação | Crítica | CWE-306, CWE-862 |
| SB-03 | Campo `admin` sem RBAC efetivamente aplicado | Alta | CWE-269, CWE-863 |
| SB-04 | Token Bearer persistido no `localStorage` | Alta | CWE-922; impacto ampliado por XSS |
| SB-05 | Dados sensíveis e credenciais aparecem nos logs SQL | Alta | CWE-532 |

As severidades são uma triagem inicial. Elas deverão ser confirmadas na futura matriz de riscos considerando probabilidade, impacto e controles compensatórios.

## SB-01 - Senha armazenada em texto claro

### Arquivos e endpoints afetados

- `app/identidade/persistence/pessoa_orm.py`: a coluna `senha` é uma `String` sem distinção entre senha e hash.
- `app/identidade/services/pessoa_service.py`: cadastro persiste diretamente o valor recebido.
- `app/identidade/services/sessao_service.py`: o login compara `pessoa.senha != senha` diretamente.
- `app/shared/seed.py`: cria a conta fictícia com senha legível.
- `POST /api/v1/pessoas/`: recebe e persiste a senha.
- `POST /api/v1/sessoes/login`: compara a senha em texto claro.

### Reprodução local

1. Inicie o backend e o banco com `docker compose up -d --build`.
2. Execute a consulta abaixo. Ela mascara o valor exibido, mas comprova que o conteúdo possui apenas sete caracteres e não começa com o prefixo `$` normalmente usado por formatos Argon2/bcrypt.

```bash
docker compose exec -T postgres psql -U fink -d fink -c \
  "SELECT email,
          left(senha, 2) || repeat('*', greatest(length(senha) - 2, 0)) AS senha_mascarada,
          length(senha) AS tamanho,
          left(senha, 1) = chr(36) AS inicia_com_prefixo_hash
     FROM pessoa;"
```

Resultado observado:

```text
email          | senha_mascarada | tamanho | inicia_com_prefixo_hash
demo@fink.dev  | de*****         |       7 | f
```

3. Confirme a comparação direta no código:

```bash
rg -n "pessoa\.senha != senha|senha=\"" app/identidade app/shared/seed.py
```

### Impacto

Uma leitura indevida do banco, de um backup ou de logs permite recuperar imediatamente as senhas. Se uma pessoa reutilizar a senha em outro serviço, o impacto ultrapassa a aplicação. O problema também impede demonstrar proteção adequada de credenciais no SecureAI Lab.

### Correção planejada

- Adotar Argon2id com salt individual e parâmetros versionados.
- Renomear a coluna para `senha_hash` e migrar contas existentes sem manter o texto claro.
- Verificar senhas em tempo constante pela biblioteca escolhida e permitir rehash gradual.
- Remover credenciais legíveis do seed e usar valores fictícios fornecidos apenas por configuração local.
- Criar testes de cadastro, login válido, login inválido e garantia de que o valor persistido não equivale à senha recebida.

## SB-02 - Endpoints acessíveis sem autenticação

### Endpoints afetados

Os endpoints públicos intencionais devem se limitar a health checks, informações não sensíveis, cadastro, login e consulta pública dos planos. No baseline, o OpenAPI também declara sem autenticação:

- Pessoas: `GET /api/v1/pessoas/` e `GET /api/v1/pessoas/by-email/{email}`.
- Sessões: `GET /api/v1/sessoes/pessoa/{id_pessoa}` e `DELETE /api/v1/sessoes/pessoa/{id_pessoa}/todas`.
- Assinaturas: `GET /api/v1/assinaturas/`.
- Planos: `POST /api/v1/planos/`, `PATCH /api/v1/planos/{id_plano}`, `DELETE /api/v1/planos/{id_plano}`, `PUT /api/v1/planos/{id_plano}/ativar` e `PUT /api/v1/planos/{id_plano}/desativar`.
- Tipos de pagamento: todas as rotas em `/api/v1/tipos-pagamento/`, inclusive criação, alteração e exclusão.
- Solicitações de pagamento: todas as rotas em `/api/v1/solicitacoes-pagamento/`, inclusive criação e exclusão.
- Pluggy: todas as rotas em `/api/v1/pluggy/`, incluindo `/_debug-auth`.

### Reprodução local

1. Liste as rotas e o requisito de segurança publicado pela própria aplicação:

```bash
curl --fail --silent http://localhost:8000/openapi.json | jq -r '
  .paths | to_entries[] as $p |
  $p.value | to_entries[] |
  "\(.key | ascii_upcase) \($p.key) security=\(.value.security // "none")"'
```

2. Sem header `Authorization`, faça apenas leituras não destrutivas:

```bash
curl --output /dev/null --write-out '%{http_code}\n' \
  http://localhost:8000/api/v1/pessoas/
curl --output /dev/null --write-out '%{http_code}\n' \
  http://localhost:8000/api/v1/assinaturas/
curl --output /dev/null --write-out '%{http_code}\n' \
  http://localhost:8000/api/v1/tipos-pagamento/
curl --output /dev/null --write-out '%{http_code}\n' \
  http://localhost:8000/api/v1/solicitacoes-pagamento/
```

Resultado observado: `200` nas quatro requisições. `GET /api/v1/planos/` retornou `500` e `GET /api/v1/pluggy/connect-token` retornou `502` no ambiente sem credenciais externas; esses códigos demonstram que os handlers foram alcançados sem autenticação, mas não devem ser usados como teste de disponibilidade da integração.

Não se deve executar os métodos mutáveis (`POST`, `PATCH`, `PUT` ou `DELETE`) para reproduzir este baseline. A ausência de segurança no OpenAPI e de dependência de autorização no código é evidência suficiente sem alterar dados.

### Impacto

Um cliente anônimo pode enumerar pessoas, assinaturas, pagamentos e sessões, além de alcançar operações administrativas. Os endpoints Pluggy não vinculam os identificadores recebidos ao usuário autenticado, criando risco de exposição de informações financeiras e abuso da integração.

### Correção planejada

- Aplicar autenticação por padrão no router `/api/v1` e liberar explicitamente apenas a pequena allowlist pública.
- Exigir autorização por papel e propriedade do recurso em todos os handlers.
- Desabilitar `/_debug-auth` fora de desenvolvimento e restringi-lo a `ADMIN` no ambiente local.
- Vincular `item_id` e `account_id` da Pluggy a uma pessoa local antes de consultar dados externos.
- Adicionar testes automáticos que esperem `401`, `403` e `404` nos casos apropriados.

## SB-03 - Ausência de RBAC apesar do campo `admin`

### Arquivos e endpoints afetados

- `app/identidade/persistence/pessoa_orm.py` e `app/identidade/domain/pessoa.py` possuem o booleano `admin`.
- `app/identidade/api/pessoa_schema.py` expõe `admin` na resposta.
- `app/api/deps.py` oferece apenas `get_current_user_id`; não carrega o papel nem fornece uma dependência `require_admin`.
- Rotas descritas como “uso administrativo”, como `GET /api/v1/pessoas/`, `GET /api/v1/assinaturas/` e operações de catálogo/pagamento, não validam o campo `admin`.

### Reprodução local

```bash
rg -n "admin|Depends\(get_current_user_id\)" app
docker compose exec -T postgres psql -U fink -d fink -c \
  "SELECT email, admin FROM pessoa;"
```

O banco possui o atributo, mas a busca no código não encontra uma decisão de autorização baseada nele. A conta fictícia, mesmo com `admin = false`, consegue alcançar endpoints administrativos que não exigem token.

### Impacto

O sistema não entrega dois níveis reais de privilégio. Marcar uma conta como administradora não concede um conjunto controlado de capacidades, e manter `admin = false` não impede ações administrativas. Isso viola o princípio do menor privilégio e o requisito de autorização do SecureAI Lab.

### Correção planejada

- Substituir o booleano por um papel explícito e validado (`USER` ou `ADMIN`), mantendo migração compatível.
- Criar `get_current_user` e `require_roles(...)` como dependências centrais.
- Aplicar políticas de propriedade (`owner_id == current_user.id`) separadamente da verificação de papel.
- Impedir que cadastro e atualização de perfil aceitem elevação de papel pelo próprio usuário.
- Testar a matriz de acesso completa com contas `USER`, `ADMIN`, anônima e recursos pertencentes a outra pessoa.

## SB-04 - Token armazenado no localStorage

### Arquivos e fluxo afetados

- `fink-frontend/lib/hooks/sessoes/mutations/use-login.ts`: grava `authToken`, `userId` e `sessionId` no `localStorage`.
- `fink-frontend/lib/api/client.ts`: lê o token e monta `Authorization: Bearer`.
- `fink-frontend/lib/hooks/sessoes/mutations/use-logout.ts`: remove os valores locais.
- Todas as páginas protegidas pelo `ProtectedRoute` dependem desse fluxo no cliente.

### Reprodução local

1. Acesse `http://localhost:3000/login` e autentique-se com a conta fictícia local.
2. No console das ferramentas de desenvolvimento do navegador, execute:

```javascript
localStorage.getItem('authToken')
```

3. O retorno é o token Bearer legível. A mesma evidência pode ser obtida sem revelar o valor:

```javascript
Boolean(localStorage.getItem('authToken'))
```

Resultado esperado após login: `true`.

### Impacto

Qualquer JavaScript executado na origem, inclusive por uma vulnerabilidade XSS ou dependência comprometida, pode ler e exfiltrar o token. O invasor poderá reutilizá-lo até expirar ou ser revogado.

### Correção planejada

- Migrar a sessão para cookie `HttpOnly`, `Secure` e `SameSite`, emitido pelo backend.
- Não persistir token ou identificadores de autorização no armazenamento acessível a JavaScript.
- Implementar proteção CSRF compatível com a política de cookies.
- Adotar CSP restritiva, validação/escape de conteúdo e testes de XSS e CSRF.
- Manter a autorização no backend; `ProtectedRoute` continuará sendo apenas controle de navegação/experiência.

## SB-05 - Dados sensíveis nos logs

### Arquivos e dados afetados

- `app/shared/database.py`: define `echo=settings.debug`, registrando instruções e parâmetros SQL quando `DEBUG=true`.
- `.env.example` habilita debug no desenvolvimento.
- `app/main.py` usa `print` para estado da integração Pluggy.
- Os logs observados durante o seed incluíram email, senha legível, nome, nascimento, telefone e endereço da pessoa fictícia.

### Reprodução local

Após iniciar a API em modo de desenvolvimento:

```bash
docker compose logs api | rg -A1 "INSERT INTO pessoa"
```

A primeira linha mostra o `INSERT`; a linha seguinte apresenta os parâmetros completos, incluindo a senha e os dados pessoais. Essa saída deve permanecer apenas no ambiente local controlado e não deve ser copiada para tickets ou relatórios sem redação.

### Impacto

Pessoas e sistemas com acesso ao agregador de logs podem obter credenciais e dados pessoais sem consultar o banco. Backups, exportações e retenção prolongada dos logs ampliam o impacto e entram no escopo de proteção de dados e LGPD.

### Correção planejada

- Desativar `SQLAlchemy echo` e logs de parâmetros por padrão, inclusive em desenvolvimento compartilhado.
- Adotar logging estruturado com allowlist de campos, redaction e identificador de correlação.
- Separar logs operacionais de trilha de auditoria de segurança.
- Nunca registrar senhas, tokens, segredos, corpos de login ou dados financeiros completos.
- Definir retenção, acesso, integridade e descarte dos logs e criar testes de ausência de segredos.

## Arquitetura de autenticação e autorização proposta

### Princípios

1. O backend é a fonte de verdade. Guardas no frontend não concedem autorização.
2. Uma sessão autenticada identifica uma pessoa e seu papel imutável durante a requisição.
3. `USER` acessa somente os próprios dados e recursos vinculados.
4. `ADMIN` gerencia usuários e catálogos, mas não recebe acesso irrestrito ao conteúdo financeiro por padrão.
5. Toda decisão negada e toda ação administrativa relevante gera evento de auditoria sem dados sensíveis.

Fluxo proposto:

```text
Browser -> cookie de sessão HttpOnly -> get_current_user
                                      -> valida sessão/revogação
                                      -> require_roles(USER, ADMIN)
                                      -> verifica propriedade/escopo
                                      -> serviço/repositório
                                      -> audit log seguro
```

### Matriz exata de acesso proposta

Legenda: “próprio” significa que o backend deriva ou valida o `id_pessoa` a partir da sessão; conhecer um UUID ou ID externo não concede acesso.

| Método e rota | Público | USER | ADMIN | Regra adicional |
|---|:---:|:---:|:---:|---|
| `GET /` | Sim | Sim | Sim | Somente metadados não sensíveis |
| `GET /health` | Sim | Sim | Sim | Liveness mínima |
| `GET /api/v1/health` | Sim | Sim | Sim | Liveness mínima |
| `GET /api/v1/info` | Sim | Sim | Sim | Não expor debug/configuração |
| `POST /api/v1/pessoas/` | Sim | Sim | Sim | Cadastro público sempre cria `USER`; ADMIN pode criar papel explicitamente em fluxo autenticado |
| `GET /api/v1/pessoas/` | Não | Não | Sim | Lista administrativa auditada |
| `GET /api/v1/pessoas/{id_pessoa}` | Não | Sim | Sim | USER somente próprio; ADMIN qualquer pessoa |
| `PATCH /api/v1/pessoas/{id_pessoa}` | Não | Sim | Sim | USER somente próprio e nunca altera papel; ADMIN pode administrar papel |
| `DELETE /api/v1/pessoas/{id_pessoa}` | Não | Sim | Sim | USER somente próprio; ADMIN qualquer pessoa, com auditoria |
| `GET /api/v1/pessoas/by-email/{email}` | Não | Não | Sim | Busca administrativa auditada |
| `POST /api/v1/sessoes/login` | Sim | Sim | Sim | Rate limit e resposta genérica para credenciais inválidas |
| `GET /api/v1/sessoes/validar` | Não | Sim | Sim | Valida somente a sessão atual |
| `DELETE /api/v1/sessoes/logout` | Não | Sim | Sim | Revoga somente a sessão atual |
| `GET /api/v1/sessoes/pessoa/{id_pessoa}` | Não | Sim | Sim | USER somente próprio; ADMIN qualquer pessoa |
| `DELETE /api/v1/sessoes/pessoa/{id_pessoa}/todas` | Não | Sim | Sim | USER somente próprio; ADMIN qualquer pessoa, com auditoria |
| `GET /api/v1/alertas/` | Não | Sim | Sim | USER recebe próprios; ADMIN somente alertas operacionais/administrativos, sem ampliar acesso financeiro |
| `PATCH /api/v1/alertas/{id_alerta}` | Não | Sim | Sim | Somente proprietário ou ADMIN em ação auditada |
| `GET /api/v1/metas/` | Não | Sim | Não | Somente próprias |
| `POST /api/v1/metas/` | Não | Sim | Não | Cria para a identidade da sessão |
| `GET /api/v1/metas/{id_meta}` | Não | Sim | Não | Somente própria |
| `PATCH /api/v1/metas/{id_meta}` | Não | Sim | Não | Somente própria |
| `DELETE /api/v1/metas/{id_meta}` | Não | Sim | Não | Somente própria |
| `POST /api/v1/metas/{id_meta}/atualizar_saldo` | Não | Sim | Não | Somente própria; operação auditada |
| `GET /api/v1/metas/movimentacao/{id_meta}` | Não | Sim | Não | Somente movimentações da própria meta |
| `GET /api/v1/planos/` | Sim | Sim | Sim | Catálogo público, somente planos ativos para anônimos/USER |
| `GET /api/v1/planos/{id_plano}` | Sim | Sim | Sim | Catálogo público; ADMIN pode ver inativos |
| `POST /api/v1/planos/` | Não | Não | Sim | Administração de catálogo |
| `PATCH /api/v1/planos/{id_plano}` | Não | Não | Sim | Administração de catálogo |
| `DELETE /api/v1/planos/{id_plano}` | Não | Não | Sim | Preferir desativação; exclusão auditada |
| `PUT /api/v1/planos/{id_plano}/ativar` | Não | Não | Sim | Administração de catálogo |
| `PUT /api/v1/planos/{id_plano}/desativar` | Não | Não | Sim | Administração de catálogo |
| `GET /api/v1/assinaturas/` | Não | Sim | Sim | USER recebe próprias; ADMIN lista todas |
| `POST /api/v1/assinaturas/` | Não | Sim | Sim | USER cria para si; ADMIN pode criar para outra pessoa |
| `GET /api/v1/assinaturas/{id_assinatura}` | Não | Sim | Sim | Proprietário ou ADMIN |
| `PATCH /api/v1/assinaturas/{id_assinatura}` | Não | Não | Sim | Alteração administrativa |
| `DELETE /api/v1/assinaturas/{id_assinatura}` | Não | Não | Sim | Exclusão administrativa auditada |
| `POST /api/v1/assinaturas/{id_assinatura}/renovar` | Não | Sim | Sim | Proprietário ou ADMIN; operação auditada |
| `PUT /api/v1/assinaturas/{id_assinatura}/cancelar` | Não | Sim | Sim | Proprietário ou ADMIN; operação auditada |
| `GET /api/v1/tipos-pagamento/` | Não | Sim | Sim | Catálogo autenticado |
| `GET /api/v1/tipos-pagamento/{id_pagamento}` | Não | Sim | Sim | Catálogo autenticado |
| `GET /api/v1/tipos-pagamento/by-tipo/{tipo}` | Não | Sim | Sim | Catálogo autenticado |
| `POST /api/v1/tipos-pagamento/` | Não | Não | Sim | Administração de catálogo |
| `PATCH /api/v1/tipos-pagamento/{id_pagamento}` | Não | Não | Sim | Administração de catálogo |
| `DELETE /api/v1/tipos-pagamento/{id_pagamento}` | Não | Não | Sim | Administração de catálogo, com auditoria |
| `GET /api/v1/solicitacoes-pagamento/` | Não | Sim | Sim | USER recebe próprias; ADMIN lista todas |
| `POST /api/v1/solicitacoes-pagamento/` | Não | Sim | Sim | USER cria para assinatura própria; ADMIN pode criar em suporte auditado |
| `GET /api/v1/solicitacoes-pagamento/{id_solicitacao}` | Não | Sim | Sim | Proprietário ou ADMIN |
| `DELETE /api/v1/solicitacoes-pagamento/{id_solicitacao}` | Não | Não | Sim | Ação administrativa auditada |
| `GET /api/v1/pluggy/connect-token` | Não | Sim | Não | Token associado à identidade da sessão |
| `GET /api/v1/pluggy/accounts/{item_id}` | Não | Sim | Não | `item_id` deve pertencer ao USER |
| `GET /api/v1/pluggy/transactions/{account_id}` | Não | Sim | Não | `account_id` deve pertencer ao USER |
| `GET /api/v1/pluggy/accounts/{account_id}/balance` | Não | Sim | Não | `account_id` deve pertencer ao USER |
| `GET /api/v1/pluggy/accounts/{account_id}/summary` | Não | Sim | Não | `account_id` deve pertencer ao USER |
| `GET /api/v1/pluggy/_debug-auth` | Não | Não | Somente local | Desabilitado fora de desenvolvimento; ADMIN local e resposta redigida |

Para suporte excepcional a dados financeiros, recomenda-se um fluxo “break glass” separado, com justificativa, autorização adicional, prazo curto e auditoria. O papel `ADMIN` comum não deve herdar automaticamente acesso às metas, transações, saldos ou contas bancárias de usuários.

## Critérios para o reteste futuro

- Senha persistida difere da senha informada e possui hash Argon2id válido.
- Rotas não públicas retornam `401` sem sessão.
- `USER` recebe `403` ao tentar ação exclusiva de `ADMIN`.
- `USER` recebe `404` ou `403`, conforme política documentada, ao tentar acessar recurso de outra pessoa.
- Sessão não é legível via `localStorage` ou `document.cookie`.
- Logs não contêm senha, token, segredo nem dados pessoais completos.
- A matriz acima possui testes automatizados positivos e negativos por papel e propriedade.
