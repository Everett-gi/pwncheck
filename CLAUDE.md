# PwnCheck — Contexto do Projeto

> Handoff para o Claude Code. Este projeto faz parte do portfólio cuja central é
> [Everett-gi/Projetos-e-ideias](https://github.com/Everett-gi/Projetos-e-ideias): lá ficam as
> convenções compartilhadas (README), o guia de deploy (DEPLOY-GERAL.md) e a trilha de
> aprendizado (tutorial/). Referência de qualidade: o DocSage (Everett-gi/docsage).
> **Status:** 🚧 em construção — fases 1 a 5 concluídas (cliente k-anonymity, política de senha,
> cache de prefixos, API FastAPI com autenticação, rate limit e métricas). Falta o deploy.

## Modo tutorial

O autor vem de **C e C++** (domina lógica, ponteiros, memória, compilação) e está aprendendo
Python com este projeto.

- Explique cada passo e o **porquê**, com analogias a C/C++ quando ajudarem. Não explique
  lógica de programação básica; foque no que é novo.
- Cada fase concluída ganha uma lição em `docs/tutorial/fase-N-*.md`, com exercícios e
  respostas no fim, e uma entrada no índice `tutorial/README.md` do Projetos-e-ideias.
- O autor pediu explicação **detalhe por detalhe**: cada lição traz diagramas (Mermaid, que o
  GitHub renderiza, e desenhos em texto), analogias com C/C++ e um **glossário** com todos os
  termos técnicos novos.
- Confirme rodando código qualquer afirmação técnica antes de escrevê-la numa lição.
- Deixe o autor rodar os comandos sempre que possível. Ambiente: Windows 11, PowerShell 7,
  VS Code, Python 3.12. Comandos em sintaxe PowerShell.
- Commits no padrão Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`).

## O que é
API que verifica se uma senha apareceu em vazamentos usando **k-anonymity** (padrão do
HaveIBeenPwned): a senha **nunca** sai do servidor — só um prefixo de hash é consultado.

**Valor de portfólio:** um padrão de privacidade elegante (k-anonymity), ótimo tema de entrevista.

## Stack
Python 3.12 · FastAPI · httpx · SQLAlchemy 2.1 (psycopg 3) · Alembic · pydantic-settings ·
PostgreSQL 16 (cache de prefixos) · Docker Compose · argon2-cffi · PyJWT · pytest · ruff.

## Como funciona (k-anonymity)
1. Calcula o SHA-1 da senha localmente.
2. Envia à API pública **apenas os 5 primeiros caracteres** do hash.
3. Recebe a lista de sufixos correspondentes e compara **localmente**.
A senha e o hash completo nunca trafegam.

## Mapa dos arquivos

| Arquivo | Responsabilidade |
|---|---|
| `app/kanonymity.py` | **Funções puras**: `sha1_hex`, `split_hash`, `parse_range_response`. Sem rede, sem banco. |
| `app/hibp_client.py` | Cliente HTTP da API Pwned Passwords (`fetch_range`, `check_password`). Recebe o `httpx.Client` por parâmetro. |
| `app/policy.py` | **Funções puras** da política de senha (NIST SP 800-63B-4): `evaluate_password`, `blocklist_keys`, `email_context_words`. A contagem de vazamentos entra por parâmetro. |
| `app/data/common-passwords.txt` | ~10 mil senhas mais comuns (SecLists, MIT), carregadas por `common_passwords()`. |
| `app/freshness.py` | **Funções puras** de validade do cache: `CachePolicy`, `classify` (FRESH/STALE/EXPIRED). O "agora" entra por parâmetro. |
| `app/config.py` | Configuração via `pydantic-settings`, em escada: `DatabaseSettings` → `CacheSettings` (→ `Settings` da API). Segredos em `SecretStr`. |
| `app/database.py` | `Base` (com convenção de nomes), `create_db_engine`, `create_session_factory`. |
| `app/models.py` | Tabelas SQLAlchemy 2 (`PrefixCache`). Mudou? Gere migração com `alembic revision --autogenerate`. |
| `app/prefix_cache.py` | O cache: `get_range` (hit/miss/stale-if-error), `save_entry` (upsert), `check_password_cached`, `cache_stats`, `purge_expired`. Não faz commit. |
| `app/manage.py` | Manutenção: `cache-stats`, `purge-cache`, `purge-rate-limits`, `purge-refresh-tokens`, `maintenance` (as três limpezas; cron) e `make-admin EMAIL [--revoke]`. |
| `app/security.py` | **Puro**: Argon2id (`hash_password`, `verify_password`, rehash, tempo fixo no login), JWT de acesso (HS256, `algorithms` fixo), refresh token (256 bits, guardado como SHA-256). |
| `app/accounts.py` | Contas e sessões: cadastro, `authenticate`, `issue_tokens`, `rotate_refresh_token` (UPDATE atômico + revogação da família no reuso), logout, exclusão. Não faz commit. |
| `app/schemas.py` | Pydantic: entrada com `SecretStr`, limites e `extra="forbid"`; saída filtrada por `response_model`. |
| `app/deps.py` | Dependências do FastAPI: `DbSession`, `HibpClient`, `SettingsDep`, `CurrentUser` (401), `AdminUser` (403), `limit_by_ip`/`limit_by_user` (429 + Retry-After). |
| `app/middleware.py` | `BodySizeLimitMiddleware` (413, com e sem Content-Length) e `security_headers` (CSP por tipo de página, nosniff, no-store...). |
| `app/main.py` | `create_app(settings)`: lifespan (engine + cliente HIBP), middlewares, 422 sem eco do `input`, rotas, página estática. Rodar: `uvicorn app.main:create_app --factory`. |
| `app/routers/` | `auth.py` (/auth/register, login, refresh, logout, me), `passwords.py` (/check, /policy, /range/{prefixo}) e `admin.py` (/admin/metrics). |
| `app/ratelimit.py` | **Puro**: janela deslizante aproximada (`Rate`, `parse_rate`, `decide`, `retry_after` exato com `Fraction`, `rate_key` com SHA-256). |
| `app/limiter.py` | Contadores do rate limit no PostgreSQL (`hit`: upsert atômico com RETURNING; `purge_counters`). |
| `app/metrics.py` | Métricas agregadas por dia (`record(session, dia, checks=1, ...)`, `daily_report`). |
| `app/static/` | Página inicial: SHA-1 no navegador (Web Crypto) + `GET /range/{prefixo}`. Sem script inline (CSP). |
| `app/cli.py` | Ferramenta de linha de comando para testar com a API real (`python -m app.cli [--cache]`): vazamentos + política. |
| `migrations/` | Alembic: `env.py` (URL vem do ambiente) e `versions/000N_*.py`. Configuração em `[tool.alembic]` no `pyproject.toml`. |
| `docker-compose.yml` | Desenvolvimento: PostgreSQL 16 num container (`db/init-test-db.sql` cria o `pwncheck_test`). |
| `tests/test_kanonymity.py` | Testes das funções puras (vetores conferidos com `sha1sum`). |
| `tests/test_hibp_client.py` | Testes do cliente com `httpx.MockTransport` — inclui a garantia de que só o prefixo sai. |
| `tests/test_policy.py` | Testes da política (bordas de comprimento, Unicode, derivados, padrões). |
| `tests/conftest.py` | Fixtures `db_engine` (recria o esquema com as migrações) e `db_session` (savepoint + rollback). Sem `TEST_DATABASE_URL`, testes de banco são pulados; com `PWNCHECK_REQUIRE_DB=1` (CI), falham. |
| `tests/test_prefix_cache.py` | Cache com PostgreSQL real e HIBP simulado — inclui a prova de que o banco não distingue senhas com o mesmo prefixo. |
| `tests/test_migrations.py` | `alembic check` (modelos × migrações) e downgrade/upgrade completos. |
| `tests/fakes.py` | `FakeHIBP`: HIBP simulado (corpo fixo ou `leaked={senha: contagem}` por prefixo). |
| `tests/test_security.py` | Argon2 e os ataques ao JWT (expirado, outra chave, adulterado, `alg: none`...). |
| `tests/test_api_auth.py`, `tests/test_api_passwords.py`, `tests/test_api_limits.py` | API de ponta a ponta com `TestClient` + `dependency_overrides` (banco transacional e HIBP falso). `make_api(rate_limit_...="3/minute")` muda a configuração. |
| `tests/test_ratelimit.py` | As contas da janela deslizante, incluindo `test_retry_after_nunca_mente` (milhares de casos). |
| `.github/workflows/ci.yml` | CI: ruff (lint + format), pytest, pip-audit e bandit. |

**Regras de arquitetura:**
- `kanonymity.py`, `policy.py` e `freshness.py` não importam rede, banco nem config. Lógica
  pura nova vai num módulo puro, com teste.
- Só o **prefixo** do hash chega ao banco e aos logs. O sufixo é comparado em Python (mandá-lo
  numa consulta SQL levaria o hash completo ao servidor de banco).
- Funções de serviço recebem a `Session` e **não fazem commit**: quem abre a sessão decide
  (na API, a rota).
- Toda senha que entra pela API é `SecretStr` e nunca volta numa resposta (nem no 422).
- Rotas `def` (síncronas, no threadpool). `async` só onde o ASGI exige (lifespan, middlewares).
- Todo acesso HTTP recebe o `httpx.Client` de fora (injeção de dependência) — é o que permite
  testar sem internet.
- A senha **nunca** é impressa, logada, persistida ou passada por argumento de linha de comando.

## Comandos (PowerShell, dentro de `C:\dev\pwncheck`)

```powershell
.\.venv\Scripts\Activate.ps1          # ativa o ambiente virtual
python -m pip install -r requirements-dev.txt
pytest -v                             # testes (sem internet)
ruff check .                          # lint + regras de segurança
ruff format .                         # formata o código (o CI exige formatado)
python -m app.cli                     # testa com a API real
Copy-Item .env.example .env           # 1ª vez: depois ajuste as senhas
docker compose up -d                  # sobe o PostgreSQL (fase 3)
alembic upgrade head                  # aplica as migrações
python -m app.cli --cache             # consulta passando pelo cache
python -m app.manage cache-stats      # estado do cache
uvicorn app.main:create_app --factory --reload   # a API (fase 4): http://127.0.0.1:8000/docs
```

## Modelo de dados
- **prefix_cache** (prefix, suffixes JSONB, fetched_at) — fase 3
- **users** (id, email único, password_hash Argon2id, is_admin, terms_accepted_at, created_at) — fase 4
- **refresh_tokens** (id, user_id → users CASCADE, family_id, token_hash SHA-256 único,
  expires_at, used_at, revoked_at, created_at) — fase 4
- **rate_limit_counters** (key "escopo:sha256", window_start, hits; PK composta) — fase 5
- **usage_metrics** (id, day único, checks, policies, ranges, breached, cache_hits,
  cache_misses, cache_stale, registrations, rate_limited) — fase 5

## Endpoints (fase 4)
- `GET /` — página inicial: verificação 100% no navegador via `/range`
- `GET /range/{prefixo}` — público: sufixos vazados do prefixo, formato do HIBP (k-anonymity)
- `POST /check` — (login) recebe uma senha, retorna se foi vista em vazamentos e quantas vezes
- `POST /policy` — (login) avalia a senha contra a política, com contexto e MFA
- `POST /auth/register | login | refresh | logout`, `GET/DELETE /auth/me`
- `GET /admin/metrics?days=7` — (admin) uso por dia e taxa de acerto do cache — fase 5
- `GET /health`, `/docs` (Swagger), `/redoc`

Rate limits (fase 5, configuráveis no `.env` como "10/minute"): login por IP e por e-mail,
cadastro e refresh por IP, `/check` e `/policy` por usuário, `/range` por IP.

## Foco de segurança
A senha **nunca** é logada nem persistida; só o prefixo de hash trafega; **rate limit**;
HTTPS obrigatório; cache para reduzir chamadas externas.

## Plano de build

1. ✅ Cliente k-anonymity (funções puras + testes com API simulada) + CLI de teste
   — lição: `docs/tutorial/fase-1-k-anonymity.md`
2. ✅ Política de força de senha (funções puras + testes)
   — lição: `docs/tutorial/fase-2-politica-de-senha.md`
3. ✅ Cache de prefixos: PostgreSQL + SQLAlchemy + **Alembic** + Docker
   — lição: `docs/tutorial/fase-3-cache-postgresql.md`
4. ✅ API (FastAPI) + autenticação (Argon2id, JWT + refresh com rotação e detecção de reuso)
   — lição: `docs/tutorial/fase-4-api-fastapi-autenticacao.md`
5. ✅ Rate limit (janela deslizante no PostgreSQL) + métricas
   — lição: `docs/tutorial/fase-5-rate-limit-metricas.md`
6. Deploy (ver `DEPLOY-GERAL.md` no Projetos-e-ideias)

## Armadilhas conhecidas
- **SHA-1 exige `usedforsecurity=False`.** Sem isso o ruff/bandit acusa hash inseguro (S324).
  Aqui o SHA-1 é só a chave de busca da base do HIBP, não protege nada.
- **Codificação é UTF-8.** O hash é sobre bytes; outra codificação muda o hash e a busca
  falha em silêncio (há teste para isso).
- **Contagem 0 é padding**, não vazamento (cabeçalho `Add-Padding: true`).
- **Upsert (Core) × mapa de identidade.** O `INSERT ... ON CONFLICT` não atualiza objetos que a
  sessão já tem; por isso `load_entry` usa `populate_existing=True` (há teste de regressão).
- **O `db/init-test-db.sql` só roda na criação do volume.** Banco antigo sem `pwncheck_test`:
  `docker compose down -v` (apaga os dados) e `up -d`.
- **Os testes apagam o esquema do `TEST_DATABASE_URL`** (`DROP SCHEMA public CASCADE`). Nunca
  aponte essa variável para o banco de desenvolvimento ou produção.
- **Datas sempre com fuso (UTC).** `datetime.now(UTC)` e `DateTime(timezone=True)`.
- **O 422 padrão do FastAPI ecoa o `input`** (inclusive senhas, mesmo `SecretStr`). O handler em
  `main.py` o remove; não o apague.
- **Exceção dentro do `receive` vira 400 no FastAPI.** Por isso o limite de corpo lê e conta o
  corpo antes de chamar a aplicação.
- **Reuso de refresh token:** a rota faz `commit()` da revogação ANTES de responder 401.
- **Campos de tipo "complexo" no pydantic-settings são lidos do ambiente como JSON.** Os
  limites (`Rate`) usam `NoDecode`; teste configurações pelo AMBIENTE (`monkeypatch.setenv`).
- **Contas do rate limit com `Fraction`, não `float`** (o float errava o Retry-After em 1 s).
- **Retry-After pode passar do tamanho da janela** (as recusadas contam); o teto é 2 janelas.
- **`pkill -f` no terminal** pode casar com o próprio comando; pare o uvicorn com Ctrl+C.
- **`getpass` precisa de um terminal de verdade.** No Windows ele lê direto do console
  (`msvcrt`); com a entrada redirecionada ou sem console, não se comporta como esperado.
