# PwnCheck — Contexto do Projeto

> Handoff para o Claude Code. Convenções compartilhadas em `../../README.md`.
> **Status:** blueprint (a construir). Referência de qualidade: `../docsage`.

## O que é
API que verifica se uma senha apareceu em vazamentos usando **k-anonymity** (padrão do
HaveIBeenPwned): a senha **nunca** sai do servidor — só um prefixo de hash é consultado.

**Valor de portfólio:** um padrão de privacidade elegante (k-anonymity), ótimo tema de entrevista.

## Stack
Python 3.12 · FastAPI · httpx · SQLAlchemy 2 · Alembic · PostgreSQL 16 (cache de prefixos) ·
pytest · ruff.

## Como funciona (k-anonymity)
1. Calcula o SHA-1 da senha localmente.
2. Envia à API pública **apenas os 5 primeiros caracteres** do hash.
3. Recebe a lista de sufixos correspondentes e compara **localmente**.
A senha e o hash completo nunca trafegam.

## Modelo de dados
- **prefix_cache** (prefix, suffixes JSONB, fetched_at)
- **usage_metrics** (id, date, checks_count)

## Endpoints principais
- `POST /check` — recebe uma senha, retorna se foi vista em vazamentos e quantas vezes
- `POST /policy` — valida força da senha contra uma política

## Foco de segurança
A senha **nunca** é logada nem persistida; só o prefixo de hash trafega; **rate limit**;
HTTPS obrigatório; cache para reduzir chamadas externas.

## Plano de build
1. Cliente k-anonymity (função pura + testes com resposta mockada) + Alembic
2. Política de força de senha
3. Cache de prefixos
4. API + autenticação
5. Rate limit + métricas
6. Deploy (ver `../../DEPLOY-GERAL.md`)

## Como começar
Scaffold a partir de `../../../projeto-template` (use `Dockerfile.python`). Escreva o teste do
cliente k-anonymity primeiro, garantindo que a senha completa nunca é enviada.
