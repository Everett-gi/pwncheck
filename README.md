# PwnCheck

[![CI](https://github.com/Everett-gi/pwncheck/actions/workflows/ci.yml/badge.svg)](https://github.com/Everett-gi/pwncheck/actions/workflows/ci.yml)

Verifica se uma senha já apareceu em vazamentos de dados **sem enviar a senha a ninguém**,
usando o modelo **k-anonymity** da API [Pwned Passwords](https://haveibeenpwned.com/Passwords)
(HaveIBeenPwned).

> 🚧 **Em construção — fases 1 a 4 de 6 concluídas:** o cliente k-anonymity, a política de
> senha (NIST SP 800-63B-4), o cache de prefixos em PostgreSQL e a API web (FastAPI) com
> contas de usuário. *Rate limit*, métricas e o deploy vêm nas próximas fases.

## Como funciona

```
senha ──SHA-1──> 21BD1 2DC183F740EE76F27B78EB39C8AD972A757
                 └─┬─┘ └───────────────┬─────────────────┘
                prefixo      sufixo: nunca sai da máquina
                   │
                   └──> GET /range/21BD1 ──> a API devolve TODOS os sufixos vazados
                                             com esse prefixo; a comparação é feita aqui
```

1. O SHA-1 da senha é calculado localmente.
2. Só os **5 primeiros caracteres** do hash vão para a API.
3. A API devolve todos os sufixos vazados que começam com esse prefixo (cerca de dois mil) e
   a comparação acontece localmente.

Quem observa a consulta — inclusive a própria API — vê apenas um prefixo compartilhado por
milhares de hashes, e não tem como saber qual era o nosso. A resposta ainda vem com
*padding* (entradas falsas), para que nem o tamanho do tráfego revele o prefixo.

## A API

| Rota | Acesso | O que faz |
|---|---|---|
| `GET /` | público | página que verifica a senha **no navegador**: só o prefixo do hash sai |
| `GET /range/{prefixo}` | público | sufixos vazados do prefixo, no formato do HIBP (k-anonymity) |
| `POST /check` | login | a senha foi vazada? quantas vezes? |
| `POST /policy` | login | avaliação completa da política (com contexto e MFA) |
| `POST /auth/register`, `/login`, `/refresh`, `/logout` | — | contas e sessões |
| `GET` / `DELETE /auth/me` | login | ver e apagar a própria conta (LGPD) |

Documentação interativa em `/docs`. Segurança da autenticação: senhas com **Argon2id**; login
com tempo de resposta constante (não revela quais e-mails têm conta); **JWT** de 15 minutos com
algoritmo fixo; **refresh tokens** de uso único, guardados como hash, com **detecção de reuso**
(um token roubado e reutilizado derruba a sessão inteira). Respostas com CSP, `nosniff` e
`no-store`; corpo limitado a 16 KB; erros de validação sem eco da senha.

## Política de senha

Não vazar não basta: a senha também precisa ser forte. A política segue o
[NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) (2025):
**comprimento acima de complexidade** (15+ caracteres, ou 8+ com MFA), **nenhuma** regra do
tipo "maiúscula, número e símbolo", e comparação da senha inteira — e de seus derivados
óbvios, como `P@ssw0rd123` — com senhas comuns, palavras do contexto e vazamentos. Toda
rejeição vem com o motivo e uma dica.

| Senha | Resultado |
|---|---|
| `P@ssw0rd` | ❌ curta, comum e vazada 6,4 milhões de vezes |
| `cavalo correto bateria grampo azul` | ✅ aceita |

## Cache de prefixos

As faixas consultadas ficam guardadas no PostgreSQL (~2 ms por leitura, contra ~80 ms da API),
com validade de 24 h e uma janela de *stale-if-error*: se o HIBP cair, uma cópia de até 7 dias
ainda responde. Só o **prefixo** chega ao banco — um teste prova que duas senhas diferentes
com o mesmo prefixo geram exatamente os mesmos comandos SQL.

## Rodando localmente (Windows / PowerShell)

Pré-requisitos: Python 3.12 e, para o cache, Docker Desktop.

```powershell
git clone https://github.com/Everett-gi/pwncheck.git
cd pwncheck
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt

python -m app.cli      # verifica uma senha de verdade: vazamentos + política (digitação oculta)

# Banco (fase 3)
Copy-Item .env.example .env        # e troque as senhas
docker compose up -d               # PostgreSQL 16 num container
alembic upgrade head               # cria as tabelas
pytest -v                          # 163 testes, sem acesso à internet
python -m app.cli --cache          # a 2ª consulta da mesma senha vem do cache

# API (fase 4): preencha JWT_SECRET no .env antes
uvicorn app.main:create_app --factory --reload   # http://127.0.0.1:8000 e /docs
```

Sem o banco configurado, os testes que precisam dele são pulados e o resto roda normalmente.

## Qualidade e segurança

- **Testes com a API simulada** (`httpx.MockTransport`), incluindo um que garante que só o
  prefixo do hash sai da máquina: URL, cabeçalhos e corpo da requisição são inspecionados.
- **Testes com PostgreSQL de verdade** (no CI, um *service container*), isolados por
  savepoints; as migrações do Alembic são testadas a cada execução (`alembic check`).
- **Lint** com `ruff`, incluindo as regras de segurança do bandit, e formatação automática.
- **CI** no GitHub Actions: lint, formatação, testes, `pip-audit` e `bandit` a cada push, com
  token de privilégio mínimo.
- A senha nunca é impressa, logada, persistida ou aceita como argumento de linha de comando.

## Roadmap

1. ✅ Cliente k-anonymity + testes
2. ✅ Política de força de senha (NIST SP 800-63B-4)
3. ✅ Cache de prefixos (PostgreSQL + SQLAlchemy + Alembic + Docker)
4. ✅ API REST (FastAPI) + autenticação (Argon2id, JWT, refresh com rotação)
5. Rate limit + métricas
6. Deploy com HTTPS

O passo a passo de cada fase, em formato de tutorial, está em [docs/tutorial/](docs/tutorial/).

---

Parte do portfólio [Projetos-e-ideias](https://github.com/Everett-gi/Projetos-e-ideias).
