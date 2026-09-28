# PwnCheck

Verifica se uma senha já apareceu em vazamentos de dados **sem enviar a senha a ninguém**,
usando o modelo **k-anonymity** da API [Pwned Passwords](https://haveibeenpwned.com/Passwords)
(HaveIBeenPwned).

> 🚧 **Em construção — fase 1 de 6 concluída:** o cliente k-anonymity, com testes.
> A API web (FastAPI), o cache em PostgreSQL e o deploy vêm nas próximas fases.

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

## Rodando localmente (Windows / PowerShell)

Pré-requisito: Python 3.12.

```powershell
cd python\pwncheck
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt

pytest -v              # 17 testes, sem acesso à internet
python -m app.cli      # verifica uma senha de verdade (a digitação fica oculta)
```

## Qualidade e segurança

- **Testes com a API simulada** (`httpx.MockTransport`), incluindo um que garante que só o
  prefixo do hash sai da máquina: URL, cabeçalhos e corpo da requisição são inspecionados.
- **Lint** com `ruff`, incluindo as regras de segurança do bandit, e formatação automática.
- **CI** no GitHub Actions: lint, formatação, testes, `pip-audit` e `bandit` a cada push, com
  token de privilégio mínimo.
- A senha nunca é impressa, logada, persistida ou aceita como argumento de linha de comando.

## Roadmap

1. ✅ Cliente k-anonymity + testes
2. Política de força de senha
3. Cache de prefixos (PostgreSQL + Alembic + Docker)
4. API REST (FastAPI) + autenticação
5. Rate limit + métricas
6. Deploy com HTTPS

O passo a passo de cada fase, em formato de tutorial, está em [docs/tutorial/](docs/tutorial/).
