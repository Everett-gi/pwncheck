# PwnCheck

[![CI](https://github.com/Everett-gi/pwncheck/actions/workflows/ci.yml/badge.svg)](https://github.com/Everett-gi/pwncheck/actions/workflows/ci.yml)

Verifica se uma senha já apareceu em vazamentos de dados **sem enviar a senha a ninguém**,
usando o modelo **k-anonymity** da API [Pwned Passwords](https://haveibeenpwned.com/Passwords)
(HaveIBeenPwned).

> 🚧 **Em construção — fases 1 e 2 de 6 concluídas:** o cliente k-anonymity e a política de
> senha (NIST SP 800-63B-4). O cache em PostgreSQL, a API web (FastAPI) e o deploy vêm nas
> próximas fases.

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

## Rodando localmente (Windows / PowerShell)

Pré-requisito: Python 3.12.

```powershell
git clone https://github.com/Everett-gi/pwncheck.git
cd pwncheck
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt

pytest -v              # 74 testes, sem acesso à internet
python -m app.cli      # verifica uma senha de verdade: vazamentos + política (digitação oculta)
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
2. ✅ Política de força de senha (NIST SP 800-63B-4)
3. Cache de prefixos (PostgreSQL + Alembic + Docker)
4. API REST (FastAPI) + autenticação
5. Rate limit + métricas
6. Deploy com HTTPS

O passo a passo de cada fase, em formato de tutorial, está em [docs/tutorial/](docs/tutorial/).

---

Parte do portfólio [Projetos-e-ideias](https://github.com/Everett-gi/Projetos-e-ideias).
