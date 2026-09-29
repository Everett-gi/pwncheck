# Política de Segurança — PwnCheck

## Reportar uma vulnerabilidade

Use o recurso **Report a vulnerability** (aba *Security* → *Advisories*) deste repositório no
GitHub, com a descrição e os passos para reproduzir. Por favor, não abra *issues* públicas para
falhas de segurança.

## O que o PwnCheck protege

A promessa central: **a senha consultada nunca é revelada**.

| Caminho | O que sai da máquina do usuário | Quem pode saber a senha |
|---|---|---|
| Página inicial / `GET /range/{prefixo}` | só o prefixo de 5 caracteres do SHA-1 | ninguém — nem o PwnCheck, nem o HIBP |
| `POST /check`, `POST /policy` | a senha, por HTTPS | o PwnCheck a usa só em memória: nunca a grava nem a registra em log |

Nos dois caminhos, o PwnCheck consulta o HIBP só com o prefixo (k-anonymity), e o banco de dados
recebe só o prefixo e a faixa pública correspondente. Testes automatizados verificam essas
garantias: o que sai para o HIBP, o que chega ao banco (duas senhas com o mesmo prefixo geram
exatamente os mesmos comandos SQL) e o que aparece nos logs.

## Gestão de segredos

- Nenhum segredo é versionado: `.env` está no `.gitignore` e no `.dockerignore`; o repositório só
  tem o `.env.example`, com valores fictícios.
- Segredos entram por **variáveis de ambiente**, em tempo de execução — nunca na imagem Docker.
  Na aplicação, ficam em `SecretStr` (não aparecem em logs nem em *tracebacks*).
- No servidor, o `.env` de produção é criado direto na VM, com `chmod 600`.
- *Secret Scanning* e *Push Protection* do GitHub habilitados no repositório.

## Medidas implementadas

| Risco (OWASP Top 10) | Mitigação |
|---|---|
| **A01 — Broken Access Control** | Rotas protegidas exigem token; `/admin/*` exige o papel de administrador (403); o papel só é concedido por comando no servidor. Campos extras no corpo são recusados (`extra="forbid"`), o que impede *mass assignment* (`is_admin` no cadastro). |
| **A02 — Cryptographic Failures** | Senhas com **Argon2id** (64 MiB, 3 passadas, sal aleatório) e *rehash* automático; refresh tokens de 256 bits guardados como SHA-256; JWT HS256 com chave de 32+ caracteres; TLS obrigatório (Caddy + Let's Encrypt) com **HSTS**. |
| **A03 — Injection** | Banco acessado só via SQLAlchemy com parâmetros ligados; nenhum SQL montado com strings. Restrições `CHECK` no banco. Página inicial com CSP sem scripts inline e saída via `textContent`. |
| **A04 — Insecure Design** | Política de senha do NIST SP 800-63B-4 no próprio cadastro; falha **fechada** quando o HIBP não responde; detecção de reuso de refresh token (revoga a sessão inteira); reautenticação para apagar a conta. |
| **A05 — Security Misconfiguration** | Container com usuário não-root e código só leitura; banco e aplicação sem portas públicas, em redes Docker separadas; cabeçalhos de segurança (CSP, `nosniff`, `X-Frame-Options`, `Referrer-Policy`, `Cache-Control: no-store`); `Server` removido. |
| **A06 — Vulnerable Components** | `pip-audit` e `bandit` bloqueando o CI; Dependabot para pip, GitHub Actions e a imagem base. |
| **A07 — Identification and Authentication Failures** | Mesma resposta e **mesmo tempo** para e-mail inexistente e senha errada (anti-enumeração por temporização); **rate limit** no login por IP e por conta; tokens de acesso de 15 minutos com algoritmo fixo (`alg: none` e troca de algoritmo recusados). |
| **A09 — Logging Failures** | Logs sem senhas, hashes completos, tokens ou e-mails (verificado por testes); só o prefixo k-anônimo aparece. Reuso de refresh token gera alerta no log. |
| **Negação de serviço** | Corpo limitado a 16 KB (Caddy e aplicação, com e sem `Content-Length`); rate limit por IP/usuário; tamanho máximo de senha antes de qualquer regex (ReDoS). |

## Privacidade (LGPD)

- **Coleta mínima:** a conta tem só e-mail e hash da senha. Senhas consultadas não são guardadas.
- **Consentimento:** aceite dos termos obrigatório no cadastro, com data registrada.
- **Direitos do titular:** `GET /auth/me` (acesso) e `DELETE /auth/me` (exclusão, com a senha).
- **Rate limit:** IPs e e-mails entram nos contadores só como SHA-256 (pseudonimização — um IPv4
  pode ser recuperado por força bruta) e são apagados em até dois dias.
- **Métricas:** apenas contagens agregadas por dia, sem nada que identifique pessoas.
- **Logs de acesso** do Caddy e do uvicorn contêm IPs; ficam só no servidor, com rotação (3 × 10 MB
  por container).

## Limitações conhecidas

- Não há confirmação de e-mail: o cadastro revela (409) se um e-mail já tem conta. O rate limit por
  IP no cadastro reduz a enumeração.
- Não há MFA, recuperação de senha nem bloqueio progressivo de conta (atrasos crescentes, CAPTCHA).
- O limite de login por conta permite que um atacante gaste as tentativas de uma vítima por até
  uma hora (troca consciente contra ataques distribuídos).
- `POST /check` exige confiar que o servidor não guarda a senha; o caminho sem confiança é
  `GET /range/{prefixo}`.

## Dependências e verificação

A cada push e pull request, o CI roda lint (ruff, com as regras do bandit), formatação, 196+
testes (com PostgreSQL de verdade), `alembic check`, `pip-audit`, `bandit` e o build da imagem
Docker com um teste de fumaça da stack de produção.
