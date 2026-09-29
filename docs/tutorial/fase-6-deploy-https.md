# PwnCheck — Fase 6: deploy com HTTPS

> **Objetivo:** empacotar o PwnCheck numa imagem Docker enxuta e segura, descrever a stack de
> produção (banco, migrações, aplicação e Caddy com HTTPS automático) e deixar tudo pronto para
> subir na VM da Oracle Cloud — com o CI subindo a stack inteira a cada push.
>
> **Pré-requisito:** [Fase 5 — rate limit e métricas](fase-5-rate-limit-metricas.md).
> **O passo a passo do servidor** está em [`docs/DEPLOY.md`](../DEPLOY.md); esta lição explica
> cada peça.

**O que você vai aprender:** Dockerfile (instruções, camadas, cache) · build em múltiplos
estágios · usuário não-root e código só leitura · `.dockerignore` (e a pegadinha do `**/`) ·
`HEALTHCHECK` · Compose de produção (ordem de subida, serviço de migração, redes separadas,
rotação de logs, âncoras YAML, `${VAR:?}`) · nomes de projeto e volumes · TLS, certificados e
Let's Encrypt (ACME) · Caddy (HTTPS automático, HSTS, HTTP/2, limite de corpo) ·
`X-Forwarded-For` e proxies confiáveis, testados · *profiles* e redes externas · CI com a stack
completa · Dependabot · cron e backups · interceptação de TLS (o proxy do ambiente de nuvem).

> Os blocos `mermaid` viram diagramas no GitHub (ou no VS Code com a extensão *Markdown
> Preview Mermaid Support*). No fim há um **glossário**.

**Sumário**
1. [Do código ao ar: o mapa](#1-do-código-ao-ar-o-mapa)
2. [O Dockerfile, instrução por instrução](#2-o-dockerfile-instrução-por-instrução)
3. [Camadas e cache](#3-camadas-e-cache)
4. [Uma imagem enxuta e segura](#4-uma-imagem-enxuta-e-segura)
5. [O Compose de produção](#5-o-compose-de-produção)
6. [O incidente: dois PostgreSQL no mesmo volume](#6-o-incidente-dois-postgresql-no-mesmo-volume)
7. [HTTPS em 10 minutos](#7-https-em-10-minutos)
8. [O Caddy](#8-o-caddy)
9. [O IP real: `X-Forwarded-For`, testado](#9-o-ip-real-x-forwarded-for-testado)
10. [Um Caddy só por VM](#10-um-caddy-só-por-vm)
11. [CI: a stack de produção a cada push](#11-ci-a-stack-de-produção-a-cada-push)
12. [Operação: cron, backup e atualização](#12-operação-cron-backup-e-atualização)
13. [Bastidores: o proxy TLS do ambiente de nuvem](#13-bastidores-o-proxy-tls-do-ambiente-de-nuvem)
14. [Mão na massa](#14-mão-na-massa)
15. [Decisões de design (bom assunto para entrevista)](#15-decisões-de-design-bom-assunto-para-entrevista)
16. [Glossário](#16-glossário)
17. [Exercícios](#17-exercícios)
18. [Fim do projeto — e o que vem depois](#18-fim-do-projeto--e-o-que-vem-depois)

---

## 1. Do código ao ar: o mapa

```
Dockerfile                  a receita da imagem da aplicação              NOVO
.dockerignore               o que NÃO entra na imagem                     NOVO
docker-compose.prod.yml     a stack de produção                           NOVO
docker-compose.shared-caddy.yml  variante: VM com um Caddy que já existe  NOVO
Caddyfile                   HTTPS, HSTS, limite de corpo, proxy reverso   NOVO
docs/DEPLOY.md              o passo a passo no servidor                   NOVO
SECURITY.md                 as medidas de segurança, por risco da OWASP   NOVO
.github/dependabot.yml      atualizações automáticas de dependências      NOVO
.github/workflows/ci.yml    + job "docker": sobe a stack e testa por HTTPS
docker-compose.yml          + name: pwncheck-dev (seção 6)
```

```mermaid
flowchart LR
    U(["Usuário"]) -- "HTTPS :443<br/>(HTTP :80 redireciona)" --> C
    subgraph VM["VM Oracle Cloud (Ubuntu ARM + Docker)"]
        subgraph FE["rede frontend"]
            C["caddy<br/>TLS · HSTS · 16 KB"]
        end
        subgraph BOTH["nas duas redes"]
            A["pwncheck-app<br/>uvicorn :8080"]
        end
        subgraph BE["rede backend"]
            M["pwncheck-migrate<br/>alembic upgrade head<br/>(roda e termina)"]
            D[("pwncheck-db<br/>PostgreSQL 16")]
        end
        C -- "http://pwncheck-app:8080" --> A
        A --> D
        M --> D
    end
    A -- "só o prefixo" --> H[("api.pwnedpasswords.com")]
    C -. "certificado (ACME)" .- LE[("Let's Encrypt")]
```

Só o Caddy tem portas abertas para a internet. A aplicação e o banco não publicam porta
nenhuma: não há como alcançá-los de fora, mesmo sabendo o IP da VM.

---

## 2. O Dockerfile, instrução por instrução

Um **Dockerfile** é a receita de uma imagem: cada instrução executa um passo sobre o resultado
do anterior.

```dockerfile
# ---------- Estágio 1: dependências ----------
FROM python:3.12-slim AS builder
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
COPY requirements.txt .
RUN /opt/venv/bin/pip install -r requirements.txt

# ---------- Estágio 2: a imagem final ----------
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY pyproject.toml ./
COPY app ./app
COPY migrations ./migrations
USER app
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3)"]
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
```

| Instrução | O que faz | Analogia |
|---|---|---|
| `FROM imagem AS nome` | começa a partir de uma imagem existente (aqui, Debian mínimo + Python 3.12) | o `#include` de uma base pronta |
| `ENV` | define variáveis de ambiente para os passos seguintes e para o container | `export` no shell |
| `RUN` | executa um comando durante o **build** | rodar um passo do `Makefile` |
| `COPY origem destino` | copia arquivos do **contexto** (a pasta do projeto) para a imagem | — |
| `COPY --from=builder` | copia de **outro estágio** do build | linkar um objeto compilado em outro alvo |
| `WORKDIR` | muda a pasta atual (e a cria) | `cd` |
| `USER` | a partir daqui (e na execução), roda como esse usuário | `setuid` |
| `EXPOSE` | documenta a porta que o programa usa (não publica nada) | comentário executável |
| `HEALTHCHECK` | comando que diz se o container está saudável | um *watchdog* |
| `CMD` | o comando padrão quando o container sobe | o `main` |

Alguns detalhes:

- **`python:3.12-slim`**: Debian com o mínimo para rodar Python (179 MB). Há imagens ainda
  menores (`alpine`), mas as *wheels* do PyPI são feitas para a glibc do Debian; com a musl do
  Alpine, algumas dependências teriam de ser compiladas.
- **Um ambiente virtual dentro do container** (`/opt/venv`)? Parece redundante — o container já
  é isolado —, mas deixa as nossas dependências separadas das do Python do sistema, e a pasta
  inteira pode ser copiada de um estágio para o outro de uma vez.
- **`CMD` em formato de lista** (`["uvicorn", ...]`) executa o programa direto, sem um shell no
  meio. Assim, o uvicorn recebe os sinais do Docker (o `SIGTERM` do `docker stop`) e desliga
  com calma, rodando o fim do `lifespan`.
- **`--no-server-header`**: o uvicorn para de anunciar `server: uvicorn`. Esconder a versão do
  software não é defesa (é "segurança por obscuridade"), mas não há por que dar a informação
  de graça.

---

## 3. Camadas e cache

Cada instrução gera uma **camada** (*layer*): a diferença no sistema de arquivos em relação à
anterior. A imagem é a pilha dessas camadas — medimos com `docker history`:

```
  camada                                    tamanho
  ──────────────────────────────────────    ────────
  COPY migrations ./migrations               77,8 kB
  COPY app ./app                            463 kB
  COPY pyproject.toml ./                     12,3 kB
  COPY --from=builder /opt/venv /opt/venv   120 MB     <- as dependências
  RUN useradd ...                           ~10 kB
  python:3.12-slim                          179 MB     <- a base
```

O Docker **reaproveita** uma camada se a instrução e tudo o que veio antes não mudaram. Por
isso o `requirements.txt` é copiado e instalado **antes** do código:

```
  mudou só o código (app/...):
    COPY requirements.txt   -> CACHED
    RUN pip install ...     -> CACHED      (a parte lenta)
    COPY app ./app          -> refeito     (milissegundos)

  mudou o requirements.txt:
    tudo a partir do COPY requirements.txt é refeito
```

Medimos: depois de mudar um arquivo em `app/`, o `pip install` veio do cache e o rebuild levou
**menos de 1 segundo**. Se o código fosse copiado antes do `pip install`, qualquer vírgula
mudada reinstalaria todas as dependências. É o mesmo raciocínio do `make`: só recompila o que
depende do que mudou.

---

## 4. Uma imagem enxuta e segura

### Dois estágios

O estágio `builder` instala as dependências; o estágio final copia **só** o ambiente pronto. O
que ficou no `builder` (o `requirements.txt`, arquivos temporários da instalação) não vai para
a imagem final. Medimos as duas versões:

| Versão | Tamanho |
|---|---|
| Um estágio só (`COPY . .` e `pip install` na mesma imagem) | 367 MB |
| **Dois estágios** (a nossa) | **331 MB** |

A diferença aqui é modesta (~10%), porque todas as nossas dependências vêm **pré-compiladas**
(*wheels*). O ganho grande aparece quando é preciso compilar código C durante o `pip install`:
o compilador (`gcc`, cabeçalhos...) fica no estágio `builder` e não pesa na imagem final — e
não fica disponível para um invasor.

### Menor privilégio dentro do container

```dockerfile
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app
...
USER app
```

Por padrão, o processo de um container roda como **root**. Se alguém explorar uma falha da
aplicação e executar código, ser root dentro do container facilita escapar dele ou mexer em
tudo. Com o usuário `app` (sem senha, sem shell, sem pasta pessoal), o estrago fica limitado.
E como os `COPY` acontecem **antes** do `USER app`, os arquivos pertencem ao root: o usuário
`app` só os lê. Conferimos dentro da imagem:

```
$ id
uid=10001(app) gid=999(app) groups=999(app)
$ touch /app/app/x
touch: cannot touch '/app/app/x': Permission denied
```

A aplicação não consegue alterar o próprio código — um invasor também não.

### `.dockerignore` e a pegadinha do `**/`

O `docker build` envia a pasta do projeto (o **contexto**) para o motor do Docker. O
`.dockerignore` diz o que **não** enviar: primeiro os segredos (`.env`), depois o que não é
necessário (`.git`, `.venv`, `tests`, `docs`).

Na primeira versão, conferindo a imagem, apareceu uma pasta `__pycache__` dentro de `/app/app`.
O `.dockerignore` tinha a linha `__pycache__` — mas, ao contrário do `.gitignore`, **um padrão
sem barra só vale na raiz do contexto**. Para valer em qualquer profundidade, é preciso `**/`:

```
**/__pycache__
**/*.py[cod]
```

(`[cod]` é uma classe de caracteres, como na regex: `.pyc`, `.pyo` ou `.pyd`.) A lição: **olhe
dentro da imagem** que você gerou —
`docker run --rm --entrypoint sh pwncheck -c 'ls -la /app'` —, em vez de confiar que as regras
fazem o que você acha.

### `HEALTHCHECK`

O Docker executa o comando do `HEALTHCHECK` a cada 30 segundos. Se ele falhar 3 vezes
seguidas, o container fica `unhealthy`. A imagem *slim* não tem `curl`, então o próprio Python
faz a requisição ao `/health` (qualquer erro vira exceção, e a exceção vira código de saída
diferente de 0). O Compose usa esse estado para ordenar a subida (seção 5).

---

## 5. O Compose de produção

### A ordem de subida

```mermaid
flowchart LR
    DB["pwncheck-db"] -- "service_healthy<br/>(pg_isready)" --> MIG["pwncheck-migrate<br/>alembic upgrade head"]
    MIG -- "service_completed_successfully<br/>(terminou com código 0)" --> APP["pwncheck-app"]
    DB -- "service_healthy" --> APP
    APP -- "service_healthy<br/>(HEALTHCHECK do Dockerfile)" --> CAD["caddy"]
```

```yaml
  pwncheck-migrate:
    build: .
    image: pwncheck:latest
    command: ["alembic", "upgrade", "head"]
    env_file: .env
    depends_on:
      pwncheck-db:
        condition: service_healthy
    restart: "no"

  pwncheck-app:
    ...
    depends_on:
      pwncheck-db:
        condition: service_healthy
      pwncheck-migrate:
        condition: service_completed_successfully
```

- **Um serviço só para as migrações**: usa a **mesma imagem** da aplicação, mas com outro
  comando, roda uma vez e termina. A aplicação só sobe se ele terminar **com sucesso** — nunca
  uma versão nova do código com o esquema antigo do banco. (O DEPLOY-GERAL pede "rode
  `alembic upgrade head` na subida"; separar em outro serviço evita que duas réplicas da
  aplicação migrem ao mesmo tempo.)
- **`restart: "no"`** para o migrador (ele deve terminar) e `unless-stopped` para os outros
  (voltam sozinhos depois de uma queda ou de um reboot da VM).

Subimos a stack aqui e o log do migrador mostrou exatamente isso:

```
Running upgrade  -> 0001, create prefix_cache
Running upgrade 0001 -> 0002, create users and refresh_tokens
Running upgrade 0002 -> 0003, create rate_limit_counters and usage_metrics
```

seguido de `pwncheck-migrate  Exited (0)` e `pwncheck-app  Up (healthy)`.

### Duas redes: menor privilégio na rede

```yaml
  pwncheck-db:      networks: [backend]
  pwncheck-migrate: networks: [backend]
  pwncheck-app:     networks: [backend, frontend]
  caddy:            networks: [frontend]
```

```
   frontend:  caddy ─────── pwncheck-app
   backend:                 pwncheck-app ─── pwncheck-db ─── pwncheck-migrate
```

Cada rede do Docker é uma rede virtual isolada, com DNS próprio (os containers se acham pelo
**nome do serviço**). O Caddy, o único exposto à internet, **não tem rota** para o banco. Se
alguém explorar uma falha no Caddy, ainda não alcança o PostgreSQL. É a segmentação de rede
que você veria num datacenter (a "DMZ"), em miniatura.

### Logs com rotação, âncoras YAML e variáveis obrigatórias

```yaml
x-logging: &logging
  driver: json-file
  options:
    max-size: "10m"
    max-file: "3"

services:
  pwncheck-db:
    logging: *logging
```

- Por padrão, o Docker guarda o log de cada container **sem limite** — até encher o disco da
  VM. Com `max-size` e `max-file`, cada container guarda no máximo 3 arquivos de 10 MB.
- **`&logging`** define uma **âncora** (um nome para um trecho de YAML) e **`*logging`** a
  reutiliza — um `#define` do YAML. Chaves começando com `x-` são ignoradas pelo Compose: é o
  lugar para esses trechos compartilhados.
- **`"${DOMAIN:?defina DOMAIN no .env, ...}"`**: se a variável faltar, o Compose **para** com a
  mensagem, em vez de subir o Caddy com um domínio vazio. (Entre aspas: um `: ` solto dentro do
  valor confundiu o YAML na primeira versão — `mapping values are not allowed in this context`.)

### Nomes com prefixo

Os serviços se chamam `pwncheck-db`, `pwncheck-app`... e não `db`, `app`. Na seção 10, a
aplicação vai entrar na rede de **outro** projeto (o DocSage), que também tem serviços chamados
`app` e `db`. Com nomes genéricos, o DNS do Docker poderia resolver `db` para o banco do outro
projeto. Nomes únicos eliminam a ambiguidade.

---

## 6. O incidente: dois PostgreSQL no mesmo volume

Ao testar a stack de produção nesta fase, a migração falhou. O motivo era sério.

O Compose agrupa containers, redes e volumes num **projeto**, e usa o nome do projeto como
**prefixo**: o volume `pgdata` do projeto `pwncheck` se chama `pwncheck_pgdata`. O compose de
desenvolvimento não tinha nome explícito — e o Compose usa o **nome da pasta** (`pwncheck`). O
de produção tinha `name: pwncheck`. Resultado:

```
  docker-compose.yml       (projeto "pwncheck")  ── volume pgdata ──┐
                                                                    ├──> pwncheck_pgdata  (O MESMO!)
  docker-compose.prod.yml  (projeto "pwncheck")  ── volume pgdata ──┘
```

O banco de "produção" montou o volume do banco de **desenvolvimento**, que tinha outra senha
(o `POSTGRES_PASSWORD` só é lido na **criação** do volume) — daí a falha de autenticação da
migração. Pior: por alguns segundos, **dois processos do PostgreSQL** rodaram sobre o mesmo
diretório de dados. O PostgreSQL tem um arquivo de trava (`postmaster.pid`) para impedir isso,
mas ele confere o **PID** gravado ali — e cada container tem a sua própria numeração de
processos (namespaces!), então a trava não funciona entre containers. Dois servidores
escrevendo nos mesmos arquivos podem corromper o banco.

O que fizemos:

1. Paramos na hora o container de produção.
2. Conferimos o banco de desenvolvimento (sem sinais de dano) e, por segurança, o recriamos do
   zero — era descartável.
3. Demos **nomes explícitos e diferentes** aos dois projetos: `name: pwncheck-dev` no
   `docker-compose.yml` e `name: pwncheck-prod` no `docker-compose.prod.yml`, com um comentário
   explicando o porquê.

Lições: nomes implícitos (vindos da pasta) são uma fonte de colisões; e volumes de banco são
estado precioso — um descuido de nome pode apontar duas coisas para o mesmo disco.

---

## 7. HTTPS em 10 minutos

**HTTPS** é HTTP dentro de um túnel **TLS**. O TLS garante três coisas:

| Garantia | Contra o quê |
|---|---|
| **Confidencialidade** (criptografia) | alguém no Wi-Fi lendo a senha do `/check` |
| **Integridade** | alguém alterando a resposta no caminho (injetando um script na página) |
| **Autenticidade** (certificado) | alguém se passando pelo servidor |

### Certificados e autoridades

O servidor apresenta um **certificado**: um documento com o domínio e a chave pública do
servidor, **assinado** por uma **autoridade certificadora** (CA). O navegador confia numa
lista de CAs raiz (a *trust store* do sistema). A cadeia fica assim:

```
  CA raiz (na trust store do navegador)
     └─ assina ─> CA intermediária
                     └─ assina ─> certificado de pwncheck-gil.duckdns.org
                                  (chave pública do servidor + validade)
```

No teste local, o Caddy usou a **própria CA local** (o emissor era
`Caddy Local Authority - ECC Intermediate`, com validade de 12 horas), porque `localhost` não
pode ter certificado público. Por isso usamos `curl -k` (aceitar certificado não confiável) —
nunca faça isso em produção.

### Let's Encrypt e o desafio ACME

O **Let's Encrypt** é uma CA gratuita e automatizada. Antes de emitir um certificado para
`pwncheck-gil.duckdns.org`, ela precisa ter certeza de que **você controla** esse domínio. O
protocolo é o **ACME**, e o desafio mais comum é o **HTTP-01**:

```mermaid
sequenceDiagram
    participant C as Caddy (na sua VM)
    participant LE as Let's Encrypt
    C->>LE: quero um certificado para pwncheck-gil.duckdns.org
    LE-->>C: prove: sirva o texto TOKEN em /.well-known/acme-challenge/...
    C->>C: prepara a resposta
    LE->>C: GET http://pwncheck-gil.duckdns.org/.well-known/acme-challenge/... (porta 80)
    C-->>LE: TOKEN
    LE-->>C: certificado assinado (vale 90 dias)
    Note over C: renova sozinho antes de vencer
```

É por isso que:

- o **DNS** precisa apontar para a VM antes (o Let's Encrypt resolve o nome e vai até lá);
- a **porta 80** precisa estar aberta, mesmo que o site só funcione em HTTPS;
- o volume `caddy_data` não pode ser apagado: ele guarda os certificados, e o Let's Encrypt
  limita quantos certificados (e quantas falhas) um domínio pode ter por semana/hora.

O Caddy faz tudo isso **sozinho**: basta o domínio no `Caddyfile`. É o que se chama de *HTTPS
automático*.

---

## 8. O Caddy

```
{
	email {$ACME_EMAIL}
	servers {
		protocols h1 h2
	}
}

{$DOMAIN} {
	encode zstd gzip
	request_body {
		max_size 16KB
	}
	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
		-Server
	}
	reverse_proxy pwncheck-app:8080
	log
}
```

- **`{$DOMAIN}`**: o Caddy lê a variável de ambiente (que o Compose preenche a partir do `.env`).
  Um bloco com um domínio = um site com HTTPS automático, incluindo o **redirecionamento** de
  `http://` para `https://` (testamos: `308 -> https://localhost/health`).
- **`reverse_proxy pwncheck-app:8080`**: o Caddy repassa cada requisição para a aplicação, pela
  rede `frontend`. Ele é um **proxy reverso**: o cliente acha que fala com o Caddy; o Caddy fala
  com a aplicação.
- **`encode zstd gzip`**: comprime as respostas. As faixas do `/range` (~80 KB de texto
  hexadecimal) diminuem bastante.
- **`request_body { max_size 16KB }`**: a primeira barreira do tamanho do corpo (a aplicação
  tem a segunda, desde a fase 4). Testamos: 20 KB → 413.
- **HSTS** (`Strict-Transport-Security`): "pelo próximo ano, use **só** HTTPS com este
  domínio". Depois da primeira visita, o navegador nem tenta mais `http://` — o que fecha a
  janela de um ataque que interceptasse aquela primeira requisição sem criptografia para
  redirecionar a vítima a um site falso (*SSL stripping*). Ele mora no Caddy porque só vale
  numa resposta HTTPS.
- **`-Server`**: remove o cabeçalho que anuncia o servidor.
- **`protocols h1 h2`**: HTTP/1.1 e HTTP/2 (conferimos: a resposta veio em `HTTP/2`). O HTTP/3
  usaria UDP na porta 443, que não está aberta no firewall da VM; desligá-lo evita que os
  navegadores tentem à toa.
- **`log`**: log de acesso na saída padrão, com a rotação do Docker (seção 5).

Os outros cabeçalhos de segurança (CSP, `nosniff`, `X-Frame-Options`...) vêm da **aplicação**,
desde a fase 4 — assim valem também no desenvolvimento, sem o Caddy. Conferimos a resposta
completa, através do Caddy:

```
HTTP/2 200
cache-control: no-store
content-security-policy: default-src 'none'; frame-ancestors 'none'
referrer-policy: no-referrer
strict-transport-security: max-age=31536000; includeSubDomains
x-content-type-options: nosniff
x-frame-options: DENY
```

(E nenhum cabeçalho `server`.)

---

## 9. O IP real: `X-Forwarded-For`, testado

A fase 5 explicou o problema: atrás do Caddy, a conexão sempre vem **do Caddy**. Para o rate
limit funcionar por IP, a aplicação precisa do IP original, que o Caddy manda no cabeçalho
`X-Forwarded-For`. E o uvicorn só aceita esse cabeçalho de proxies confiáveis:

```yaml
  pwncheck-app:
    environment:
      FORWARDED_ALLOW_IPS: "*"
```

`"*"` significa "confie em qualquer um que se conectar a mim". Isso só é seguro porque **a
aplicação não publica porta nenhuma**: só os containers das redes do projeto (na prática, o
Caddy) conseguem se conectar a ela. Com uma porta publicada, `"*"` deixaria qualquer um forjar
o IP.

E se o **cliente** mandar um `X-Forwarded-For` falso para o Caddy? Testamos:

```
> curl -k -H "X-Forwarded-For: 1.2.3.4" https://localhost/health

log da aplicação:  INFO: 172.22.0.1:0 - "GET /health HTTP/1.1" 200 OK
```

A aplicação viu `172.22.0.1` (o endereço de onde a conexão chegou ao Caddy), **não** o
`1.2.3.4` forjado: o Caddy, por padrão, **sobrescreve** o `X-Forwarded-For` que vem de clientes
em quem ele não confia. (Testando da própria máquina, o IP visto é o *gateway* da rede do
Docker; na internet, é o IP público do usuário.)

```
  cliente (mente: XFF 1.2.3.4) ──> Caddy: "não confio em você" ──> XFF: <IP real da conexão>
                                                                         │
                                          uvicorn: "confio no Caddy" <───┘  request.client.host
```

---

## 10. Um Caddy só por VM

O DEPLOY-GERAL recomenda **um Caddy para a VM inteira**, com um bloco por domínio — só um
processo pode escutar nas portas 80/443. Se o DocSage já está no ar com o Caddy dele, o
PwnCheck entra assim:

```yaml
# docker-compose.shared-caddy.yml
services:
  caddy:
    profiles: ["desligado"]
  pwncheck-app:
    networks: [backend, frontend, edge]

networks:
  edge:
    external: true
    name: ${EDGE_NETWORK:?defina EDGE_NETWORK com o nome da rede do Caddy central}
```

```
  docker compose -f docker-compose.prod.yml -f docker-compose.shared-caddy.yml up -d
                    └──── a base ────────┘    └──── sobrescreve partes ─────┘
```

- **Vários `-f`**: o Compose junta os arquivos, e o segundo **sobrescreve/acrescenta** ao
  primeiro. A base continua igual; a variação fica num arquivo pequeno.
- **`profiles: ["desligado"]`**: um serviço com *profile* só sobe se alguém ativar esse
  profile (`--profile desligado`). Ninguém ativa: o Caddy do PwnCheck fica desligado.
- **`external: true`**: a rede `edge` já existe (é a do outro projeto). O Compose só a usa —
  não a cria nem a apaga.
- A aplicação entra na rede do Caddy central, que a alcança pelo nome `pwncheck-app` — e é aqui
  que os **nomes com prefixo** (seção 5) evitam confusão com o `app` do DocSage.

Testamos com um Caddy "central" simulado numa rede `edge-teste`: o Caddy do PwnCheck não subiu,
e o central respondeu `/health` e `/range` pela aplicação do PwnCheck. O passo a passo com o
DocSage de verdade está em `docs/DEPLOY.md`.

---

## 11. CI: a stack de produção a cada push

O CI ganhou um terceiro job, `docker`, que faz no GitHub o mesmo que fizemos aqui:

1. cria um `.env` com segredos **aleatórios e descartáveis** (`openssl rand`) e
   `DOMAIN=localhost`;
2. `docker compose -f docker-compose.prod.yml up -d --build --wait` — constrói a imagem, roda as
   migrações, sobe a aplicação e o Caddy, e espera todos ficarem saudáveis;
3. teste de fumaça por HTTPS: `/health` responde, o HSTS está lá, `http://` redireciona (308) e
   `/check` sem token dá 401;
4. em caso de falha, imprime os logs dos containers; no fim, derruba tudo (`down -v`).

Um **teste de fumaça** (*smoke test*) não testa regras de negócio (os 196 testes fazem isso); ele
verifica que o sistema **liga** — que o Dockerfile, o Compose, o Caddyfile e as migrações
funcionam juntos. Erros de configuração são os mais comuns num deploy, e nenhum teste unitário
os pega.

### Dependabot

O `.github/dependabot.yml` pede ao GitHub que abra *pull requests* quando saírem versões novas
das dependências pip (semanal), das actions do CI e da imagem base do Dockerfile (mensal). Cada
PR passa pelo CI inteiro — inclusive o `pip-audit` e a stack de produção. Com dependências
travadas em `==X.Y.*`, as correções entram sozinhas; o Dependabot cuida das versões novas.

---

## 12. Operação: cron, backup e atualização

O `docs/DEPLOY.md` tem os comandos; aqui, o porquê.

- **`python -m app.manage maintenance` no cron** (todo dia às 3h): apaga cache expirado,
  contadores velhos do rate limit e refresh tokens vencidos. Rodando **dentro** do container
  (`docker compose exec -T pwncheck-app ...`), ele usa a mesma imagem e o mesmo `.env` da
  aplicação. `-T` desliga o terminal interativo, que o cron não tem.
- **Backup com `pg_dump`**: um arquivo SQL com o esquema e os dados, compactado com `gzip`.
  Testamos o comando: 89 KB, com as 6 tabelas. O `pg_dump` roda dentro do container do banco,
  onde as variáveis `POSTGRES_USER` e `POSTGRES_DB` já existem — por isso o `sh -c '...'` com
  aspas simples (as variáveis são expandidas **dentro** do container, não na VM).
- **Atualizar** é `git pull` + `up -d --build`: a imagem é refeita (rápido, graças ao cache de
  camadas), o migrador aplica as migrações novas, e só então a aplicação nova sobe.
- **`SECURITY.md`**: a baseline do portfólio pede que cada repositório documente suas medidas.
  O do PwnCheck organiza tudo pelas categorias do **OWASP Top 10** e lista as limitações
  conhecidas — ser honesto sobre o que falta é parte da segurança.

---

## 13. Bastidores: o proxy TLS do ambiente de nuvem

Este projeto foi desenvolvido num ambiente de nuvem, e o primeiro `docker build` falhou assim:

```
SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify
failed: self-signed certificate in certificate chain'))
Could not find a version that satisfies the requirement httpx==0.28.*
```

Nesse ambiente, todo o tráfego HTTPS de saída passa por um **proxy que intercepta o TLS**: ele
abre a conexão com o `pypi.org` e apresenta ao programa um certificado **dele**, assinado por uma
CA **dele**. Fora dos containers, a máquina confia nessa CA (ela foi instalada na *trust store*).
Dentro de um container novo, não — e o `pip` recusou, corretamente: do ponto de vista dele,
aquilo era um **ataque de homem no meio** (*man-in-the-middle*).

Empresas fazem o mesmo (para inspecionar tráfego), e a solução legítima é **confiar
explicitamente** na CA do proxy — nunca desligar a verificação de certificados. Para os testes
desta fase, construímos uma cópia do Dockerfile (fora do repositório) que entrega o certificado
ao `pip` por um *secret* do BuildKit — um arquivo montado só durante aquele `RUN`, que não fica
em nenhuma camada:

```dockerfile
RUN --mount=type=secret,id=ca PIP_CERT=/run/secrets/ca /opt/venv/bin/pip install -r requirements.txt
```

```
docker build --secret id=ca,src=/caminho/ca-bundle.crt ...
```

O Dockerfile do repositório ficou limpo — é ele que roda no GitHub e na sua VM, onde não há
interceptação. Pela mesma razão, no teste da stack local foi preciso dar à aplicação o
certificado do proxy (`SSL_CERT_FILE`) para ela alcançar o HIBP de dentro do container.

---

## 14. Mão na massa

### Teste a stack de produção no seu PC

Use uma **segunda cópia** do repositório, para o `.env` de produção não se misturar com o de
desenvolvimento (o nome do projeto já é diferente — seção 6):

```powershell
cd C:\dev
git clone https://github.com/Everett-gi/pwncheck.git pwncheck-prod-teste
cd pwncheck-prod-teste
notepad .env
```

Conteúdo (gere a senha e o segredo com `python -c "import secrets; print(secrets.token_urlsafe(32))"`):

```
POSTGRES_DB=pwncheck
POSTGRES_USER=pwncheck
POSTGRES_PASSWORD=SENHA_GERADA
DATABASE_URL=postgresql+psycopg://pwncheck:SENHA_GERADA@pwncheck-db:5432/pwncheck
JWT_SECRET=SEGREDO_GERADO
DOMAIN=localhost
ACME_EMAIL=teste@exemplo.com
```

```powershell
docker compose -f docker-compose.prod.yml up -d --build --wait
docker compose -f docker-compose.prod.yml ps -a
docker compose -f docker-compose.prod.yml logs pwncheck-migrate
```

Abra **https://localhost** (o navegador vai avisar sobre o certificado da CA local do Caddy:
aceite só aqui, é o seu PC). Teste a página, o `/docs` e:

```powershell
curl.exe -sk -D - https://localhost/health        # cabeçalhos, com HSTS e sem Server
curl.exe -s -o NUL -w "%{http_code}" http://localhost/health   # 308
docker compose -f docker-compose.prod.yml exec pwncheck-app python -m app.manage cache-stats
docker compose -f docker-compose.prod.yml down -v   # derruba e APAGA os dados de teste
```

(`curl.exe`, e não `curl`: no PowerShell, `curl` é um apelido do `Invoke-WebRequest`.)

### Depois, o servidor

Siga o [`docs/DEPLOY.md`](../DEPLOY.md). Ele começa pelo guia do DocSage (a VM) e cobre os dois
cenários — PwnCheck sozinho ou dividindo a VM com o DocSage.

---

## 15. Decisões de design (bom assunto para entrevista)

- **Por que um serviço de migração separado, e não rodar o Alembic no início do container da
  aplicação?** Com duas réplicas da aplicação, as duas tentariam migrar ao mesmo tempo. Separado,
  roda uma vez, e a aplicação só sobe com o esquema certo (`service_completed_successfully`).
- **Por que Caddy e não Nginx?** HTTPS automático (emissão e renovação) com duas linhas de
  configuração, HTTP/2 e bons padrões (como sobrescrever o `X-Forwarded-For`). O Nginx é ótimo,
  mas exigiria o Certbot e mais configuração — mais lugares para errar.
- **Por que duas redes?** Menor privilégio: o único container exposto à internet não enxerga o
  banco.
- **Por que `FORWARDED_ALLOW_IPS="*"` e não o IP do Caddy?** O IP do Caddy é atribuído pelo
  Docker e muda. Como a aplicação não publica porta, só containers das redes do projeto a
  alcançam — o risco fica contido. Fixar o IP (redes com sub-rede definida) é o exercício 4.
- **Por que construir a imagem na VM (`--build`) e não num registro de imagens?** Simplicidade:
  um `git pull` e pronto, sem credenciais de registro na VM. O próximo passo natural seria o CI
  publicar a imagem no GitHub Container Registry e a VM só baixá-la (exercício 5).
- **Por que o teste de fumaça no CI, se já há 196 testes?** Eles testam o código; o de fumaça
  testa a **montagem** — Dockerfile, Compose, Caddyfile, migrações e variáveis. Os três
  problemas desta fase (o `**/` do `.dockerignore`, o `: ` no YAML e a colisão de nomes de
  projeto) eram todos de montagem.

---

## 16. Glossário

| Termo | O que é |
|---|---|
| **Dockerfile** | Receita de uma imagem: instruções executadas em sequência. |
| **Camada (layer)** | O resultado de uma instrução; a imagem é uma pilha de camadas. |
| **Cache de build** | Reaproveitamento de camadas cujas entradas não mudaram. |
| **Contexto de build** | A pasta enviada ao Docker no `docker build`. |
| **Multi-stage build** | Build em estágios; a imagem final copia só o necessário dos anteriores. |
| **Wheel** | Pacote Python pré-compilado (`.whl`), instalado sem compilar nada. |
| **Usuário não-root** | Rodar o processo sem privilégios de administrador. |
| **Healthcheck** | Comando periódico que diz se o container está saudável. |
| **Serviço one-shot** | Container que executa uma tarefa e termina (o migrador). |
| **Rede Docker** | Rede virtual isolada, com DNS pelo nome do serviço. |
| **Segmentação de rede** | Separar serviços em redes para limitar quem alcança quem. |
| **DMZ** | Zona de rede exposta, separada da rede interna. |
| **Âncora YAML** | `&nome` define e `*nome` reutiliza um trecho do YAML. |
| **Projeto Compose** | O grupo de containers/redes/volumes; o nome vira prefixo. |
| **Profile** | Marca que faz um serviço só subir quando o profile é ativado. |
| **Rede externa** | Rede criada fora do projeto, que o Compose só usa. |
| **TLS** | Protocolo que cifra e autentica a conexão (o "S" do HTTPS). |
| **Certificado** | Documento que liga um domínio a uma chave pública, assinado por uma CA. |
| **CA** | Autoridade certificadora: quem assina certificados. |
| **Trust store** | A lista de CAs em que o sistema/navegador confia. |
| **Let's Encrypt** | CA gratuita e automatizada. |
| **ACME / HTTP-01** | Protocolo de emissão automática / desafio que prova o controle do domínio pela porta 80. |
| **Proxy reverso** | Servidor na frente da aplicação que repassa as requisições. |
| **HSTS** | Cabeçalho que obriga o navegador a usar só HTTPS com o domínio. |
| **SSL stripping** | Ataque que mantém a vítima em HTTP, interceptando o redirecionamento. |
| **HTTP/2** | Versão do HTTP com várias requisições numa mesma conexão. |
| **Smoke test** | Teste rápido de que o sistema liga e responde. |
| **Dependabot** | Robô do GitHub que abre PRs de atualização de dependências. |
| **Cron / crontab** | Agendador de tarefas do Linux / a tabela de agendamentos. |
| **pg_dump** | Ferramenta de backup lógico do PostgreSQL. |
| **Man-in-the-middle** | Alguém no meio da conexão se passando pelas duas pontas. |
| **Interceptação de TLS** | Proxy que abre o TLS com um certificado próprio (legítimo só com CA confiável). |
| **BuildKit secret** | Arquivo disponível só durante um `RUN`, sem ficar na imagem. |
| **OWASP Top 10** | Lista dos riscos de segurança mais críticos em aplicações web. |

---

## 17. Exercícios

1. **Veja o cache.** Rode `docker build -t pwncheck .` duas vezes; depois mude um comentário em
   `app/policy.py` e rode de novo. Quais passos aparecem como `CACHED`? Agora mova o
   `COPY app ./app` para **antes** do `pip install` (numa cópia do Dockerfile) e repita. O que
   mudou?
2. **Olhe dentro da imagem.** Com
   `docker run --rm --entrypoint sh pwncheck -c '...'`, responda: qual usuário roda o processo?
   A pasta `tests` está lá? E o `.env`? O usuário `app` consegue criar um arquivo em `/app`?
3. **Quebre a ordem de subida.** No `docker-compose.prod.yml` de teste, mude o `command` do
   migrador para `["false"]` (um comando que sempre falha). Suba a stack. O que acontece com a
   aplicação? Por quê?
4. **Desafio: confiar só no Caddy.** Defina uma sub-rede fixa para a rede `frontend`
   (`ipam: config: - subnet: 172.30.10.0/24`) e troque `FORWARDED_ALLOW_IPS` por essa sub-rede.
   Teste com `X-Forwarded-For` de novo. Qual o risco de fixar sub-redes numa VM com vários
   projetos?
5. **Desafio: publicar a imagem.** Escreva um job de CI que, num push na `main`, publique a
   imagem no GitHub Container Registry (`ghcr.io/everett-gi/pwncheck`) usando o `GITHUB_TOKEN`
   com `permissions: packages: write`. O que mudaria no `docker-compose.prod.yml` da VM?
6. **Restaure um backup.** Com a stack de teste no ar, faça um backup, derrube com `down -v`,
   suba de novo (banco vazio, as migrações criam as tabelas) e restaure. O que acontece com as
   tabelas que as migrações já criaram? Como resolver?

<details>
<summary>Respostas</summary>

1. Na terceira rodada, `pip install` fica `CACHED` e só os `COPY` do código (e o que vem depois)
   são refeitos. Com o `COPY app` antes do `pip install`, qualquer mudança no código invalida a
   camada do `pip install`, e as dependências são reinstaladas a cada build.
2. `uid=10001(app)`; `tests` e `.env` não existem (`.dockerignore`); `touch /app/x` dá
   `Permission denied` (a pasta é do root).
3. O migrador termina com código 1, a condição `service_completed_successfully` não é
   satisfeita, e o Compose **não** sobe a aplicação (nem o Caddy, que depende dela). O
   `up --wait` falha com `service "pwncheck-migrate" didn't complete successfully: exit 1`. É o
   comportamento desejado: melhor ficar fora do ar do que rodar com o esquema errado.
4. Com a sub-rede fixa e o Caddy nela, o uvicorn só aceita o `X-Forwarded-For` vindo dali. O
   risco: se outra rede Docker (de outro projeto) já usar essa faixa, o Compose falha com
   `Pool overlaps with other one on this address space`. Numa VM compartilhada, é preciso
   combinar as faixas entre os projetos.
5. Use `docker/login-action` com `registry: ghcr.io`, `username: ${{ github.actor }}` e
   `password: ${{ secrets.GITHUB_TOKEN }}`, e `docker/build-push-action` com `push: true` e
   `tags: ghcr.io/everett-gi/pwncheck:latest` (em minúsculas). Na VM, os serviços usariam
   `image: ghcr.io/everett-gi/pwncheck:latest` sem `build:`, e a atualização viraria
   `docker compose pull && docker compose up -d`. Se o pacote for privado, a VM precisa de um
   `docker login` com um token de leitura.
6. O `pg_dump` padrão gera `CREATE TABLE`, que falha porque as tabelas já existem. Opções:
   restaurar **antes** das migrações (suba só o `pwncheck-db`, restaure, depois suba o resto —
   o Alembic vê a versão 0003 na `alembic_version` e não faz nada), ou gerar o backup com
   `pg_dump --clean --if-exists`, que apaga e recria cada objeto.

</details>

---

## 18. Fim do projeto — e o que vem depois

O PwnCheck está completo. Em seis fases, você passou pela pilha inteira de uma aplicação web
moderna, sempre com a segurança na frente:

| Fase | O que foi construído | O que ficou de aprendizado |
|---|---|---|
| 1 | cliente k-anonymity | hashing, `str` × `bytes`, pytest, mocks, CI |
| 2 | política de senha (NIST) | Unicode, dataclass, enum, regex, ReDoS |
| 3 | cache no PostgreSQL | Docker, SQL, SQLAlchemy, Alembic, transações |
| 4 | API + autenticação | HTTP, FastAPI, Pydantic, Argon2, JWT, rotação de tokens |
| 5 | rate limit + métricas | algoritmos, `Fraction`, testes de propriedade, concorrência |
| 6 | deploy com HTTPS | Dockerfile, Compose, TLS, Caddy, proxies, CI de ponta a ponta |

O próximo projeto da trilha Python é o **FileSentry**: ele reaproveita os hashes (agora de
arquivos inteiros, lidos em blocos) e acrescenta `pathlib`, threads e uma API externa com chave.
