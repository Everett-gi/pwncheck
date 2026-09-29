# PwnCheck — Fase 3: cache de prefixos com PostgreSQL, SQLAlchemy, Alembic e Docker

> **Objetivo:** guardar as respostas da API do HIBP num banco de dados, para que consultas
> repetidas não precisem sair pela internet — sem abrir mão da privacidade: o banco também
> não pode saber qual senha foi consultada.
>
> **Pré-requisito:** [Fase 2 — política de senha](fase-2-politica-de-senha.md).

**O que você vai aprender:** cache, TTL e *stale-if-error* · datas com fuso horário ·
Docker (imagem, container, volume, porta) e Docker Compose · WSL 2 · PostgreSQL e o SQL
essencial (`CREATE TABLE`, `SELECT`, `INSERT ... ON CONFLICT`, `CHECK`, `JSONB`,
`timestamptz`) · transações e ACID · SQLAlchemy 2 (Engine, pool, Session, mapeamento
declarativo, mapa de identidade, Core × ORM) · Alembic (migrações, `--autogenerate`,
`upgrade`/`downgrade`/`check`) · `pydantic-settings` e `SecretStr` · `logging` ·
`argparse` com subcomandos · fixtures do pytest com escopo e `yield` · savepoints ·
*event listeners* · `@contextmanager` · `services` no GitHub Actions.

> Os blocos `mermaid` viram diagramas no GitHub (ou no VS Code com a extensão *Markdown
> Preview Mermaid Support*). No fim há um **glossário** com todos os termos técnicos.

**Sumário**
1. [Por que um cache?](#1-por-que-um-cache)
2. [A arquitetura da fase 3](#2-a-arquitetura-da-fase-3)
3. [Validade: TTL e stale-if-error](#3-validade-ttl-e-stale-if-error)
4. [Docker em 15 minutos](#4-docker-em-15-minutos)
5. [Instalando o WSL 2 e o Docker Desktop](#5-instalando-o-wsl-2-e-o-docker-desktop)
6. [`docker-compose.yml` linha a linha](#6-docker-composeyml-linha-a-linha)
7. [Configuração: `.env`, `pydantic-settings` e `SecretStr`](#7-configuração-env-pydantic-settings-e-secretstr)
8. [PostgreSQL e o SQL essencial](#8-postgresql-e-o-sql-essencial)
9. [SQLAlchemy: o ORM](#9-sqlalchemy-o-orm)
10. [Transações e o upsert atômico](#10-transações-e-o-upsert-atômico)
11. [O serviço de cache: `prefix_cache.py`](#11-o-serviço-de-cache-prefix_cachepy)
12. [Alembic: migrações do esquema](#12-alembic-migrações-do-esquema)
13. [Privacidade: o banco também não sabe](#13-privacidade-o-banco-também-não-sabe)
14. [`logging`](#14-logging)
15. [A CLI e os comandos de manutenção (`argparse`)](#15-a-cli-e-os-comandos-de-manutenção-argparse)
16. [Testes com banco de verdade](#16-testes-com-banco-de-verdade)
17. [CI: um PostgreSQL dentro do GitHub Actions](#17-ci-um-postgresql-dentro-do-github-actions)
18. [Mão na massa](#18-mão-na-massa)
19. [Decisões de design (bom assunto para entrevista)](#19-decisões-de-design-bom-assunto-para-entrevista)
20. [Glossário](#20-glossário)
21. [Exercícios](#21-exercícios)
22. [Próxima fase](#22-próxima-fase)

---

## 1. Por que um cache?

Um **cache** é uma cópia local de dados caros de obter. A CPU tem cache L1/L2/L3 para não ir
à RAM toda hora; o navegador guarda imagens para não baixá-las de novo. Aqui, a "RAM lenta"
é a API do HIBP, do outro lado da internet.

Medimos no ambiente de desenvolvimento:

| Operação | Tempo |
|---|---|
| Consulta à API do HIBP (primeira, com aperto de mão TLS) | ~470 ms |
| Consulta à API do HIBP (conexão já aberta) | 75 a 92 ms |
| Mesma faixa lida do nosso PostgreSQL (*cache hit*) | ~2 ms |

Três ganhos:

1. **Latência:** 30 a 200 vezes mais rápido.
2. **Resiliência:** se o HIBP cair, ainda respondemos com a cópia (seção 3).
3. **Educação com o serviço alheio:** a API do HIBP é gratuita; não é justo martelá-la com a
   mesma pergunta mil vezes. Na fase 4, com usuários de verdade, os prefixos se repetem
   muito — senhas fracas se concentram em poucos hashes.

E o custo? Cada faixa tem ~2 mil sufixos. Em JSON são ~80 KB; no PostgreSQL, que comprime o
JSONB, ~70 KB. Mil prefixos em cache ≈ 70 MB. Não tentamos guardar os 1.048.576 prefixos
(seriam ~70 GB): o cache cresce com o uso, e o comando `purge-cache` apaga o que expirou.

---

## 2. A arquitetura da fase 3

```
app/
├── kanonymity.py      (fase 1, puro)     hash, divisão, parsing
├── hibp_client.py     (fase 1, rede)     fetch_range, check_password
├── policy.py          (fase 2, puro)     política de senha
├── freshness.py       NOVO (puro)        a cópia ainda serve? FRESH / STALE / EXPIRED
├── config.py          NOVO               configuração lida do ambiente / .env
├── database.py        NOVO               Engine, Session, classe Base
├── models.py          NOVO               a tabela prefix_cache
├── prefix_cache.py    NOVO (banco+rede)  get_range: o cache em si
├── manage.py          NOVO               python -m app.manage cache-stats | purge-cache
└── cli.py             agora aceita --cache
migrations/            NOVO               Alembic: env.py e versions/0001_create_prefix_cache.py
db/init-test-db.sql    NOVO               cria o banco de testes na 1ª subida do container
docker-compose.yml     NOVO               o PostgreSQL num container
.env.example           NOVO               modelo de configuração
tests/
├── conftest.py        NOVO               fixtures de banco (db_engine, db_session)
├── test_freshness.py  NOVO               regras de validade (puro)
├── test_prefix_cache.py NOVO             o cache, com PostgreSQL de verdade
├── test_migrations.py NOVO               migrações sobem, descem e batem com os modelos
└── test_manage.py     NOVO               comandos de manutenção
```

Quem conversa com quem:

```mermaid
flowchart LR
    CLI["cli.py --cache"] --> PC["prefix_cache.py<br/>get_range"]
    PC --> FR["freshness.py<br/>classify (puro)"]
    PC --> HC["hibp_client.py<br/>fetch_range"]
    PC --> M["models.py<br/>PrefixCache"]
    HC -- "HTTPS: só o prefixo" --> HIBP[("api.pwnedpasswords.com")]
    M -- "SQLAlchemy + psycopg" --> DB[("PostgreSQL 16<br/>no Docker")]
    CFG["config.py<br/>(.env)"] -.-> CLI
```

A regra continua: módulos **puros** (`kanonymity`, `policy`, `freshness`) não importam
rede nem banco. `prefix_cache.py` é a nova "casca": orquestra banco e rede, mas delega as
decisões (a cópia ainda serve?) ao núcleo puro.

---

## 3. Validade: TTL e stale-if-error

Toda cópia envelhece. O HIBP acrescenta senhas vazadas continuamente, então uma faixa
guardada há um mês pode não ter as senhas do último vazamento. A solução clássica é o
**TTL** (*time to live*, tempo de vida): depois dele, a cópia deixa de ser "fresca".

Mas e se, na hora de renovar, o HIBP estiver fora do ar? Temos duas opções ruins — responder
com erro, ou usar uma cópia velha — e escolhemos a menos ruim com um limite: uma janela de
**stale-if-error** ("velha, se der erro"), o mesmo nome da diretiva de cache do HTTP
(RFC 5861).

```
    idade da cópia:  0 ──────── ttl ──────────── ttl + stale_if_error ──────────>
                     │  FRESH   │      STALE          │        EXPIRED
                     │ usa sem  │ só se o HIBP        │ nunca usa
                     │ consultar│ estiver fora do ar  │
                     └── 24 h ──┴────── + 7 dias ─────┘   (valores padrão)
```

Por que é aceitável usar uma cópia velha? Porque a base do HIBP só **cresce**: uma cópia
antiga é um subconjunto da atual. Ela nunca diz que uma senha vazou quando não vazou; no
máximo deixa de conhecer um vazamento recente. E quando não há cópia utilizável, o erro
**sobe** — sem dados, não existe resposta honesta.

### O núcleo puro: `freshness.py`

```python
@dataclass(frozen=True, slots=True)
class CachePolicy:
    ttl: timedelta
    stale_if_error: timedelta


class Freshness(StrEnum):
    FRESH = "fresh"
    STALE = "stale"
    EXPIRED = "expired"


def classify(fetched_at: datetime, now: datetime, policy: CachePolicy) -> Freshness:
    age = now - fetched_at
    if age < policy.ttl:
        return Freshness.FRESH
    if age < policy.ttl + policy.stale_if_error:
        return Freshness.STALE
    return Freshness.EXPIRED
```

- **`datetime` e `timedelta`:** um `datetime` é um instante; um `timedelta` é uma duração.
  `datetime - datetime` dá `timedelta`; `datetime - timedelta` dá `datetime`. Em C você
  faria contas com `time_t` (segundos desde 1970) e `difftime`; aqui os tipos impedem somar
  dois instantes (não faz sentido) e as unidades ficam explícitas: `timedelta(hours=24)`.
- **O "agora" entra por parâmetro.** Ler o relógio é uma forma de E/S: o resultado muda a cada
  chamada. Com `now` injetado, os testes usam uma data fixa
  (`datetime(2026, 9, 29, 12, 0, tzinfo=UTC)`) e testam as bordas exatas: um segundo antes
  do TTL é `FRESH`; exatamente no TTL já é `STALE`.

### Fuso horário: *aware* × *naive*

Um `datetime` pode ter fuso (**aware**, "consciente") ou não (**naive**, "ingênuo"). Um
`datetime` sem fuso é ambíguo: `12:00` de onde? Brasília? UTC? O Python se recusa a
misturar os dois:

```python
>>> datetime(2026, 9, 29, 12, 0) - datetime(2026, 9, 29, 12, 0, tzinfo=UTC)
TypeError: can't subtract offset-naive and offset-aware datetimes
```

A regra do projeto: **tudo em UTC, sempre com fuso** — `datetime.now(UTC)` no código e
`timestamptz` no banco (seção 8). Converter para o horário local é trabalho da tela, nunca
do armazenamento. Há um teste para o erro acima.

---

## 4. Docker em 15 minutos

Precisamos de um PostgreSQL. Poderíamos instalá-lo no Windows, mas aí a versão, a
configuração e os dados ficam presos à sua máquina — e o servidor da fase 6 é Linux. O
**Docker** resolve isso empacotando o PostgreSQL (e, depois, a nossa aplicação) de um jeito
que roda igual em qualquer lugar.

### Os quatro conceitos

| Conceito | O que é | Analogia com C |
|---|---|---|
| **Imagem** | Um pacote imutável: sistema de arquivos mínimo + programa + dependências. Ex.: `postgres:16-alpine`. | O executável **estaticamente linkado**, com tudo dentro. |
| **Container** | Uma imagem **em execução**: um processo isolado, com seu próprio sistema de arquivos, rede e lista de processos. | O **processo** criado ao rodar o executável. Várias execuções = vários containers. |
| **Volume** | Uma pasta gerenciada pelo Docker que sobrevive ao container. | Um arquivo em disco que o processo abre: o processo morre, o arquivo fica. |
| **Porta publicada** | Um redirecionamento de uma porta da sua máquina para uma porta do container. | Um `bind()` na sua máquina encaminhando para o socket do processo. |

```
  SUA MÁQUINA (Windows + WSL 2)
  ┌─────────────────────────────────────────────────────────────────────┐
  │                                                                     │
  │  python -m app.cli --cache                                          │
  │        │                                                            │
  │        │ localhost:5432 (porta publicada só para 127.0.0.1)         │
  │        v                                                            │
  │  ┌──────────── container "pwncheck-db-1" ─────────────┐             │
  │  │  imagem: postgres:16-alpine                        │             │
  │  │  processo: postgres, escutando na 5432 do container│             │
  │  │  /var/lib/postgresql/data ─────────────────────────┼──> volume   │
  │  └────────────────────────────────────────────────────┘   "pgdata"  │
  │                                                          (os dados  │
  │                                                           ficam)    │
  └─────────────────────────────────────────────────────────────────────┘
```

**Container não é máquina virtual.** Uma VM emula um computador inteiro, com o próprio
kernel. Um container é um processo comum do Linux que o kernel **isola** com dois recursos:

- **namespaces:** o processo enxerga só a própria árvore de arquivos, a própria rede, os
  próprios PIDs (dentro do container, o PostgreSQL acha que é o processo 1);
- **cgroups:** limites de CPU e memória.

Por isso um container sobe em segundos e gasta pouca memória. E por isso também ele precisa
de um **kernel Linux** — que, no Windows, vem do WSL 2.

**Por que `alpine`?** A tag `16-alpine` usa o Alpine Linux, uma distribuição mínima. A
imagem fica menor e com menos programas instalados — menos coisas que podem ter
vulnerabilidades (*superfície de ataque* menor).

### Docker Compose

Subir um container "na mão" exige um comando comprido (`docker run -e ... -p ... -v ...`).
O **Docker Compose** descreve os containers num arquivo YAML (`docker-compose.yml`), e um
comando sobe tudo: `docker compose up -d`. Na fase 6, o mesmo arquivo terá também a nossa
aplicação e o servidor web.

---

## 5. Instalando o WSL 2 e o Docker Desktop

Esta é a pendência de ambiente registrada na trilha. O passo a passo é o mesmo do
[guia do DocSage](https://github.com/Everett-gi/docsage/blob/main/docs/PASSO-A-PASSO.md#antes-do-docker-o-wsl-2):

1. **Confira se o WSL já existe:** no PowerShell, `wsl --status`.
2. **Instale o WSL 2**, se precisar: PowerShell **como administrador** → `wsl --install` →
   **reinicie o computador**. Na volta, o Ubuntu pede um usuário e uma senha para o Linux.
3. **Instale o Docker Desktop** (https://www.docker.com/products/docker-desktop/). Na
   instalação, deixe marcado *Use WSL 2 instead of Hyper-V*.
4. **Abra o Docker Desktop** e espere o ícone ficar verde (*Engine running*).
5. Confira:

   ```powershell
   docker --version
   docker compose version
   docker run --rm hello-world     # baixa uma imagem minúscula e roda: "Hello from Docker!"
   ```

O que é o **WSL 2** (*Windows Subsystem for Linux*)? Um Linux de verdade, com kernel
próprio, rodando numa máquina virtual leve gerenciada pelo Windows. O Docker Desktop põe o
motor do Docker lá dentro, e o comando `docker` do PowerShell conversa com ele.

```
  Windows 11
  ├── PowerShell ── comando "docker" ──┐
  └── WSL 2 (VM leve, kernel Linux)    │
      └── Docker Engine  <─────────────┘
          └── containers (processos Linux isolados)
```

> Se aparecer erro de *daemon* (`error during connect`), quase sempre é o Docker Desktop
> fechado. Abra-o e espere ficar verde.

---

## 6. `docker-compose.yml` linha a linha

```yaml
services:
  db:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    ports:
      - "127.0.0.1:${POSTGRES_PORT:-5432}:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./db/init-test-db.sql:/docker-entrypoint-initdb.d/init-test-db.sql:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: 5s
      timeout: 5s
      retries: 10

volumes:
  pgdata:
```

- **`services:`** a lista de containers. Temos um, chamado `db`. O Compose dá ao container o
  nome `pwncheck-db-1` (pasta do projeto + serviço + número).
- **`image:`** qual imagem usar. Na primeira vez, o Docker a baixa do *Docker Hub* (o
  "repositório de imagens" público).
- **`restart: unless-stopped`:** se o container cair (ou o Docker reiniciar), ele volta
  sozinho — a menos que você o tenha parado.
- **`environment:`** variáveis de ambiente dentro do container. A imagem oficial do
  PostgreSQL lê `POSTGRES_DB`, `POSTGRES_USER` e `POSTGRES_PASSWORD` **na primeira
  subida** para criar o banco e o usuário.
- **`${POSTGRES_PASSWORD}`:** interpolação. O Compose lê o arquivo `.env` da mesma pasta e
  substitui. `${POSTGRES_PORT:-5432}` significa "o valor de `POSTGRES_PORT`, ou `5432` se ele
  não existir" — a mesma sintaxe do shell do Linux.
- **`ports: "127.0.0.1:5432:5432"`:** `IP_do_host:porta_do_host:porta_do_container`. O
  `127.0.0.1` é importante: sem ele, a porta seria publicada em **todas** as interfaces de
  rede, e qualquer computador da sua rede Wi-Fi poderia tentar conectar no seu banco.
- **`volumes:`**
  - `pgdata:/var/lib/postgresql/data` — um **volume nomeado** na pasta onde o PostgreSQL
    guarda os dados. Sem ele, os dados morreriam com o container.
  - `./db/init-test-db.sql:/docker-entrypoint-initdb.d/...:ro` — um **bind mount**: um
    arquivo do repositório aparece dentro do container (`:ro` = só leitura). A imagem do
    PostgreSQL executa os `.sql` dessa pasta **só quando cria o banco pela primeira vez**.
    O nosso cria o banco `pwncheck_test`, que os testes usam.
- **`healthcheck:`** um comando que o Docker roda periodicamente para saber se o serviço está
  **saudável** (aqui, `pg_isready`: "o banco aceita conexões?"). "Container rodando" só quer
  dizer que o processo existe; "saudável" quer dizer que ele está pronto para trabalhar. O
  `docker compose ps` mostra `(healthy)`.

> **Pegadinha do init script:** como ele só roda na criação do volume, se você já tinha
> subido o banco antes deste arquivo existir, o `pwncheck_test` não será criado. A solução é
> recriar o volume: `docker compose down -v` (apaga os dados!) e `docker compose up -d`.

---

## 7. Configuração: `.env`, `pydantic-settings` e `SecretStr`

A URL do banco contém a senha: `postgresql+psycopg://pwncheck:SENHA@localhost:5432/pwncheck`.
Ela não pode estar no código nem no Git. O padrão (os "12 fatores" de aplicações modernas) é
ler configuração de **variáveis de ambiente**; no desenvolvimento, um arquivo `.env` (fora do
Git) faz o papel delas.

```
  .env.example  (no Git, valores fictícios)  ──copiar──>  .env  (fora do Git, valores reais)
                                                            │
                     docker compose lê ${POSTGRES_...} <────┤
                     pydantic-settings lê DATABASE_URL <────┘
```

`app/config.py` usa o **pydantic-settings**: você declara uma classe com campos tipados, e ele
preenche cada campo com a variável de ambiente de mesmo nome, **validando o tipo**:

```python
class DatabaseSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: SecretStr


class CacheSettings(DatabaseSettings):
    hibp_timeout_seconds: float = Field(default=10.0, gt=0)
    cache_ttl_hours: int = Field(default=24, ge=1)
    cache_stale_if_error_hours: int = Field(default=168, ge=0)
```

- `database_url` sem valor padrão = **obrigatório**. Se faltar, `CacheSettings()` levanta
  `ValidationError` na hora — melhor que descobrir no meio de uma requisição.
- `Field(default=24, ge=1)`: padrão 24 e validação "maior ou igual a 1" (`gt` = maior que).
  `CACHE_TTL_HOURS=abc` no `.env` vira erro claro, não um bug silencioso. É o que em C você
  faria com `strtol` + verificação de erro + faixa, de graça.
- **Ordem de prioridade:** variável de ambiente > `.env` > valor padrão. No servidor (fase
  6), as variáveis vêm do Docker; no seu PC, do `.env`.

### Herança: uma escada de configurações

```
  DatabaseSettings        database_url                      <- usado pelo Alembic
    └── CacheSettings     + hibp_timeout, ttl, stale        <- CLI e manage
          └── Settings    + segredos da API (fase 4)        <- a API web
```

Cada ferramenta pede **só o degrau de que precisa**. O Alembic não deveria exigir o segredo
dos tokens da API (fase 4) só para criar uma tabela. `class CacheSettings(DatabaseSettings)`
é herança simples, como `class CacheSettings : public DatabaseSettings` em C++: herda os
campos e acrescenta outros.

### `SecretStr`: segredo que não se deixa imprimir

```python
>>> settings.database_url
SecretStr('**********')
>>> str(settings.database_url)
'**********'
>>> settings.database_url.get_secret_value()      # uso explícito, só onde precisa
'postgresql+psycopg://pwncheck:...@localhost:5432/pwncheck'
```

Um `print(settings)` esquecido, um log de depuração ou um *traceback* não vazam a senha. O
próprio SQLAlchemy faz o mesmo: `print(engine)` mostra
`Engine(postgresql+psycopg://pwncheck:***@localhost:5432/pwncheck)`.

---

## 8. PostgreSQL e o SQL essencial

O **PostgreSQL** é um banco de dados **relacional**: os dados ficam em **tabelas** (linhas ×
colunas, como um array de structs), e você conversa com ele em **SQL**. Esta é a nossa tabela,
como o PostgreSQL a descreve (`\d prefix_cache` no `psql`):

```
                      Table "public.prefix_cache"
   Column   |           Type           | Nullable
------------+--------------------------+----------
 prefix     | character varying(5)     | not null
 suffixes   | jsonb                    | not null
 fetched_at | timestamp with time zone | not null
Indexes:
    "pk_prefix_cache" PRIMARY KEY, btree (prefix)
Check constraints:
    "ck_prefix_cache_prefix_hex" CHECK (prefix::text ~ '^[0-9A-F]{5}$'::text)
```

Em C, seria parecido com:

```c
struct prefix_cache {
    char   prefix[6];        /* VARCHAR(5): até 5 caracteres (+ '\0' no C)              */
    json  *suffixes;         /* JSONB: {"1E4C9B...": 42, ...}                            */
    time_t fetched_at;       /* TIMESTAMPTZ: um instante, guardado em UTC                */
};
/* ...num array ordenado por prefix (o índice da PRIMARY KEY), com busca binária.       */
```

- **`PRIMARY KEY` (chave primária):** identifica cada linha; não pode repetir nem ser nula. O
  PostgreSQL cria automaticamente um **índice** B-tree para ela — uma árvore ordenada que
  acha um prefixo em O(log n), em vez de ler a tabela inteira.
- **`VARCHAR(5)`:** texto de até 5 caracteres. Tentar gravar 6 dá erro.
- **`JSONB`:** JSON guardado num formato **binário** que o PostgreSQL entende: dá para
  consultar chaves (`suffixes ->> 'ABC...'`) e indexar. Guardamos a faixa inteira como um
  objeto `{sufixo: contagem}`.
- **`TIMESTAMPTZ`** (*timestamp with time zone*): o instante é convertido para UTC ao gravar.
  Não há ambiguidade de fuso, o equivalente do `datetime` *aware* da seção 3.
- **`CHECK`:** uma regra que o **banco** garante em toda escrita. `~` é o operador de regex do
  PostgreSQL. Mesmo que um bug no Python tente gravar `"5baa6"` (minúsculo), o banco recusa.
  É defesa em profundidade: a validação mais perto dos dados é a última linha de defesa.

### O SQL que a aplicação envia

Estes são os comandos reais, capturados nos testes (seção 16). A busca por chave primária:

```sql
SELECT prefix_cache.prefix, prefix_cache.suffixes, prefix_cache.fetched_at
FROM prefix_cache
WHERE prefix_cache.prefix = %(pk_1)s::VARCHAR
```

O `%(pk_1)s` é um **parâmetro**: o valor (`'5BAA6'`) viaja **separado** do texto do comando.
O banco nunca interpreta o valor como SQL. É a defesa contra **SQL injection** — o ataque em
que alguém digita `'; DROP TABLE prefix_cache; --` num campo e o programa, que montou o SQL
concatenando strings, executa isso. Com parâmetros, esse texto seria só um prefixo inválido.
(Em C, é a diferença entre montar a consulta com `sprintf` e usar `PQexecParams` da libpq.)

E a gravação, o **upsert** da seção 10:

```sql
INSERT INTO prefix_cache (prefix, suffixes, fetched_at)
VALUES (%(prefix)s::VARCHAR, %(suffixes)s::JSONB, %(fetched_at)s::TIMESTAMP WITH TIME ZONE)
ON CONFLICT (prefix) DO UPDATE SET suffixes = excluded.suffixes, fetched_at = excluded.fetched_at
```

### Explorando com o `psql`

O `psql` é o terminal do PostgreSQL. Ele já vem dentro do container:

```powershell
docker compose exec db psql -U pwncheck -d pwncheck
```

```
pwncheck=# \dt                        -- lista as tabelas
pwncheck=# \d prefix_cache            -- descreve uma tabela
pwncheck=# SELECT prefix, fetched_at,
pwncheck-#        (SELECT count(*) FROM jsonb_object_keys(suffixes)) AS sufixos
pwncheck-#   FROM prefix_cache;
 prefix |         fetched_at          | sufixos
--------+-----------------------------+---------
 21BD1  | 2026-09-29 00:55:47.3714+00 |    1925
pwncheck=# \q                         -- sai
```

`docker compose exec db <comando>` executa um comando **dentro** do container `db` em
execução — como abrir um terminal na "máquina" do banco.

---

## 9. SQLAlchemy: o ORM

Poderíamos mandar SQL em texto para o driver (`psycopg`) direto. O **SQLAlchemy** é uma camada
acima, com duas partes:

- **Core:** monta SQL com objetos Python (`select(...)`, `insert(...)`) — sempre com
  parâmetros, sempre no dialeto certo do banco.
- **ORM** (*Object-Relational Mapper*): mapeia **classes** para **tabelas** e **objetos**
  para **linhas**. Você lê e escreve objetos; ele gera o SQL.

```
      PYTHON                                        POSTGRESQL
  class PrefixCache(Base):        <── mapeia ──>    TABLE prefix_cache
      prefix: Mapped[str]         <──────────>        prefix VARCHAR(5)
      suffixes: Mapped[dict]      <──────────>        suffixes JSONB
      fetched_at: Mapped[datetime]<──────────>        fetched_at TIMESTAMPTZ

  objeto PrefixCache("21BD1",...) <──────────>      uma linha da tabela
```

### As peças de `database.py`

```mermaid
flowchart TD
    E["Engine<br/>(um por aplicação)<br/>URL + pool de conexões"] --> P["Pool<br/>conexões TCP já abertas<br/>e autenticadas"]
    SM["sessionmaker<br/>(fábrica, configurada uma vez)"] --> S1["Session<br/>(uma por tarefa/requisição)"]
    SM --> S2["Session"]
    S1 -- "pega uma conexão emprestada" --> P
    S2 -- "pega uma conexão emprestada" --> P
    P --> DB[("PostgreSQL")]
```

- **Engine:** criado uma vez. Guarda a URL e um **pool** de conexões. Abrir uma conexão
  com o banco custa caro (TCP, TLS, autenticação); o pool mantém algumas abertas e as
  empresta — o mesmo princípio de um *pool* de threads ou de buffers pré-alocados em C.
  `pool_pre_ping=True` testa a conexão antes de emprestá-la (o banco pode ter derrubado uma
  conexão ociosa).
- **Session:** a unidade de trabalho. Pega uma conexão do pool, abre uma **transação**,
  acumula as operações e, no `commit()`, confirma tudo de uma vez.
- **`expire_on_commit=False`:** por padrão, depois do commit a sessão "esquece" os valores dos
  objetos e os relê do banco no próximo acesso. Desligamos isso: depois do commit, os valores
  continuam lá (útil para devolver o objeto numa resposta da API, na fase 4).

### O mapeamento declarativo: `models.py`

```python
class PrefixCache(Base):
    __tablename__ = "prefix_cache"
    __table_args__ = (CheckConstraint("prefix ~ '^[0-9A-F]{5}$'", name="prefix_hex"),)

    prefix: Mapped[str] = mapped_column(String(5), primary_key=True)
    suffixes: Mapped[dict[str, int]] = mapped_column(JSONB)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
```

- `Mapped[str]` diz o tipo **Python**; `mapped_column(String(5))`, o tipo **SQL**. Sem
  `| None` no tipo, a coluna é `NOT NULL`.
- `__tablename__` e `__table_args__` são atributos "mágicos" que o SQLAlchemy lê da classe.
- `Base` vem de `database.py`: `class Base(DeclarativeBase)`. Toda classe que herda dela é
  registrada no `Base.metadata`, o **catálogo do esquema** — o Alembic compara esse catálogo
  com o banco (seção 12).
- **`NAMING_CONVENTION`:** sem ela, o PostgreSQL inventaria nomes para as restrições
  (`prefix_cache_prefix_check`...). Com ela, os nomes são previsíveis
  (`ck_prefix_cache_prefix_hex`, `pk_prefix_cache`), e uma migração futura consegue apagá-las
  pelo nome.
- **`__repr__` personalizado:** o padrão imprimiria as ~2 mil entradas de `suffixes`. Um repr
  enorme inunda logs e o depurador.

### O mapa de identidade (e um bug que ele causaria)

A `Session` mantém um **mapa de identidade** (*identity map*): um dicionário
`{(classe, chave primária): objeto}`. Carregar a mesma linha duas vezes devolve **o mesmo
objeto**, sem consultar o banco de novo:

```python
>>> a = session.get(PrefixCache, "AAAAA")
>>> b = session.get(PrefixCache, "AAAAA")
>>> a is b
True
```

Isso garante que, dentro de uma sessão, só existe um objeto por linha (sem duas cópias
divergentes). Mas cria uma armadilha quando alteramos o banco **sem passar pelo ORM**, como
no nosso upsert (que é Core). Fizemos o experimento:

```python
save_entry(session, "AAAAA", {"X": 1}, ...)        # grava {"X": 1}
a = session.get(PrefixCache, "AAAAA")              # carrega: objeto entra no mapa
save_entry(session, "AAAAA", {"X": 2}, ...)        # upsert direto no banco: {"X": 2}

session.get(PrefixCache, "AAAAA").suffixes                            # {'X': 1}  <- VELHO!
session.get(PrefixCache, "AAAAA", populate_existing=True).suffixes    # {'X': 2}
```

```
   Session                                   Banco
   ┌───────────────────────────────┐         ┌─────────────────────┐
   │ mapa de identidade            │         │ AAAAA  {"X": 2}     │  <- o upsert mudou aqui
   │ ("PrefixCache","AAAAA") ──> ● │         └─────────────────────┘
   └───────────────────────────────┘
                                 │
                                 v
                          objeto em memória: {"X": 1}   <- e ninguém avisou o objeto
```

Por isso `load_entry` usa `populate_existing=True`: "leia do banco e **sobrescreva** o objeto
que já está no mapa". É o mesmo problema de **coerência de cache** que você conhece de
hardware: duas cópias do mesmo dado, uma desatualizada.

**Um detalhe que descobrimos testando: referências fracas.** A primeira tentativa de escrever
um teste para esse bug **passou mesmo sem** o `populate_existing`. Por quê? O mapa de
identidade guarda **referências fracas** (*weak references*): ele aponta para o objeto, mas
não o mantém vivo. Quando ninguém mais segura o objeto (a variável local `entry` de
`get_range` sai de escopo ao retornar), o coletor de lixo o libera, ele some do mapa, e a
próxima leitura vai mesmo ao banco. É o `std::weak_ptr` do C++: um ponteiro que não é dono e
que vira nulo quando o dono solta o objeto.

```
  variável "a" ──(forte)──> objeto PrefixCache <──(fraca)── mapa de identidade
                               ^
  "a" sai de escopo: nenhuma referência forte ──> objeto liberado ──> sai do mapa
```

O bug só aparece quando **alguém segura o objeto** (no experimento acima, a variável `a`).
O teste de regressão `test_upsert_nao_deixa_objeto_desatualizado_na_sessao` faz exatamente
isso — guarda o objeto numa variável `held` — e falha sem o `populate_existing`. Lição: um
teste de bug precisa **reproduzir as condições** do bug, senão passa por acaso.

---

## 10. Transações e o upsert atômico

Uma **transação** agrupa operações num bloco de "tudo ou nada". As garantias têm um nome,
**ACID**:

| Letra | Garantia | Na prática |
|---|---|---|
| **A**tomicidade | tudo ou nada | se o programa cair no meio, nada do bloco fica gravado |
| **C**onsistência | as regras valem sempre | `PRIMARY KEY`, `CHECK`, `NOT NULL` nunca são violadas |
| **I**solamento | transações simultâneas não se atrapalham | cada uma vê um estado coerente |
| **D**urabilidade | confirmado é para sempre | depois do `COMMIT`, sobrevive a queda de energia |

### "Quem abriu a sessão faz o commit"

As funções de `prefix_cache.py` **não** chamam `commit()`. Quem cria a sessão (a CLI, o
`manage.py` e, na fase 4, a API) decide quando confirmar. Assim, várias operações podem
compor uma transação só, e os testes conseguem desfazer tudo no fim (seção 16).

```python
with Session(engine) as session, httpx.Client(...) as client:   # abre
    result = check_password_cached(session, client, password, policy=...)
    session.commit()                                             # confirma
# ao sair do "with", a sessão é fechada e a conexão volta ao pool (RAII)
```

### A corrida que o upsert evita

Imagine duas requisições para o mesmo prefixo ao mesmo tempo, com o cache vazio. A ingênua
"procura; se não achar, insere" tem uma **condição de corrida** (*race condition*) — o mesmo
problema de dois threads fazendo `if (!existe) cria();` sem mutex:

```mermaid
sequenceDiagram
    participant A as Requisição A
    participant B as Requisição B
    participant DB as PostgreSQL
    A->>DB: SELECT ... WHERE prefix='5BAA6'
    DB-->>A: nada
    B->>DB: SELECT ... WHERE prefix='5BAA6'
    DB-->>B: nada
    A->>DB: INSERT '5BAA6'
    DB-->>A: ok
    B->>DB: INSERT '5BAA6'
    DB-->>B: ERRO: chave duplicada
```

O erro real, reproduzido no nosso banco:

```
duplicate key value violates unique constraint "pk_prefix_cache"
DETAIL:  Key (prefix)=(BBBBB) already exists.
```

O **upsert** (*update* + *insert*) resolve isso **dentro do banco**, numa operação atômica:

```sql
INSERT INTO prefix_cache (...) VALUES (...)
ON CONFLICT (prefix) DO UPDATE SET suffixes = excluded.suffixes, fetched_at = excluded.fetched_at
```

"Tente inserir; se a chave já existir, atualize a linha existente com os valores que eu
tentei inserir". `excluded` é o nome que o PostgreSQL dá à linha que **tentamos** inserir.
Com isso, a requisição B simplesmente atualiza a linha que A criou. No SQLAlchemy:

```python
statement = insert(PrefixCache).values(prefix=prefix, suffixes=suffixes, fetched_at=fetched_at)
statement = statement.on_conflict_do_update(
    index_elements=[PrefixCache.prefix],
    set_={"suffixes": statement.excluded.suffixes, "fetched_at": statement.excluded.fetched_at},
)
session.execute(statement)
```

Repare no `insert` importado de `sqlalchemy.dialects.postgresql`, não de `sqlalchemy`: o
`ON CONFLICT` é específico do PostgreSQL, e o SQLAlchemy deixa isso explícito no import.

---

## 11. O serviço de cache: `prefix_cache.py`

```mermaid
flowchart TD
    A["get_range(prefixo)"] --> B["load_entry: SELECT pela chave primária"]
    B --> C{"há cópia?<br/>classify()"}
    C -- "FRESH" --> HIT["devolve a cópia<br/>source = HIT"]
    C -- "STALE, EXPIRED<br/>ou sem cópia" --> D["fetch_range: consulta o HIBP"]
    D -- "ok" --> E["save_entry: upsert"] --> MISS["devolve a resposta nova<br/>source = MISS"]
    D -- "httpx.HTTPError" --> F{"a cópia é STALE?"}
    F -- "sim" --> STALE["log de aviso (só o prefixo)<br/>devolve a cópia: source = STALE"]
    F -- "não" --> ERR["raise: o erro sobe"]
```

```python
def get_range(session, client, prefix, *, policy, now=None) -> RangeResult:
    now = now or datetime.now(UTC)
    entry = load_entry(session, prefix)
    freshness = classify(entry.fetched_at, now, policy) if entry else Freshness.EXPIRED

    if entry is not None and freshness is Freshness.FRESH:
        return RangeResult(entry.suffixes, CacheSource.HIT, entry.fetched_at)

    try:
        suffixes = fetch_range(client, prefix)
    except httpx.HTTPError:
        if entry is not None and freshness is Freshness.STALE:
            logger.warning("HIBP indisponível; usando a cópia antiga do prefixo %s", prefix)
            return RangeResult(entry.suffixes, CacheSource.STALE, entry.fetched_at)
        raise

    save_entry(session, prefix, suffixes, now)
    return RangeResult(suffixes, CacheSource.MISS, now)
```

- **`now = now or datetime.now(UTC)`:** `or` devolve o primeiro valor verdadeiro. Se ninguém
  passou `now` (`None`, falso), usa o relógio.
- **`X if cond else Y`** é o operador ternário do Python (o `cond ? X : Y` do C).
- **`is` com membros de enum** (`freshness is Freshness.FRESH`): como cada membro é único,
  comparar identidade é correto e deixa claro que é um enum.
- **`raise` sozinho**, dentro de um `except`, relança a exceção que está sendo tratada, com o
  *traceback* original — como um `throw;` sem argumento em C++.
- **Reuso da fase 1:** `fetch_range` é a mesma função de `hibp_client.py`, com o mesmo cliente
  injetado. O cache é uma camada **em volta**, sem mudar o cliente.

`check_password_cached` é o equivalente cacheado do `check_password` da fase 1:

```python
def check_password_cached(session, client, password, *, policy, now=None):
    prefix, suffix = split_hash(sha1_hex(password))
    result = get_range(session, client, prefix, policy=policy, now=now)
    return result.suffixes.get(suffix, 0), result.source
```

---

## 12. Alembic: migrações do esquema

O esquema do banco (tabelas, colunas, restrições) muda ao longo do projeto: a fase 4 vai
criar a tabela de usuários; a fase 5, a de métricas. Como aplicar essas mudanças no seu banco,
no banco do CI e no do servidor, **na ordem certa** e sem perder dados?

Uma **migração** é um script que leva o esquema de uma versão à seguinte — e sabe desfazer.
Pense nelas como **patches** numerados aplicados em sequência, como os commits do Git, mas
para o banco:

```
   base (vazio) ──0001──> prefix_cache ──0002──> + users (fase 4) ──0003──> + métricas (fase 5)
                <─────── downgrade ──────────────────────────────────────── upgrade ────────>
```

O **Alembic** (do mesmo autor do SQLAlchemy) gerencia isso. Ele grava no próprio banco, numa
tabela `alembic_version`, qual foi a última migração aplicada:

```
pwncheck=# SELECT * FROM alembic_version;
 version_num
-------------
 0001
```

`alembic upgrade head` lê esse número e aplica **só as que faltam**, na ordem. O mesmo comando
funciona num banco vazio (aplica todas) e num banco atualizado (não faz nada).

### O arquivo de migração

```python
revision: str = "0001"
down_revision: str | Sequence[str] | None = None   # a anterior (None = é a primeira)


def upgrade() -> None:
    op.create_table(
        "prefix_cache",
        sa.Column("prefix", sa.String(length=5), nullable=False),
        sa.Column("suffixes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("prefix ~ '^[0-9A-F]{5}$'", name=op.f("ck_prefix_cache_prefix_hex")),
        sa.PrimaryKeyConstraint("prefix", name=op.f("pk_prefix_cache")),
    )


def downgrade() -> None:
    op.drop_table("prefix_cache")
```

`down_revision` forma uma **lista encadeada**: cada migração aponta para a anterior, como o
ponteiro `prev` de uma lista em C. O Alembic percorre a corrente para saber a ordem.

### `--autogenerate`: o Alembic escreve o rascunho

```powershell
alembic revision --autogenerate -m "create prefix_cache" --rev-id 0001
```

```mermaid
flowchart LR
    M["app/models.py<br/>(Base.metadata)<br/>o esquema DESEJADO"] --> C{"Alembic compara"}
    D[("banco real<br/>o esquema ATUAL")] --> C
    C --> F["versions/0001_create_prefix_cache.py<br/>a diferença, em Python"]
    F --> R["VOCÊ revisa e ajusta"]
```

O `--autogenerate` compara os modelos com o banco e escreve a diferença. **É um rascunho**:
ele não detecta tudo (renomear uma coluna parece "apagar uma e criar outra", o que perderia os
dados!). Sempre leia a migração gerada antes de aplicá-la.

### Configuração: `pyproject.toml` e `migrations/env.py`

A configuração do Alembic mora no `pyproject.toml`, junto com a do ruff e do pytest:

```toml
[tool.alembic]
script_location = "%(here)s/migrations"
file_template = "%%(rev)s_%%(slug)s"
prepend_sys_path = ["."]

[[tool.alembic.post_write_hooks]]
name = "ruff_format"
type = "module"
module = "ruff"
options = "format REVISION_SCRIPT_FILENAME"
```

Os *post write hooks* rodam o ruff em cada migração gerada, para ela já nascer formatada (o CI
exige). `[[...]]` em TOML é uma **lista de tabelas**: cada bloco é um item da lista.

A URL do banco **não** está lá — ela tem senha. O `migrations/env.py` (o script que o Alembic
executa a cada comando) a busca no `DatabaseSettings`:

```python
target_metadata = Base.metadata   # o esquema desejado, para o --autogenerate


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:        # conexão emprestada (os testes usam isso)
        run_migrations(connection)
        return

    url = DatabaseSettings().database_url.get_secret_value()
    engine = create_engine(url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        run_migrations(connection)
```

`import app.models  # noqa: F401` no topo parece inútil (o nome não é usado), mas o
**efeito colateral** do import é o que importa: definir as classes registra as tabelas no
`Base.metadata`. O `# noqa: F401` avisa o ruff de que o "import não usado" é intencional.

### Comandos do dia a dia

| Comando | O que faz |
|---|---|
| `alembic upgrade head` | aplica todas as migrações que faltam |
| `alembic downgrade -1` | desfaz a última |
| `alembic current` | mostra a versão atual do banco |
| `alembic history` | lista as migrações |
| `alembic revision --autogenerate -m "..."` | gera uma migração a partir dos modelos |
| `alembic check` | falha se os modelos tiverem mudanças sem migração |

### DDL transacional

No PostgreSQL, até `CREATE TABLE` e `DROP TABLE` (os comandos de **DDL**, *Data Definition
Language*) respeitam transações. Se a migração 0003 falhar no meio, o banco volta ao estado
da 0002 — nada de "meia tabela criada". O MySQL, por exemplo, não oferece isso. O Alembic
avisa no log: `Will assume transactional DDL.`

---

## 13. Privacidade: o banco também não sabe

Na fase 1, garantimos que só o prefixo sai para o HIBP. Com o cache, surge um novo
observador: o **nosso** banco de dados (e quem tiver acesso a ele ou aos logs dele). Ele pode
descobrir qual senha foi consultada?

O que chega ao banco:

- na consulta, o **prefixo** (`WHERE prefix = '5BAA6'`);
- na gravação, a **faixa inteira** que o HIBP devolveu para esse prefixo.

A faixa é igual para qualquer senha com aquele prefixo: são dados públicos do HIBP, os mesmos
~2 mil sufixos. Logo, o banco vê exatamente o mesmo que o HIBP viu — e nada mais.

**A otimização proibida.** Seria mais "eficiente" pedir ao banco só a contagem do nosso
sufixo, em vez de trazer ~70 KB:

```sql
SELECT suffixes ->> '1E4C9B93F3F0682250B6CF8331B7EE68FD8' FROM prefix_cache WHERE prefix = '5BAA6'
```

Mas esse comando leva o **hash completo** da senha (prefixo + sufixo) ao servidor de banco.
Um log de consultas lentas, uma ferramenta de monitoramento, um erro que registra os
parâmetros — e o hash de uma senha fraca pode ser quebrado em segundos. Por isso a
comparação do sufixo acontece **em Python**, na memória da aplicação.

### O teste que prova

A fase 1 tinha `test_somente_o_prefixo_sai_da_maquina`. A fase 3 tem o equivalente para o
banco, e ele é ainda mais forte. Achamos por força bruta (0,3 s) uma senha com o mesmo prefixo
de `password`, e conferimos com uma ferramenta independente:

```
printf 'password'           | sha1sum  ->  5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
printf 'outra-senha-315727' | sha1sum  ->  5baa6e406facb04632ffcc0efea7577d7836bdb7
```

O teste "grampeia" a conexão (seção 16), consulta as duas senhas com o cache vazio e compara
**todos** os comandos SQL enviados, com **todos** os parâmetros:

```python
def test_o_banco_nao_consegue_distinguir_senhas_com_o_mesmo_prefixo(db_session):
    ...
    assert recordings[0] == recordings[1]
```

Se as duas senhas geram exatamente o mesmo tráfego para o banco, então **nada** do que o banco
vê depende da senha além do prefixo. É a definição de k-anonymity, verificada por um teste.

---

## 14. `logging`

`print` escreve na tela; **`logging`** registra eventos com **nível**, **origem** e destino
configurável (terminal, arquivo, serviço de logs):

```python
logger = logging.getLogger(__name__)          # __name__ == "app.prefix_cache"

logger.warning("HIBP indisponível; usando a cópia antiga do prefixo %s", prefix)
```

- **Um logger por módulo**, nomeado por `__name__`. Os nomes formam uma hierarquia
  (`app` → `app.prefix_cache`): dá para ligar os logs de um módulo só.
- **Níveis**, do menos ao mais grave: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. Uma
  cópia velha em uso é `WARNING`: nada quebrou, mas alguém deveria saber.
- **`%s` com o valor separado**, e não f-string: a mensagem só é montada se o nível estiver
  ativo (economia), e ferramentas de log conseguem agrupar mensagens iguais com valores
  diferentes. É o `printf` com os argumentos passados à parte.
- **O que NUNCA vai para o log:** senha, hash completo, sufixo. Só o prefixo, que é
  k-anônimo. Um teste verifica isso com a fixture `caplog` (seção 16).

---

## 15. A CLI e os comandos de manutenção (`argparse`)

O **`argparse`** (biblioteca padrão) transforma `sys.argv` em opções validadas e gera a ajuda
sozinho — o `getopt` do C, com muito menos código:

```python
parser = argparse.ArgumentParser(prog="python -m app.cli", description="...")
parser.add_argument("--cache", action="store_true", help="consulta através do cache ...")
args = parser.parse_args(argv)     # args.cache é True ou False
```

```
> python -m app.cli --help
usage: python -m app.cli [-h] [--cache]

Verifica se uma senha vazou (k-anonymity) e avalia a política de senha.

options:
  -h, --help  show this help message and exit
  --cache     consulta através do cache no PostgreSQL (exige DATABASE_URL e o banco no ar)
```

`main(argv: list[str] | None = None)` recebe os argumentos por parâmetro (`None` = usar os da
linha de comando): assim um teste pode chamar `main(["--cache"])` sem mexer em `sys.argv`.

Rodando duas vezes com a mesma senha:

```
> python -m app.cli --cache
ALERTA: esta senha apareceu 6.421.042 vezes em vazamentos. Não use!
Fonte: API do HIBP (a resposta foi gravada no cache)

> python -m app.cli --cache
ALERTA: esta senha apareceu 6.421.042 vezes em vazamentos. Não use!
Fonte: cache (cópia fresca no PostgreSQL; a API nem foi consultada)
```

A CLI trata três famílias de erro, cada uma com um **código de saída** diferente (1 =
configuração, 2 = API, 3 = banco) e uma mensagem útil, sem *traceback*:

```
Configuração incompleta: defina DATABASE_URL (copie o .env.example para .env).
Falha ao acessar o banco (ele está no ar? docker compose ps): (psycopg.OperationalError) connection failed: ... Connection refused
```

### `manage.py`: subcomandos

```
> python -m app.manage cache-stats
1 faixa(s) no cache:
  fresh    1
  stale    0
  expired  0

> python -m app.manage purge-cache
0 faixa(s) expirada(s) apagada(s).
```

Os comandos ficam num **dicionário de funções** — em C, uma tabela de ponteiros para função
indexada pelo nome do comando:

```python
Command = Callable[[Session, CachePolicy, datetime], str]   # o "typedef" do ponteiro

COMMANDS: dict[str, tuple[Command, str]] = {
    "cache-stats": (cmd_cache_stats, "mostra quantas faixas há no cache, por estado"),
    "purge-cache": (cmd_purge_cache, "apaga as faixas expiradas do cache"),
}
...
command, _ = COMMANDS[args.command]
output = command(session, settings.cache_policy(), datetime.now(UTC))
```

`Callable[[A, B, C], R]` é o tipo "função que recebe A, B, C e devolve R" — o
`typedef R (*Command)(A, B, C);` do C. Cada comando recebe a sessão e **devolve** o texto, sem
imprimir: o `main` faz a E/S, e os testes chamam os comandos com a sessão transacional.

`cache_stats` usa um **`Counter`** (de `collections`): um dicionário que conta ocorrências e
devolve 0 para chaves ausentes — `Counter(["a", "b", "a"])` → `{"a": 2, "b": 1}`.

---

## 16. Testes com banco de verdade

Por que não simular o banco com um mock? Porque o que queremos testar é justamente o que o
**banco** faz: o `ON CONFLICT`, o JSONB, o `CHECK`, as datas com fuso. Um mock só confirmaria
que chamamos as funções que achávamos que deveríamos chamar.

### Fixtures: preparação reutilizável

Uma **fixture** é uma função que prepara algo para os testes. O teste a pede pelo **nome do
parâmetro**, e o pytest a executa antes e injeta o resultado — injeção de dependência de
novo, agora feita pelo pytest. Elas ficam em `tests/conftest.py`, que o pytest carrega
sozinho.

```python
@pytest.fixture(scope="session")
def db_engine() -> Iterator[Engine]:
    url = _TestSettings().test_database_url
    if not url:
        if os.environ.get("PWNCHECK_REQUIRE_DB") == "1":
            pytest.fail("PWNCHECK_REQUIRE_DB=1, mas TEST_DATABASE_URL não foi definida.")
        pytest.skip("Defina TEST_DATABASE_URL para rodar os testes que usam o banco.")

    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text("DROP SCHEMA public CASCADE"))
        connection.execute(text("CREATE SCHEMA public"))
        command.upgrade(alembic_config(connection), "head")
    yield engine
    engine.dispose()
```

- **`yield` numa fixture:** o que vem antes é a **preparação**; o que vem depois, a
  **limpeza**, executada quando a fixture não é mais necessária — mesmo se o teste falhar.
  Construtor e destrutor, de novo.
- **`scope="session"`:** roda **uma vez** por execução do pytest, compartilhada por todos os
  testes. Recriar o esquema a cada teste seria lento.
- **Recriamos o esquema com as migrações**, não com `Base.metadata.create_all()`. Assim, toda
  execução dos testes também testa as migrações.
- **Pular × falhar:** sem banco configurado, os testes de banco são **pulados** (`skip`) — você
  consegue rodar o resto no seu PC sem Docker. Mas no CI, `PWNCHECK_REQUIRE_DB=1` transforma
  o pulo em **falha**: um CI verde com 16 testes pulados seria um verde mentiroso.

### Cada teste começa com o banco limpo: savepoints

```python
@pytest.fixture
def db_session(db_engine: Engine) -> Iterator[Session]:
    with db_engine.connect() as connection:
        transaction = connection.begin()
        session = Session(bind=connection, join_transaction_mode="create_savepoint")
        try:
            yield session
        finally:
            session.close()
            transaction.rollback()
```

```
  conexão
  └── BEGIN  (transação "de fora", aberta pela fixture)
      ├── SAVEPOINT sa_1   (a sessão cria; o commit() do código testado só o confirma)
      │     INSERT ... ON CONFLICT ...
      │     SELECT ...
      ├── RELEASE SAVEPOINT sa_1
      └── ROLLBACK  (a fixture desfaz TUDO no fim) ──> o próximo teste vê o banco vazio
```

Um **savepoint** é um "ponto de restauração" dentro de uma transação. Com
`join_transaction_mode="create_savepoint"`, até um `session.commit()` no código testado só
confirma o savepoint, e o `ROLLBACK` final apaga tudo. Resultado: os testes podem gravar à
vontade, e cada um começa do zero — rápido, porque desfazer uma transação é quase instantâneo.

### Grampeando o SQL: *event listeners*

O SQLAlchemy dispara **eventos** em pontos do seu funcionamento, e você pode registrar
funções para ouvi-los (*callbacks*, como um `signal()` ou um ponteiro de função registrado em
C). O evento `before_cursor_execute` acontece logo antes de cada comando SQL sair para o banco:

```python
@contextmanager
def record_sql(db_session) -> Iterator[list[tuple[str, dict]]]:
    statements: list[tuple[str, dict]] = []
    connection = db_session.connection()

    def capture(conn, cursor, statement, parameters, context, executemany):
        if "prefix_cache" in statement:
            values = {key: getattr(value, "obj", value) for key, value in parameters.items()}
            statements.append((statement, values))

    event.listen(connection, "before_cursor_execute", capture)
    try:
        yield statements
    finally:
        event.remove(connection, "before_cursor_execute", capture)
```

O **`@contextmanager`** transforma um gerador num gerenciador de contexto para usar com
`with`: o código antes do `yield` roda na entrada; o `finally`, na saída. Uso:

```python
with record_sql(db_session) as statements:
    check_password_cached(...)
# aqui o grampo já foi removido, e statements tem todos os comandos enviados
```

> **O bug que encontramos escrevendo este teste:** a primeira versão registrava o grampo e
> nunca o removia. No laço das duas senhas, o grampo da primeira continuava ativo durante a
> segunda, e a primeira gravação ficava com 4 comandos em vez de 2. O `try/finally` do
> gerenciador de contexto garante a remoção — é exatamente o tipo de vazamento de recurso que
> o RAII evita em C++.

E o `getattr(value, "obj", value)`? O psycopg embrulha o JSON num objeto `Jsonb`, que não
implementa `==` (dois `Jsonb` com o mesmo conteúdo são "diferentes"). `getattr` com três
argumentos devolve o atributo `obj` se existir, ou o próprio valor — desembrulhamos para
comparar o **conteúdo**.

### Outras fixtures prontas do pytest

- **`caplog`** captura os logs emitidos durante o teste: `assert SUFFIX not in caplog.text`.
- **`pytestmark = pytest.mark.usefixtures("db_session")`** aplica uma fixture a todos os testes
  do arquivo.

### O teste que pega migração esquecida

```python
def test_modelos_e_migracoes_estao_sincronizados(db_engine: Engine):
    with db_engine.connect() as connection:
        command.check(alembic_config(connection))
```

Fizemos o experimento: acrescentamos uma coluna `hits` ao modelo, sem gerar migração, e o
teste falhou com:

```
alembic.util.exc.AutogenerateDiffsDetected: New upgrade operations detected:
[('add_column', None, 'prefix_cache', Column('hits', Integer(), ...))]
```

---

## 17. CI: um PostgreSQL dentro do GitHub Actions

O job `test` ganhou um **service container**: o GitHub sobe um PostgreSQL ao lado da máquina
do job, e ele morre quando o job acaba.

```yaml
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_DB: pwncheck_test
          POSTGRES_USER: pwncheck
          POSTGRES_PASSWORD: ci-only-password
        ports:
          - 5432:5432
        options: >-
          --health-cmd "pg_isready -U pwncheck -d pwncheck_test"
          --health-interval 5s
          --health-timeout 5s
          --health-retries 10
    env:
      TEST_DATABASE_URL: postgresql+psycopg://pwncheck:ci-only-password@localhost:5432/pwncheck_test
      PWNCHECK_REQUIRE_DB: "1"
```

- A senha escrita no arquivo não é um problema: esse banco é **descartável**, existe só durante
  o job e não é acessível de fora.
- `options` com `--health-cmd`: o job só começa quando o banco está saudável — o mesmo
  `healthcheck` do Compose.
- `>-` no YAML junta as linhas seguintes numa só string (é o "texto dobrado").
- `pytest -q -rs`: o `-rs` lista os testes **pulados** e o motivo, no fim da saída.

---

## 18. Mão na massa

Com o Docker Desktop aberto (seção 5), no PowerShell:

```powershell
cd C:\dev\pwncheck
git pull
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt   # SQLAlchemy, psycopg, Alembic, pydantic-settings

Copy-Item .env.example .env
code .env                          # troque TROQUE_POR_UMA_SENHA_FORTE (nos 3 lugares!)

docker compose up -d               # sobe o PostgreSQL
docker compose ps                  # espere o "(healthy)"
alembic upgrade head               # cria a tabela prefix_cache

pytest -v                          # esperado: 103 passed (nenhum pulado)
ruff check .
ruff format --check .

python -m app.cli --cache          # "Fonte: API do HIBP..."
python -m app.cli --cache          # mesma senha: "Fonte: cache..."
python -m app.manage cache-stats

docker compose exec db psql -U pwncheck -d pwncheck    # explore com \dt, \d prefix_cache
```

Experimente também:

- `docker compose down` e `docker compose up -d`: os dados continuam (volume).
- `alembic downgrade base` (a tabela some) e `alembic upgrade head` (volta, vazia).
- Pare o banco (`docker compose stop`) e rode `python -m app.cli --cache`: veja a mensagem de
  erro e o código de saída (`$LASTEXITCODE`).

---

## 19. Decisões de design (bom assunto para entrevista)

- **Por que PostgreSQL e não Redis para um cache?** O projeto já precisa de um banco
  relacional (usuários na fase 4, métricas na fase 5). Um serviço a menos para operar,
  proteger e fazer backup. Com ~2 ms por leitura, o PostgreSQL atende com folga.
- **Por que JSONB e não uma tabela `(prefix, suffix, count)` com uma linha por sufixo?** Seriam
  ~2 mil linhas por prefixo, sempre lidas e gravadas juntas. Uma linha com JSONB é uma leitura
  só, e o upsert troca a faixa inteira atomicamente. (Uma linha por sufixo permitiria buscar
  só o nosso sufixo no SQL — o que a seção 13 proíbe.)
- **Por que stale-if-error?** Disponibilidade sem mentir: uma cópia velha só pode ter
  **menos** vazamentos, nunca um falso "vazou". E há limite de idade.
- **Por que as funções do cache não fazem commit?** Composição e testabilidade: quem abre a
  sessão decide a transação.
- **Por que testar com banco real?** O comportamento que importa (upsert, CHECK, fuso) é do
  banco. Com savepoints, os testes continuam rápidos (~0,5 s para os 103).
- **Limitação conhecida:** o cache não tem limite de tamanho; ele cresce com os prefixos
  consultados, e o `purge-cache` só remove os expirados. O exercício 5 discute alternativas.

---

## 20. Glossário

| Termo | O que é |
|---|---|
| **Cache** | Cópia local de dados caros de obter. |
| **Hit / miss** | Achou no cache / não achou (e foi buscar na fonte). |
| **TTL** | *Time to live*: por quanto tempo uma cópia é considerada fresca. |
| **Stale-if-error** | Usar uma cópia vencida só quando a fonte falha (RFC 5861). |
| **Aware / naive** | `datetime` com / sem fuso horário. |
| **UTC** | Tempo universal coordenado: o "fuso zero", referência para armazenar instantes. |
| **Docker** | Plataforma para empacotar e rodar programas em containers. |
| **Imagem** | Pacote imutável com o sistema de arquivos e o programa. |
| **Container** | Uma imagem em execução: processo isolado. |
| **Volume** | Pasta gerenciada pelo Docker que sobrevive ao container. |
| **Bind mount** | Um arquivo/pasta da sua máquina que aparece dentro do container. |
| **Porta publicada** | Redirecionamento de uma porta do host para uma do container. |
| **Healthcheck** | Comando que diz se o serviço está pronto para trabalhar. |
| **Namespaces / cgroups** | Recursos do kernel Linux que isolam (visão) e limitam (recursos) processos. |
| **Docker Compose** | Ferramenta que sobe vários containers descritos num YAML. |
| **WSL 2** | Linux de verdade rodando numa VM leve dentro do Windows. |
| **Variável de ambiente** | Par nome=valor que o sistema passa ao processo (`getenv` em C). |
| **`.env`** | Arquivo com variáveis de ambiente para o desenvolvimento, fora do Git. |
| **`SecretStr`** | Tipo do Pydantic que esconde o valor em `print`/log. |
| **Banco relacional** | Banco que guarda dados em tabelas relacionadas, consultadas com SQL. |
| **SQL** | Linguagem de consulta a bancos relacionais. |
| **Chave primária** | Coluna(s) que identifica(m) cada linha; única e não nula. |
| **Índice (B-tree)** | Estrutura ordenada que acelera buscas (O(log n)). |
| **Restrição (constraint)** | Regra garantida pelo banco: `PRIMARY KEY`, `CHECK`, `NOT NULL`... |
| **JSONB** | JSON em formato binário, consultável, no PostgreSQL. |
| **`timestamptz`** | Instante com fuso, guardado em UTC. |
| **Parâmetro (SQL)** | Valor enviado separado do comando; impede SQL injection. |
| **SQL injection** | Ataque que injeta comandos SQL por um campo de entrada. |
| **Upsert** | Inserir ou, se a chave existir, atualizar — `INSERT ... ON CONFLICT DO UPDATE`. |
| **Transação** | Bloco de operações "tudo ou nada". |
| **ACID** | Atomicidade, Consistência, Isolamento, Durabilidade. |
| **Savepoint** | Ponto de restauração dentro de uma transação. |
| **Condição de corrida** | Bug em que o resultado depende da ordem de execução de operações simultâneas. |
| **DDL** | Comandos que definem o esquema: `CREATE`, `ALTER`, `DROP`. |
| **ORM** | Mapeia classes para tabelas e objetos para linhas. |
| **Driver** | Biblioteca que fala o protocolo do banco (`psycopg`). |
| **Engine / pool** | Motor do SQLAlchemy / conjunto de conexões reaproveitadas. |
| **Session** | Unidade de trabalho do ORM: transação + mapa de identidade. |
| **Mapa de identidade** | Um objeto por linha, dentro de uma sessão. |
| **Referência fraca** | Aponta para um objeto sem mantê-lo vivo (o `std::weak_ptr` do C++). |
| **Metadata** | O catálogo do esquema descrito pelos modelos. |
| **Migração** | Script versionado que altera o esquema (e sabe desfazer). |
| **Alembic** | Ferramenta de migrações do SQLAlchemy. |
| **Autogenerate** | Rascunho de migração gerado comparando modelos e banco. |
| **Head** | A migração mais recente. |
| **Logger / nível** | Canal nomeado de logs / gravidade da mensagem (`INFO`, `WARNING`...). |
| **Fixture** | Preparação reutilizável, injetada nos testes pelo nome do parâmetro. |
| **Event listener** | Função registrada para ser chamada quando um evento acontece. |
| **Gerenciador de contexto** | Objeto usado com `with`: prepara na entrada, limpa na saída. |
| **Service container** | Container auxiliar (como um banco) que o GitHub Actions sobe ao lado do job. |

---

## 21. Exercícios

1. **Veja o mapa de identidade.** Em `load_entry`, remova o `populate_existing=True` e rode
   `pytest -v`. Qual teste falha? Agora apague a linha `held = load_entry(...)` desse teste
   (deixando o resto) e rode de novo, ainda sem o `populate_existing`. Por que ele passa?
   Desfaça tudo.
2. **Explore o SQL.** Crie o engine com `create_engine(url, echo=True)` num script e chame
   `get_range`. Leia cada comando que aparece no terminal.
3. **Uma migração sua.** Acrescente a `PrefixCache` uma coluna
   `hits: Mapped[int] = mapped_column(default=0, server_default="0")`, gere a migração com
   `alembic revision --autogenerate -m "add hits" --rev-id 0002`, leia o arquivo, aplique com
   `alembic upgrade head`, confira no `psql` e desfaça com `alembic downgrade -1`. Depois apague
   o arquivo e desfaça a mudança no modelo (a fase 4 usará o número 0002).
4. **Índice.** O `purge-cache` faz `DELETE ... WHERE fetched_at < ...`. Com milhões de linhas,
   isso leria a tabela inteira. Rode `EXPLAIN DELETE FROM prefix_cache WHERE fetched_at < now();`
   no `psql` e veja o `Seq Scan`. Como um índice em `fetched_at` mudaria isso? Vale a pena com
   algumas centenas de linhas?
5. **Desafio: limitar o tamanho do cache.** Proponha (no papel ou em código) uma política para
   o cache não passar de N faixas. Pense em "apagar as menos usadas" (*LRU*): o que precisaria
   mudar na tabela? Qual o custo de gravar a cada leitura?
6. **Desafio: o teste da corrida.** Escreva um teste com dois `threading.Thread`, cada um com a
   própria sessão, chamando `save_entry` para o mesmo prefixo ao mesmo tempo. Confirme que
   nenhum dá erro e que sobra uma linha só. (Cuidado: aqui as sessões precisam fazer commit de
   verdade — limpe a tabela no fim.)

<details>
<summary>Respostas</summary>

1. Falha `test_upsert_nao_deixa_objeto_desatualizado_na_sessao`: a segunda chamada vê a data
   antiga no objeto do mapa, acha a cópia velha e consulta a API de novo (`MISS`, e
   `api.calls == 2`). Sem a linha `held = ...`, ninguém segura o objeto: ele é liberado ao
   fim da primeira chamada, sai do mapa (referência fraca), e a segunda leitura vai ao banco
   — o teste passa por acaso. É por isso que o teste guarda o objeto.
2. Você verá o `SELECT ... WHERE prefix_cache.prefix = %(pk_1)s::VARCHAR`, o `INSERT ... ON
   CONFLICT` e, ao lado, os parâmetros — confira que o sufixo nunca aparece fora da faixa.
3. A migração gerada terá `op.add_column("prefix_cache", sa.Column("hits", sa.Integer(),
   server_default="0", nullable=False))` e o `downgrade` com `op.drop_column`. O
   `server_default` é necessário para a coluna `NOT NULL` ser criada numa tabela que já tem
   linhas: o banco precisa de um valor para preenchê-las.
4. O `EXPLAIN` mostra `Seq Scan on prefix_cache` (leitura sequencial). Com
   `CREATE INDEX ix_prefix_cache_fetched_at ON prefix_cache (fetched_at)`, o plano passa a usar
   o índice quando poucas linhas casam. Com poucas centenas de linhas, o PostgreSQL pode
   preferir o `Seq Scan` mesmo com índice (ler tudo é mais barato), e o índice só acrescenta
   custo às gravações. Índice se cria por necessidade medida, não por reflexo.
5. Uma coluna `last_used_at` atualizada a cada `HIT`, e um purge que apaga as mais antigas além
   do limite (`ORDER BY last_used_at LIMIT ...`). O custo: toda leitura vira uma escrita, o que
   gera mais trabalho para o banco (e cada escrita num JSONB grande reescreve a linha inteira —
   seria melhor ter a data numa tabela separada). É uma troca real entre simplicidade e
   controle de espaço.
6. Use `db_engine` para criar duas `Session` independentes, e `threading.Barrier(2)` para os
   dois threads chamarem `save_entry` ao mesmo tempo, seguido de `commit()`. Sem o
   `ON CONFLICT`, um dos threads receberia `IntegrityError` (chave duplicada). Apague a linha
   no fim do teste, porque ela foi confirmada de verdade, fora do savepoint.

</details>

---

## 22. Próxima fase

**Fase 4 — API REST com FastAPI + autenticação.** Até aqui, só a CLI usa o PwnCheck. Vamos
construir a API web: `POST /check`, `POST /policy` e `GET /range/{prefixo}` (o desenho
"melhor" da fase 1: o navegador calcula o hash e manda só o prefixo). E contas de usuário, com
senhas guardadas com **Argon2** (lento de propósito, ao contrário do SHA-1), login com **JWT**
e *refresh tokens* com rotação — usando a nossa própria política de senha no cadastro.
