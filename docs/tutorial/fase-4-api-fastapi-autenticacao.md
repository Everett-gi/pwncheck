# PwnCheck — Fase 4: API REST com FastAPI + autenticação

> **Objetivo:** transformar o PwnCheck num serviço web: uma API com contas de usuário, login
> seguro e as verificações das fases anteriores — e uma página em que a senha é verificada
> **sem sair do navegador**.
>
> **Pré-requisito:** [Fase 3 — cache de prefixos](fase-3-cache-postgresql.md).

**O que você vai aprender:** HTTP (métodos, status, cabeçalhos, corpo) e REST · ASGI e o
uvicorn · FastAPI (rotas, `APIRouter`, `response_model`, documentação automática) · Pydantic
(`BaseModel`, `Field`, `SecretStr`, `EmailStr`, `extra="forbid"`) · injeção de dependências com
`Depends` e `Annotated` · `def` × `async def` e o *threadpool* · `lifespan` e fábricas de
aplicação · middlewares · **Argon2id** (hash de senha lento de propósito, sal, *rehash*) ·
**ataque de temporização** · **JWT** (estrutura, assinatura HS256, *claims*, o ataque
`alg: none`) · **refresh tokens** com rotação e detecção de reuso · 401 × 403 e RBAC ·
cabeçalhos de segurança (CSP, `nosniff`, `X-Frame-Options`, `Cache-Control`) · LGPD ·
`TestClient` e `dependency_overrides` · Web Crypto no navegador.

> Os blocos `mermaid` viram diagramas no GitHub (ou no VS Code com a extensão *Markdown
> Preview Mermaid Support*). No fim há um **glossário**.

**Sumário**
1. [O que muda nesta fase](#1-o-que-muda-nesta-fase)
2. [HTTP em 10 minutos](#2-http-em-10-minutos)
3. [Do socket à rota: ASGI e uvicorn](#3-do-socket-à-rota-asgi-e-uvicorn)
4. [FastAPI: rotas e documentação automática](#4-fastapi-rotas-e-documentação-automática)
5. [Pydantic: o contrato de entrada e saída](#5-pydantic-o-contrato-de-entrada-e-saída)
6. [Injeção de dependências com `Depends`](#6-injeção-de-dependências-com-depends)
7. [`create_app`, `lifespan` e `app.state`](#7-create_app-lifespan-e-appstate)
8. [Guardando senhas: Argon2id](#8-guardando-senhas-argon2id)
9. [Login e o ataque de temporização](#9-login-e-o-ataque-de-temporização)
10. [Token de acesso: JWT](#10-token-de-acesso-jwt)
11. [Refresh tokens: rotação e detecção de reuso](#11-refresh-tokens-rotação-e-detecção-de-reuso)
12. [Autorização: 401, 403 e administradores](#12-autorização-401-403-e-administradores)
13. [As rotas de senha: `/check`, `/policy` e `/range`](#13-as-rotas-de-senha-check-policy-e-range)
14. [Blindando a API](#14-blindando-a-api)
15. [A página inicial: k-anonymity no navegador](#15-a-página-inicial-k-anonymity-no-navegador)
16. [LGPD na prática](#16-lgpd-na-prática)
17. [Testes da API](#17-testes-da-api)
18. [Mão na massa](#18-mão-na-massa)
19. [Decisões de design (bom assunto para entrevista)](#19-decisões-de-design-bom-assunto-para-entrevista)
20. [Glossário](#20-glossário)
21. [Exercícios](#21-exercícios)
22. [Próxima fase](#22-próxima-fase)

---

## 1. O que muda nesta fase

```
app/
├── security.py        NOVO (puro)   Argon2id, JWT, refresh tokens
├── accounts.py        NOVO (banco)  cadastro, login, rotação de tokens, logout, exclusão
├── schemas.py         NOVO          formatos JSON de entrada e saída (Pydantic)
├── deps.py            NOVO          dependências: sessão, cliente HIBP, usuário logado
├── middleware.py      NOVO          limite de corpo e cabeçalhos de segurança
├── main.py            NOVO          create_app(): monta a aplicação
├── routers/
│   ├── auth.py        NOVO          /auth/register, login, refresh, logout, me
│   └── passwords.py   NOVO          /check, /policy, /range/{prefixo}
├── static/            NOVO          a página inicial (HTML, JS, CSS, ícone)
├── models.py          + User, RefreshToken
└── config.py          + Settings (segredo JWT, validade dos tokens, limite de corpo)
migrations/versions/0002_create_users_and_refresh_tokens.py   NOVO
tests/
├── fakes.py           NOVO          FakeHIBP compartilhado (agora responde por prefixo)
├── test_security.py   NOVO          Argon2, JWT (inclusive ataques), refresh tokens
├── test_api_auth.py   NOVO          cadastro, login, rotação, reuso, logout, exclusão
└── test_api_passwords.py NOVO       /check, /policy, /range, cabeçalhos, limites, logs
```

O mapa da aplicação:

```mermaid
flowchart LR
    B(["Navegador / cliente"]) -- "HTTPS (fase 6)" --> U["uvicorn<br/>(servidor ASGI)"]
    U --> MW["middlewares<br/>cabeçalhos · limite de corpo"]
    MW --> R1["routers/auth.py"]
    MW --> R2["routers/passwords.py"]
    R1 --> ACC["accounts.py"] --> SEC["security.py<br/>(puro)"]
    R1 --> POL["policy.py<br/>(puro)"]
    R2 --> POL
    R1 & R2 --> PC["prefix_cache.py"]
    ACC & PC --> DB[("PostgreSQL")]
    PC --> HIBP[("HIBP")]
```

---

## 2. HTTP em 10 minutos

HTTP é um protocolo de **texto** sobre TCP: o cliente manda uma **requisição**, o servidor
devolve uma **resposta**. Uma requisição de login, byte a byte (o que o `curl` envia):

```
POST /auth/login HTTP/1.1                       <- linha inicial: MÉTODO  CAMINHO  VERSÃO
Host: 127.0.0.1:8000                            <- cabeçalhos: "Nome: valor", um por linha
Content-Type: application/json                     (o corpo é JSON)
Content-Length: 84                                 (o corpo tem 84 bytes)
                                                <- linha em branco: fim dos cabeçalhos
{"email":"gil.monteiro@exemplo.com","password":"cavalo correto bateria grampo azul"}
```

E a resposta:

```
HTTP/1.1 200 OK                                 <- VERSÃO  STATUS  MOTIVO
content-type: application/json
cache-control: no-store
x-content-type-options: nosniff
...

{"access_token":"eyJhbGciOi...","refresh_token":"Qk3...","token_type":"bearer","expires_in":900}
```

Em C, você montaria isso com `send()` num socket e leria com `recv()` até a linha em branco.
O uvicorn faz essa parte por nós.

### Métodos e status que usamos

| Método | Sentido | Na nossa API |
|---|---|---|
| `GET` | ler, sem efeitos colaterais | `/auth/me`, `/range/{prefixo}`, `/health` |
| `POST` | criar ou executar uma ação | `/auth/register`, `/auth/login`, `/check`, `/policy` |
| `DELETE` | apagar | `/auth/me` |

| Status | Significado | Quando devolvemos |
|---|---|---|
| **200** OK | deu certo | a maioria das respostas |
| **201** Created | criado | cadastro |
| **204** No Content | deu certo, sem corpo | logout, exclusão da conta |
| **401** Unauthorized | **não sei quem você é** | sem token, token inválido, login errado |
| **403** Forbidden | **sei quem você é, mas não pode** | senha errada ao apagar a conta, rota de admin |
| **409** Conflict | conflito com o estado atual | e-mail já cadastrado |
| **413** Content Too Large | corpo grande demais | mais de 16 KB |
| **422** Unprocessable Content | corpo mal formado ou inválido | JSON errado, senha fraca no cadastro |
| **503** Service Unavailable | dependência fora do ar | o HIBP não respondeu |

A família do número já diz muito: **2xx** sucesso, **4xx** erro do cliente (corrija a
requisição), **5xx** erro do servidor (tente de novo mais tarde).

**REST** é o estilo de organizar a API em **recursos** (`/auth/me` = "a minha conta") e usar
os métodos HTTP como verbos (`GET` lê, `DELETE` apaga). Não é um padrão rígido; é uma
convenção que torna APIs previsíveis.

---

## 3. Do socket à rota: ASGI e uvicorn

O **uvicorn** é o servidor: ele abre o socket, aceita conexões, interpreta o HTTP e chama a
nossa aplicação. O contrato entre os dois se chama **ASGI** (*Asynchronous Server Gateway
Interface*): a aplicação é uma função (ou objeto chamável) com três parâmetros.

```
  app(scope, receive, send)
        │       │       └── função para ESCREVER a resposta (status, cabeçalhos, corpo)
        │       └────────── função para LER a requisição (o corpo, em pedaços)
        └────────────────── dicionário com o contexto: método, caminho, cabeçalhos, IP...
```

Em C, seria como registrar um *callback* num servidor:

```c
typedef void (*app_fn)(const struct scope *s,
                       ssize_t (*receive)(void *buf, size_t n),
                       ssize_t (*send)(const void *buf, size_t n));
```

O caminho de uma requisição:

```mermaid
sequenceDiagram
    participant C as Cliente
    participant U as uvicorn
    participant M as middlewares
    participant F as FastAPI
    participant T as thread do pool
    C->>U: bytes HTTP (TCP)
    U->>M: app(scope, receive, send)
    M->>F: (verifica tamanho do corpo)
    F->>F: acha a rota, valida o JSON (Pydantic), resolve Depends
    F->>T: executa a função da rota (def)
    T-->>F: valor de retorno
    F-->>M: resposta (JSON)
    M-->>U: + cabeçalhos de segurança
    U-->>C: bytes HTTP
```

### `def` × `async def`: o *threadpool*

As nossas rotas são funções comuns (`def`). Enquanto uma espera o banco ou o HIBP, a thread
fica bloqueada — então o FastAPI executa cada chamada numa **thread de um pool** (40 threads
por padrão, confirmamos com o AnyIO), e o servidor continua atendendo outras requisições.
É o modelo "uma thread por requisição" que você conhece de servidores em C com `pthread`.

A alternativa é `async def` + `await`, em que **uma** thread alterna entre muitas requisições
enquanto elas esperam E/S. É mais eficiente com milhares de conexões, mas exige que todas as
bibliotecas sejam assíncronas. Isso é assunto do próximo projeto (ThreatScope). Aqui, o único
`async` que aparece é onde o próprio ASGI exige: o `lifespan` e os middlewares.

---

## 4. FastAPI: rotas e documentação automática

Uma rota é uma função decorada com o método e o caminho:

```python
router = APIRouter(prefix="/auth", tags=["autenticação"])


@router.post("/login", response_model=TokenResponse, responses={401: {...}})
def login(body: LoginRequest, session: DbSession, config: TokenConfigDep) -> TokenResponse:
    ...
```

O FastAPI lê a **assinatura** da função para decidir tudo:

| Parâmetro | Como o FastAPI entende |
|---|---|
| `body: LoginRequest` (uma classe Pydantic) | "leia o corpo JSON e valide contra essa classe" |
| `prefix: PrefixPath` (com `Path(...)`) | "tire do caminho da URL (`/range/{prefix}`)" |
| `session: DbSession` (com `Depends`) | "chame a dependência e injete o resultado" (seção 6) |

Isso é **introspecção**: o Python guarda as anotações de tipo em tempo de execução
(`login.__annotations__`), e o FastAPI as lê. Em C, os tipos somem depois da compilação; em
Python, eles são dados que o programa pode consultar.

**`APIRouter`** agrupa rotas de um assunto (como um módulo), com prefixo e *tag* comuns; o
`main.py` junta tudo com `app.include_router(...)`.

**Documentação automática:** com as mesmas informações, o FastAPI gera a especificação
**OpenAPI** (`/openapi.json`) e duas interfaces: **`/docs`** (Swagger UI, onde dá para testar
cada rota no navegador) e **`/redoc`**. As *docstrings* das rotas viram as descrições. O
parâmetro `responses={401: ...}` documenta os erros possíveis.

---

## 5. Pydantic: o contrato de entrada e saída

O FastAPI valida tudo o que entra com classes **Pydantic** (`app/schemas.py`):

```python
PasswordField = Annotated[SecretStr, Field(min_length=1, max_length=1024)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegisterRequest(StrictModel):
    email: EmailStr = Field(max_length=254)
    password: PasswordField
    accept_terms: bool
```

- Se o JSON não bater com a classe (campo faltando, tipo errado, texto grande demais,
  e-mail inválido), o FastAPI responde **422** sozinho, e a rota nem é chamada. Validar na
  borda é a regra: dentro do sistema, os dados já são confiáveis.
- **`Annotated[T, metadados]`** anexa informações a um tipo sem mudá-lo. `PasswordField` é
  "um `SecretStr` com tamanho entre 1 e 1024" — um *alias* reutilizável, como um `typedef`.
- **`SecretStr`**: a senha não aparece em `print`, logs ou *tracebacks*
  (`RegisterRequest(password=SecretStr('**********'), ...)`). Para usá-la, é preciso pedir
  explicitamente: `body.password.get_secret_value()`.
- **`EmailStr`** usa a biblioteca `email-validator` para conferir o formato.
- **`extra="forbid"`**: campos desconhecidos são erro. Parece rigor à toa, mas pense em
  `{"email": ..., "password": ..., "accept_terms": true, "is_admin": true}`: sem o `forbid`,
  o campo extra seria ignorado em silêncio — hoje. Se um dia alguém escrevesse
  `User(**body.model_dump())`, viraria uma falha de **mass assignment** (atribuição em massa):
  o usuário se promovendo a administrador. Há um teste para isso.

Na saída, **`response_model`** funciona como um **filtro**: só os campos declarados em
`UserResponse` (`id`, `email`, `is_admin`, `created_at`) saem, mesmo que a rota devolva o
objeto `User` inteiro, com o `password_hash`. É uma garantia estrutural contra vazar dados
por descuido.

---

## 6. Injeção de dependências com `Depends`

Desde a fase 1 injetamos dependências "na mão" (o `httpx.Client` como parâmetro). O FastAPI
automatiza isso: uma rota declara do que precisa, e ele resolve a árvore de dependências a
cada requisição.

```python
def get_db(request: Request) -> Iterator[Session]:
    with request.app.state.session_factory() as session:
        yield session


DbSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]
```

Para a rota `POST /check`:

```mermaid
flowchart TD
    CHECK["check(body, session, client, settings, user)"]
    CHECK --> B["body: CheckRequest<br/>(corpo JSON validado)"]
    CHECK --> S["session: DbSession<br/>get_db"]
    CHECK --> H["client: HibpClient<br/>get_hibp_client"]
    CHECK --> CFG["settings: SettingsDep<br/>get_settings"]
    CHECK --> U["user: CurrentUser<br/>get_current_user"]
    U --> BEAR["_bearer: lê 'Authorization: Bearer ...'"]
    U --> S
    U --> TC["config: TokenConfigDep<br/>get_token_config"]
    TC --> CFG
```

Detalhes importantes:

- **Uma dependência é resolvida uma vez por requisição**, mesmo que várias peçam por ela: a
  `session` usada por `get_current_user` é a mesma que a rota recebe.
- **Dependências com `yield`** funcionam como a fixture do pytest: o código depois do `yield`
  (aqui, o fechamento da sessão pelo `with`) roda quando a requisição termina.
- **`Annotated[Session, Depends(get_db)]`** num *alias* (`DbSession`) evita repetir
  `session: Session = Depends(get_db)` em toda rota — e evita a regra B008 do ruff, que
  desconfia de chamadas de função em valores padrão.
- **Nos testes, qualquer dependência pode ser trocada:**

  ```python
  app.dependency_overrides[get_db] = lambda: db_session             # banco transacional
  app.dependency_overrides[get_hibp_client] = lambda: hibp_client   # HIBP simulado
  ```

  É o mesmo princípio do `MockTransport` da fase 1, aplicado à aplicação inteira.

---

## 7. `create_app`, `lifespan` e `app.state`

```python
def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = create_db_engine(settings.database_url.get_secret_value())
        app.state.session_factory = create_session_factory(engine)
        app.state.hibp_client = httpx.Client(timeout=settings.hibp_timeout_seconds)
        yield
        app.state.hibp_client.close()
        engine.dispose()

    app = FastAPI(title="PwnCheck", ..., lifespan=lifespan)
    app.state.settings = settings
    ...
    return app
```

- **Fábrica de aplicação** (*application factory*): em vez de um objeto `app` criado no
  `import`, uma função que o monta. Importar `app.main` não lê configuração nem conecta em
  nada; os testes chamam `create_app(settings_de_teste)`. O uvicorn aceita isso com
  `uvicorn app.main:create_app --factory`.
- **`lifespan`**: o que vem antes do `yield` roda **uma vez na subida** do servidor (criar o
  pool de conexões, o cliente HTTP); o que vem depois, **uma vez no desligamento**. Recursos
  caros e compartilhados nascem aqui, não a cada requisição.
- **`app.state`**: um "saco" de atributos da aplicação, onde as dependências vão buscar o que
  o `lifespan` criou (`request.app.state.session_factory`).

---

## 8. Guardando senhas: Argon2id

Na fase 1 dissemos que SHA-1 e SHA-256 **não servem** para guardar senhas. Medimos por quê:

| Função | Hashes por segundo (1 núcleo, Python) |
|---|---|
| SHA-1 | ~1.590.000 |
| SHA-256 | ~1.710.000 |
| **Argon2id** (parâmetros padrão) | **~19,5** |

Se a tabela de usuários vazar, o atacante testa senhas candidatas contra os hashes. Com
SHA-256, uma única placa de vídeo testa **bilhões** por segundo; com Argon2id, cada tentativa
custa ~50 ms de CPU **e 64 MiB de memória** — cerca de 87 mil vezes mais lento que o SHA-256
na nossa medição, e sem o atalho das GPUs.

### O que é o Argon2id

O **Argon2** venceu a *Password Hashing Competition* (2015) e é padronizado na RFC 9106. A
variante **id** combina resistência a ataques por canal lateral e por GPU. Ele é
**memory-hard**: exige uma grande área de memória, preenchida e relida várias vezes. GPUs têm
milhares de núcleos, mas pouca memória por núcleo; ao exigir 64 MiB por tentativa, o Argon2
anula a vantagem delas.

```python
_hasher = PasswordHasher()   # padrão da biblioteca: RFC 9106, perfil de pouca memória


def hash_password(password: str) -> str:
    return _hasher.hash(normalize_password(password))
```

O resultado é uma string **autodescritiva**:

```
$argon2id$v=19$m=65536,t=3,p=4$9P/qQrfCgjVJ8196ZcQMLQ$0i6NBwDDJL9tjvxmrIsdBcaasH8KISs752EzwyM8Dyw
 └──┬───┘ └┬─┘ └──────┬──────┘ └─────────┬──────────┘ └───────────────────┬──────────────────────┘
algoritmo versão   parâmetros:         SAL (16 bytes           o hash (32 bytes, base64)
                   m = 64 MiB          aleatórios, base64)
                   t = 3 passadas
                   p = 4 linhas paralelas
```

- **Sal** (*salt*): bytes aleatórios diferentes para cada hash. Duas pessoas com a mesma
  senha têm hashes diferentes, e tabelas pré-calculadas (*rainbow tables*) não servem. O sal
  não é segredo: ele fica guardado junto, na própria string.
- **Parâmetros na string**: o `verify` sabe como refazer o cálculo, mesmo que os parâmetros
  padrão mudem no futuro. A recomendação mínima da OWASP é 19 MiB e 2 passadas; os nossos
  64 MiB e 3 passadas ficam acima.
- **`check_needs_rehash`**: se um dia aumentarmos os parâmetros, hashes antigos continuam
  válidos, e o login os **refaz** com os parâmetros novos — é o único momento em que temos a
  senha em mãos. Há um teste que cadastra um hash fraco e confere a troca.
- **Normalização NFC** (fase 2): "é" composto e decomposto viram a mesma senha, no cadastro e
  no login. Se normalizássemos só num dos dois, alguns usuários não conseguiriam entrar.

> **Custo real:** 64 MiB por verificação significa que 40 logins simultâneos (o tamanho do
> pool de threads) podem usar 2,5 GB de RAM. É um dos motivos do *rate limit* da fase 5.

---

## 9. Login e o ataque de temporização

```python
def authenticate(session: Session, *, email: str, password: str) -> User:
    user = get_user_by_email(session, email)
    if user is None:
        burn_password_check_time(password)  # mesmo tempo de resposta: não revela o e-mail
        raise InvalidCredentialsError
    if not verify_password(user.password_hash, password):
        raise InvalidCredentialsError
    ...
```

A mensagem de erro é a mesma para "e-mail não existe" e "senha errada" (*"E-mail ou senha
inválidos."*). Mas o **tempo** poderia denunciar a diferença: se o e-mail não existe, não há
hash para verificar, e a resposta sai muito antes. Medimos:

| Situação | Sem a proteção | Com a proteção |
|---|---|---|
| E-mail existe, senha errada | 49,7 ms | 51,8 ms |
| E-mail **não** existe | **0,8 ms** | 50,6 ms |

Sem a proteção, a diferença é de 60 vezes: qualquer pessoa descobriria quais e-mails têm conta
só cronometrando respostas. Isso é um **ataque de temporização** (*timing attack*), um tipo de
canal lateral — o mesmo conceito do *padding* da fase 1. `burn_password_check_time` roda um
Argon2 contra um hash qualquer, para gastar o mesmo tempo.

> **Mas o cadastro não revela o e-mail com o 409?** Sim — é uma troca consciente. Sem envio de
> e-mails de confirmação, não há como cadastrar sem dizer que o e-mail já existe. O *rate
> limit* da fase 5 limita quantas perguntas desse tipo alguém pode fazer.

---

## 10. Token de acesso: JWT

Depois do login, o cliente precisa provar quem é em cada requisição, sem mandar a senha de
novo. Ele recebe um **token de acesso** e o envia no cabeçalho:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwi...
```

*Bearer* ("portador") significa: quem porta o token tem o acesso (RFC 6750). Por isso ele
precisa trafegar só por HTTPS e ter vida curta.

### A anatomia de um JWT

Um **JWT** (*JSON Web Token*, RFC 7519) são três partes em **base64url**, separadas por
pontos. Um token real do PwnCheck:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 . eyJzdWIiOiIxIiwiaXNzIjoicHduY2hlY2siLCJpYXQiOjE3OTA2NDQz... . loOxCW63Ux0UEG9ooWIiHTh-STjuLZcvM-RBfeCU_9M
└──────────────┬───────────────────┘   └──────────────────────────┬─────────────────────────────┘   └───────────────────┬──────────────────────┘
            HEADER                                              PAYLOAD                                            ASSINATURA
 {"alg":"HS256","typ":"JWT"}          {"sub":"1","iss":"pwncheck","iat":1790644394,                HMAC-SHA256(header.payload, chave)
                                        "exp":1790645294,"typ":"access"}
```

- **O payload não é secreto.** Base64 é só uma codificação: qualquer um decodifica (há um
  teste que faz isso). A assinatura garante que ele **não foi alterado**, não que está
  escondido. Nada sensível vai no payload.
- **As *claims*** (afirmações): `sub` (*subject*, de quem é o token — o id do usuário), `iss`
  (*issuer*, quem emitiu), `iat` (*issued at*, quando), `exp` (*expiration*, até quando) e o
  nosso `typ`.
- **HS256** = HMAC com SHA-256: a assinatura é um hash do header e do payload **misturado com
  a chave secreta** (`JWT_SECRET`). Sem a chave, é impossível produzir uma assinatura válida
  para um payload alterado. A mesma chave assina e confere — por isso ela é o segredo mais
  importante do sistema.

```mermaid
flowchart LR
    subgraph Login
        L["POST /auth/login ok"] --> E["jwt.encode(payload, CHAVE)"] --> T["token"]
    end
    subgraph "Cada requisição"
        T2["Authorization: Bearer token"] --> D["jwt.decode(token, CHAVE,<br/>algorithms=['HS256'], issuer='pwncheck')"]
        D -- "assinatura, exp e iss ok" --> OK["sub = id do usuário"]
        D -- "qualquer falha" --> E401["401"]
    end
```

### Por que o servidor não precisa guardar o token

O token de acesso carrega tudo o que é preciso (id e validade) e se autentica pela
assinatura: conferi-lo é só uma conta, sem consulta ao banco. Isso o torna **stateless**
(sem estado). O preço: não dá para "desligar" um token antes do `exp`. Por isso a vida é
curta (**15 minutos**) — e por isso, depois de validar o token, `get_current_user` ainda
confere se o usuário existe (um token de conta apagada é recusado; há teste).

### O ataque `alg: none`

O header diz qual algoritmo foi usado. Em 2015, descobriu-se que várias bibliotecas JWT
**obedeciam** o header: um token com `"alg": "none"` (sem assinatura) era aceito como válido.
O atacante escrevia o payload que quisesse. A defesa é o servidor **decidir** o algoritmo:

```python
payload = jwt.decode(
    token,
    secret,
    algorithms=[JWT_ALGORITHM],            # só HS256; o que o header diz não importa
    issuer=JWT_ISSUER,
    options={"require": ["sub", "iss", "iat", "exp"]},
)
```

`test_tokens_invalidos_sao_recusados` fabrica os ataques e confere que todos falham: token
expirado, assinado com outra chave, payload adulterado (mantendo a assinatura original),
`alg: none`, outro emissor, outro tipo, sem `exp` e lixo.

---

## 11. Refresh tokens: rotação e detecção de reuso

Um token de 15 minutos obrigaria o usuário a digitar a senha toda hora. A solução é um
segundo token, de vida longa (7 dias), que só serve para pedir um token de acesso novo: o
**refresh token**.

Ele é diferente do JWT de propósito: são **256 bits aleatórios** (`secrets.token_urlsafe(32)`,
43 caracteres), e o banco guarda só o **SHA-256** deles.

> **Por que SHA-256 serve aqui e não para senhas?** Porque o custo de um ataque depende do
> número de possibilidades. Senhas humanas vêm de um espaço pequeno e previsível, e o hash
> lento é o que protege. Um token de 256 bits aleatórios tem 2²⁵⁶ possibilidades: nem com o
> hash mais rápido do mundo dá para testá-las. E `secrets` (não `random`!) usa o gerador
> criptográfico do sistema operacional; o `random` é previsível (Mersenne Twister).

### Rotação e famílias

Cada uso troca o refresh token por um novo (**rotação**), e o antigo deixa de valer. Os tokens
de um mesmo login formam uma **família**. Se um token **já usado** aparece de novo, alguém o
copiou — o dono legítimo e o ladrão estão usando a mesma sessão. Não dá para saber quem é
quem, então a família inteira é revogada. A RFC 9700 (boas práticas de segurança do OAuth 2.0,
seção 4.14) descreve exatamente essa ideia.

```mermaid
sequenceDiagram
    participant U as Usuário
    participant A as Atacante
    participant S as PwnCheck
    U->>S: login
    S-->>U: acesso + R1 (família F)
    Note over A: rouba uma cópia de R1
    U->>S: refresh com R1
    S-->>U: acesso + R2 (R1 marcado como usado)
    A->>S: refresh com R1
    Note over S: R1 já foi usado: REUSO!<br/>revoga a família F inteira
    S-->>A: 401
    U->>S: refresh com R2
    S-->>U: 401 (faça login de novo)
```

Testamos isso ao vivo na API rodando: o reuso devolveu 401, o log registrou
`Reuso de refresh token (usuário 1): sessão revogada.`, e o R2, que era legítimo, também
parou de funcionar.

### A corrida, de novo — e um `UPDATE` atômico

```python
claimed = session.execute(
    update(RefreshToken)
    .where(RefreshToken.id == stored.id, RefreshToken.used_at.is_(None))
    .values(used_at=now)
    .returning(RefreshToken.id)
).first()
if claimed is None:
    revoke_family(session, stored.family_id, now=now)
    raise RefreshTokenReuseError
```

A versão ingênua seria "se `stored.used_at` é nulo, marque como usado". Entre a leitura e a
escrita, outra requisição com o mesmo token poderia fazer o mesmo — e as duas ganhariam um par
novo. É o **TOCTOU** (*time of check to time of use*) que você conhece de C, como no
`access()` seguido de `open()`. O `UPDATE ... WHERE used_at IS NULL` faz a verificação e a
escrita **numa operação só**, dentro do banco: só uma das requisições consegue a linha; a
outra recebe zero linhas e é tratada como reuso. `RETURNING` devolve o que foi alterado.

Detalhe da rota: quando há reuso, ela faz `session.commit()` **antes** de responder 401. Sem
isso, a revogação seria desfeita junto com a sessão.

---

## 12. Autorização: 401, 403 e administradores

**Autenticação** é saber **quem** é o usuário; **autorização** é saber o que ele **pode**
fazer. `get_current_user` autentica (401 se falhar). `require_admin` autoriza:

```python
def require_admin(user: CurrentUser) -> User:
    if not user.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Acesso restrito a administradores.")
    return user
```

É um **RBAC** (*role-based access control*) mínimo: um papel, "administrador". Ele será usado
na fase 5, na rota de métricas. Note que `is_admin` **não** pode vir do corpo do cadastro
(`extra="forbid"`, seção 5): um administrador é promovido por um comando no servidor.

---

## 13. As rotas de senha: `/check`, `/policy` e `/range`

A fase 1 terminou com uma questão: o k-anonymity protege a senha **contra o HIBP**, mas uma
API web que recebe a senha pede que o usuário **confie em nós**. A resposta desta fase é
oferecer os dois caminhos:

```
  mais confiança exigida                                          menos confiança exigida
  ◄──────────────────────────────────────────────────────────────────────────────────────►
  POST /check, POST /policy                                 GET /range/{prefixo}
  o cliente manda a SENHA (HTTPS);                          o cliente manda só o PREFIXO;
  nós prometemos não guardar nem logar.                     nós não temos como saber a senha.
  Exige login. Útil para servidores                          Público. É o que a página inicial
  que querem a política completa.                            usa, no navegador.
```

- **`/range/{prefixo}`** devolve a faixa no **mesmo formato do HIBP** (`SUFIXO:CONTAGEM`), então
  qualquer cliente de k-anonymity pode apontar para nós. O prefixo é validado pela própria rota
  (`Path(pattern=r"^[0-9A-Fa-f]{5}$")`): um prefixo inválido recebe 422 e nem chega perto do
  HIBP (há teste). Essa validação é a versão declarativa do exercício 4 da fase 1.
- **`/policy`** junta a fase 2 e a fase 3: avalia a senha com a política, usando a contagem de
  vazamentos que vem do cache.
- **Falha fechada** (*fail closed*): se o HIBP não responde e não há cópia utilizável, a
  resposta é **503** com `Retry-After: 30`. No cadastro, isso significa não aceitar a senha
  sem verificá-la. O contrário (*fail open*: "não deu para verificar, então aceito") seria
  exatamente o falso negativo que a fase 1 ensinou a evitar.
- **O cadastro usa a nossa própria política** (*dogfooding*): 15+ caracteres, fora das listas,
  sem derivar do e-mail. `Monteiro2025!` é recusada para `gil.monteiro@exemplo.com` com os
  motivos `too_short` e `context`.

---

## 14. Blindando a API

### 14.1 O 422 que devolvia a senha

Verificamos o comportamento padrão do FastAPI: quando a validação falha, a resposta 422
**ecoa o valor recebido** no campo `input` — **mesmo com `SecretStr`**:

```json
{"detail": [{"type": "too_long", "loc": ["body", "password"],
  "msg": "Value should have at most 10 items after validation, not 21",
  "input": "segredo-grande-demais", ...}]}
```

Uma senha longa demais voltaria na resposta, e respostas passam por proxies, ferramentas de
monitoramento, histórico de depuração. O `validation_error_handler` do `main.py` substitui o
tratamento padrão e devolve só `loc`, `type` e `msg`. O teste
`test_erro_de_validacao_nao_ecoa_a_senha` garante isso.

### 14.2 Limite de tamanho do corpo — e o bug que um teste achou

O `BodySizeLimitMiddleware` recusa com **413** corpos acima de 16 KB, em duas barreiras:

1. **`Content-Length`** acima do limite: recusa sem ler nada.
2. **Corpo em pedaços** (`Transfer-Encoding: chunked`, sem `Content-Length`): o middleware lê
   e conta os pedaços; passou do limite, 413, e a aplicação nem é chamada.

A primeira versão da barreira 2 **levantava uma exceção** no meio da leitura. O teste com corpo
em pedaços falhou: a resposta era **400**, não 413. Investigando, descobrimos que o FastAPI
captura qualquer exceção durante a leitura do corpo e a transforma em "erro ao interpretar o
corpo". A correção foi ler e contar o corpo **antes** de chamar a aplicação, e entregar a ela
uma função `receive` que devolve o corpo já lido. Conferimos com o uvicorn de verdade:

```
> curl -X POST .../check -H 'Transfer-Encoding: chunked' --data-binary @20KB.txt
{"detail":"Requisição grande demais."} [413]
```

A lição vale para além do caso: **teste o comportamento que importa de ponta a ponta**, não
só a peça isolada.

### 14.3 Cabeçalhos de segurança

| Cabeçalho | Valor | Protege contra |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | o navegador "adivinhar" que um texto é script e executá-lo |
| `X-Frame-Options` | `DENY` | *clickjacking*: embutir o site num `<iframe>` invisível |
| `Referrer-Policy` | `no-referrer` | vazar a URL atual para outros sites |
| `Cache-Control` | `no-store` | tokens e resultados guardados em caches ou no disco |
| `Content-Security-Policy` | por tipo de página (abaixo) | injeção de scripts (XSS) |

A **CSP** (*Content Security Policy*) diz ao navegador de onde a página pode carregar coisas:

- **Respostas da API:** `default-src 'none'; frame-ancestors 'none'` — nada pode ser carregado.
- **Página inicial:** `script-src 'self'` (só scripts do próprio site, **nenhum** script inline),
  `connect-src 'self'` (o `fetch` só fala com o próprio servidor), `form-action 'none'`
  (formulários não podem ser enviados — seção 15).
- **`/docs` e `/redoc`:** sem CSP, porque o Swagger UI carrega scripts de uma CDN.

O **HSTS** ("use sempre HTTPS") fica para o Caddy, na fase 6: ele só faz sentido numa resposta
HTTPS.

### 14.4 Logs sem segredos

O log de acesso do uvicorn registra método, caminho e status — nunca o corpo nem o cabeçalho
`Authorization`. O cliente HTTP registra as idas ao HIBP (`GET .../range/21BD1`): só o prefixo,
que é k-anônimo. E dois testes rodam cadastro, login, `/check` e `/policy` com o log no nível
mais detalhado (`DEBUG`) e conferem que nem a senha nem o sufixo do hash aparecem.

---

## 15. A página inicial: k-anonymity no navegador

`GET /` serve uma página (`app/static/`) que faz no navegador exatamente o que a fase 1 faz em
Python:

```javascript
async function sha1Hex(text) {
  const bytes = new TextEncoder().encode(text);                  // UTF-8, como no servidor
  const digest = await crypto.subtle.digest("SHA-1", bytes);    // Web Crypto API
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}
// ...
const response = await fetch(`/range/${prefix}`);                // só o prefixo sai
const count = findCount(await response.text(), suffix);          // comparação local
```

```mermaid
sequenceDiagram
    participant P as Página (navegador)
    participant S as PwnCheck
    participant H as HIBP
    P->>P: SHA-1("P@ssw0rd") = 21BD1 | 2DC183F7...
    P->>S: GET /range/21BD1
    alt faixa em cache
        S-->>P: 1.925 linhas SUFIXO:CONTAGEM
    else
        S->>H: GET /range/21BD1
        H-->>S: faixa
        S-->>P: 1.925 linhas
    end
    P->>P: procura 2DC183F7... na lista: 6.421.042
```

Testamos num Chromium de verdade: o navegador pediu `/`, os três arquivos estáticos,
`/range/21BD1` e `/range/7A56F` — **nenhuma requisição com a senha** — e o console ficou sem
erros (a CSP não bloqueou nada). Detalhes de segurança da página:

- `crypto.subtle` só existe em **contexto seguro** (HTTPS ou `localhost`).
- O resultado é escrito com `textContent`, nunca `innerHTML`: nada vira HTML (anti-XSS).
- **`form-action 'none'`**: se o JavaScript não carregar, o navegador **não envia** o
  formulário. Sem isso, um formulário sem JS faria um `GET` com a senha na URL — e ela
  pararia no histórico e nos logs.

---

## 16. LGPD na prática

A Lei Geral de Proteção de Dados pede, entre outras coisas, coleta mínima, base legal
(consentimento) e os direitos do titular. Como isso aparece no código:

| Princípio | No PwnCheck |
|---|---|
| Coleta mínima | a conta tem só e-mail e hash da senha; nenhuma senha consultada é guardada |
| Consentimento | `accept_terms` obrigatório; a data do aceite fica em `terms_accepted_at` |
| Direito de acesso | `GET /auth/me` mostra tudo o que guardamos sobre você |
| Direito à exclusão | `DELETE /auth/me` apaga a conta e todas as sessões (`ON DELETE CASCADE`) |
| Segurança | Argon2id, tokens com hash, logs sem dados pessoais (`User.__repr__` não mostra o e-mail) |

A exclusão pede a senha de novo: um token de acesso roubado não basta para uma ação
irreversível (reautenticação para operações sensíveis).

---

## 17. Testes da API

O `TestClient` do FastAPI conversa com a aplicação **sem abrir porta de rede**: ele chama a
função ASGI diretamente, mas passa por tudo — middlewares, validação, rotas, dependências.

```python
@pytest.fixture
def api(db_session, fake_hibp, settings):
    app = create_app(settings)
    hibp_client = fake_hibp.client()
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_hibp_client] = lambda: hibp_client
    with TestClient(app) as client:        # o "with" roda o lifespan
        yield client
```

O `FakeHIBP` ficou mais realista: em vez de um corpo fixo, ele recebe um dicionário de "senhas
vazadas" e monta a faixa **do prefixo pedido**, como a API de verdade:

```python
fake_hibp.leaked["cavalo correto bateria grampo azul"] = 3    # a frase "forte" vazou
response = register(api)                                      # -> 422, motivo "breached"
```

O que os 60 testes novos cobrem (163 no total):

- **Primitivas** (`test_security.py`): Argon2id (sal, NFC, hash corrompido, *rehash*) e os oito
  ataques contra o JWT.
- **Autenticação** (`test_api_auth.py`): cadastro (normalização, só o hash, termos, senha fraca,
  vazada, HIBP fora do ar, duplicado, campo `is_admin` extra), login (mesma resposta para
  e-mail inexistente e senha errada, *rehash*), rotação, **reuso**, expiração, logout,
  exclusão com CASCADE e logs sem senha.
- **Senhas e proteções** (`test_api_passwords.py`): `/check` (só o prefixo vai ao HIBP; cache),
  `/policy`, `/range` (formato, prefixos inválidos, público), 422 sem eco, 413 com e sem
  `Content-Length`, cabeçalhos e CSP.

> **Um aviso que vai aparecer:** ao rodar o pytest, o Starlette avisa que o `TestClient` com o
> `httpx` está depreciado e recomenda o pacote `httpx2` (o sucessor do httpx, mantido pela
> equipe do Pydantic). Os testes funcionam normalmente; a troca é uma decisão para depois.

---

## 18. Mão na massa

```powershell
cd C:\dev\pwncheck
git pull
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt    # FastAPI, uvicorn, Argon2, PyJWT...

# Acrescente ao .env as linhas novas do .env.example (seção "API (fase 4)") e gere o segredo:
python -c "import secrets; print(secrets.token_urlsafe(48))"    # cole em JWT_SECRET

docker compose up -d
alembic upgrade head               # 0002: users e refresh_tokens
pytest -v                          # esperado: 163 passed

uvicorn app.main:create_app --factory --reload
```

Com o servidor no ar:

1. Abra **http://127.0.0.1:8000** e teste senhas na página inicial. Abra as ferramentas do
   desenvolvedor (F12) → aba *Network* (Rede) e confira: só `/range/XXXXX` sai.
2. Abra **http://127.0.0.1:8000/docs**:
   - `POST /auth/register` → *Try it out* → cadastre-se (teste antes uma senha fraca).
   - `POST /auth/login` → copie o `access_token`.
   - Botão **Authorize** (cadeado) → cole o token → `POST /check`, `POST /policy`, `GET /auth/me`.
   - `POST /auth/refresh` duas vezes com o **mesmo** refresh token: veja o reuso ser detectado
     no terminal do uvicorn.
3. Pelo PowerShell (use uma conta de teste: comandos ficam no histórico do terminal):

   ```powershell
   $body = @{ email = "teste@exemplo.com"; password = "cavalo correto bateria grampo azul" } | ConvertTo-Json
   $tokens = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/auth/login -ContentType "application/json" -Body $body
   Invoke-RestMethod -Uri http://127.0.0.1:8000/auth/me -Headers @{ Authorization = "Bearer $($tokens.access_token)" }
   ```

4. Cole o seu `access_token` em https://jwt.io e veja o payload decodificado — sem precisar da
   chave. (Só com tokens de teste: nunca cole tokens reais em sites de terceiros.)

---

## 19. Decisões de design (bom assunto para entrevista)

- **Por que JWT de acesso + refresh opaco, e não só um dos dois?** O JWT é conferido sem ir ao
  banco (rápido) e vive pouco; o refresh fica no banco (revogável) e vive mais. Juntos, dão
  desempenho e controle.
- **Por que HS256 e não RS256?** Só o PwnCheck emite e confere os tokens: uma chave simétrica
  basta. RS256 (chave pública/privada) serve quando **outros** serviços precisam conferir os
  tokens sem poder emiti-los.
- **Por que o refresh token não é um JWT?** Ele precisa ser revogável e de uso único; isso exige
  estado no banco de qualquer jeito. Um valor aleatório, guardado como hash, é mais simples e
  não expõe dados.
- **Por que `def` e não `async def`?** O SQLAlchemy síncrono e o `httpx.Client` são mais
  simples; o *threadpool* dá conta do volume de um projeto como este. Assíncrono é o próximo
  degrau (ThreatScope).
- **Por que oferecer `/check` se `/range` é mais privado?** Clientes que não conseguem calcular
  SHA-1 (ou que querem a política completa num passo) têm uma opção — com as proteções da
  seção 14. A documentação recomenda `/range`.
- **Por que falhar fechado no cadastro?** Aceitar uma senha sem verificá-la contra vazamentos é
  um falso negativo silencioso. Um 503 com `Retry-After` é honesto.
- **Limitações conhecidas:** não há confirmação de e-mail (o 409 revela contas existentes; o
  *rate limit* da fase 5 mitiga), nem MFA, nem recuperação de senha. São os temas do AuthHub,
  o projeto de Java dedicado à autenticação.

---

## 20. Glossário

| Termo | O que é |
|---|---|
| **HTTP** | Protocolo de requisição/resposta em texto, sobre TCP. |
| **Método HTTP** | O "verbo" da requisição: `GET`, `POST`, `DELETE`... |
| **Status HTTP** | O número da resposta: 2xx sucesso, 4xx erro do cliente, 5xx do servidor. |
| **Cabeçalho** | Linha `Nome: valor` com metadados da requisição/resposta. |
| **REST** | Estilo de API organizado em recursos e métodos HTTP. |
| **JSON** | Formato de texto para dados estruturados (objetos, listas, números, textos). |
| **ASGI** | Interface entre servidor e aplicação Python: `app(scope, receive, send)`. |
| **uvicorn** | O servidor ASGI que roda o PwnCheck. |
| **Rota / endpoint** | Combinação de método + caminho tratada por uma função. |
| **OpenAPI / Swagger** | Especificação da API / interface web para testá-la (`/docs`). |
| **Introspecção** | O programa examinar a si mesmo em tempo de execução (tipos, assinaturas). |
| **Pydantic** | Biblioteca de validação por classes com anotações de tipo. |
| **Mass assignment** | Falha em que campos extras do cliente alteram atributos que não deveriam. |
| **`Depends`** | Marca um parâmetro como dependência a ser resolvida pelo FastAPI. |
| **Threadpool** | Conjunto de threads reaproveitadas para executar tarefas. |
| **Lifespan** | Código que roda na subida e no desligamento da aplicação. |
| **Fábrica de aplicação** | Função que monta e devolve a aplicação (`create_app`). |
| **Middleware** | Camada que envolve todas as requisições (antes e depois das rotas). |
| **Argon2id** | Função de hash de senhas lenta e *memory-hard* (RFC 9106). |
| **Memory-hard** | Que exige muita memória, anulando a vantagem de GPUs. |
| **Sal (salt)** | Bytes aleatórios por hash; impede tabelas pré-calculadas. |
| **Rainbow table** | Tabela pré-calculada de hashes de senhas comuns. |
| **Rehash** | Refazer o hash com parâmetros mais fortes, no login. |
| **Ataque de temporização** | Deduzir informação pelo tempo de resposta. |
| **Token bearer** | Token que dá acesso a quem o portar (RFC 6750). |
| **JWT** | Token assinado em três partes: header, payload e assinatura (RFC 7519). |
| **Claim** | Uma afirmação no payload do JWT (`sub`, `exp`, `iss`...). |
| **HMAC / HS256** | Assinatura com hash + chave secreta / HMAC com SHA-256. |
| **Base64url** | Codificação de bytes em texto seguro para URLs. **Não** é criptografia. |
| **Stateless** | Que não depende de estado guardado no servidor. |
| **Refresh token** | Token de vida longa que só serve para obter tokens de acesso novos. |
| **Rotação** | Trocar o refresh token a cada uso. |
| **Detecção de reuso** | Revogar a família quando um token já usado reaparece. |
| **TOCTOU** | Corrida entre verificar uma condição e agir sobre ela. |
| **Autenticação × autorização** | Quem você é × o que você pode fazer. |
| **RBAC** | Controle de acesso por papéis (ex.: administrador). |
| **Fail closed / fail open** | Na dúvida, negar / na dúvida, permitir. |
| **Dogfooding** | Usar o próprio produto (a nossa política no nosso cadastro). |
| **CSP** | Política que diz ao navegador de onde a página pode carregar recursos. |
| **XSS** | Injeção de script numa página, executado no navegador da vítima. |
| **Clickjacking** | Enganar o usuário com o site embutido num `<iframe>` invisível. |
| **HSTS** | Cabeçalho que obriga o navegador a usar sempre HTTPS. |
| **Web Crypto** | API de criptografia dos navegadores (`crypto.subtle`). |
| **Contexto seguro** | Página servida por HTTPS (ou localhost), exigida pela Web Crypto. |
| **LGPD** | Lei Geral de Proteção de Dados (Lei 13.709/2018). |
| **TestClient** | Cliente HTTP de testes que chama a aplicação ASGI sem rede. |

---

## 21. Exercícios

1. **Veja o eco do 422.** Em `create_app`, comente a linha do `add_exception_handler` e rode
   `pytest -k eco -v`. Leia a resposta que o teste recebe. Desfaça.
2. **O ataque de temporização.** Em `accounts.authenticate`, comente a chamada a
   `burn_password_check_time` e, com o servidor no ar, meça com o PowerShell:
   `Measure-Command { try { Invoke-RestMethod ... } catch {} }` para um e-mail cadastrado e para
   um inexistente. Desfaça.
3. **Token de outro usuário.** Gere um token com `create_access_token(2, secret="...", ...)`
   usando uma chave diferente da do `.env`. Use-o no `/auth/me`. Depois use a chave certa. O que
   isso ensina sobre o `JWT_SECRET`?
4. **Padding no `/range`.** Implemente o cabeçalho `Add-Padding: true` no nosso `/range`: quando
   presente, acrescente linhas falsas (sufixos aleatórios com contagem 0) até completar um
   total aleatório entre 800 e 1.000 linhas a mais. Escreva o teste antes. Dica: `secrets.token_hex`
   e `secrets.randbelow`.
5. **Limitar hashes simultâneos.** Na seção 8, vimos que 40 logins simultâneos podem usar 2,5 GB.
   Proponha uma forma de limitar a 4 cálculos de Argon2 ao mesmo tempo (dica:
   `threading.BoundedSemaphore`). Qual o efeito colateral para quem espera?
6. **Desafio: expiração no banco.** Os refresh tokens expirados e revogados ficam na tabela para
   sempre. Escreva `purge_refresh_tokens(session, now)` em `accounts.py`, com teste, apagando os
   que expiraram ou foram revogados há mais de 7 dias. (A fase 5 vai usá-la.)

<details>
<summary>Respostas</summary>

1. O teste falha, e a resposta tem `"input": "segredo-segredo-..."` — a senha inteira de volta.
   É o motivo de o handler existir.
2. Sem a proteção, o e-mail inexistente responde em poucos milissegundos, e o cadastrado em
   ~50 ms (a nossa medição: 0,8 ms × 49,7 ms, fora a rede). Com ela, os dois ficam iguais.
3. Com a chave errada: 401. Com a chave certa, **qualquer** `sub` é aceito: quem tem o
   `JWT_SECRET` se passa por qualquer usuário. Por isso ele fica só no ambiente, é longo e
   aleatório, e é trocado se houver suspeita de vazamento (o que invalida todos os tokens).
4. Leia o cabeçalho com `request.headers.get("Add-Padding")` (receba `request: Request` na rota).
   Gere `secrets.token_hex(18)[:35].upper()` para cada sufixo falso e embaralhe as linhas com
   `random.SystemRandom().shuffle`. O cliente (`parse_range_response` e o `app.js`) já ignora
   contagem 0. Teste: com o cabeçalho, o número de linhas cresce e as contagens reais continuam
   lá; sem ele, nada muda.
5. Um `BoundedSemaphore(4)` global em `security.py`, com `with _semaphore:` em volta do
   `hash`/`verify`. Quem chega quando os 4 estão ocupados **espera** (a thread fica parada) — o
   login fica mais lento sob carga, mas a memória fica limitada a ~256 MiB. É trocar latência por
   estabilidade.
6. `session.execute(delete(RefreshToken).where(or_(RefreshToken.expires_at < now,
   RefreshToken.revoked_at < now - timedelta(days=7))))` e devolva o `rowcount`. Teste com três
   tokens: um válido, um expirado e um revogado há 8 dias.

</details>

---

## 22. Próxima fase

**Fase 5 — Rate limit e métricas.** A API está no ar, mas nada impede alguém de tentar mil
senhas por minuto no login, ou de martelar o `/range`. Vamos implementar um **rate limit** com
janela deslizante, guardado no PostgreSQL com o mesmo upsert atômico da fase 3 (sem Redis), com
respostas **429** e `Retry-After`. E **métricas** de uso por dia — quantas verificações,
quantos acertos no cache — numa rota só para administradores.
