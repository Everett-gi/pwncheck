# PwnCheck — Fase 1: cliente k-anonymity

> **Objetivo:** verificar se uma senha vazou **sem enviá-la a ninguém**, com código testado
> automaticamente — inclusive um teste que prova que a senha não sai da máquina.
>
> **Pré-requisitos:** [Lição 00 (ambiente)](../../../../tutorial/00-ambiente.md) e
> [Lição 01 (Python para quem vem do C/C++)](../../../../tutorial/01-python-para-quem-vem-do-c.md).

**O que você vai aprender:** `hashlib` e hashes criptográficos · `str` × `bytes` na prática ·
separar lógica pura de E/S · cliente HTTP com `httpx` · injeção de dependência · `pytest`
(asserts, `raises`, `parametrize`) · mocks de rede com `MockTransport` · `ruff` (lint e
formatação) · CI com GitHub Actions · `pip-audit` e `bandit`.

**Sumário**
1. [O problema](#1-o-problema)
2. [A solução: k-anonymity](#2-a-solução-k-anonymity)
3. [SHA-1: por que ele, e por que ele não serve para guardar senhas](#3-sha-1-por-que-ele-e-por-que-ele-não-serve-para-guardar-senhas)
4. [A estrutura do projeto](#4-a-estrutura-do-projeto)
5. [`kanonymity.py`: o núcleo puro](#5-kanonymitypy-o-núcleo-puro)
6. [`hibp_client.py`: a fronteira com a rede](#6-hibp_clientpy-a-fronteira-com-a-rede)
7. [`cli.py`: testando de verdade](#7-clipy-testando-de-verdade)
8. [Testes com pytest](#8-testes-com-pytest)
9. [Mocks: testando rede sem rede](#9-mocks-testando-rede-sem-rede)
10. [Qualidade: ruff](#10-qualidade-ruff)
11. [CI: GitHub Actions](#11-ci-github-actions)
12. [Mão na massa](#12-mão-na-massa)
13. [Decisões de design (bom assunto para entrevista)](#13-decisões-de-design-bom-assunto-para-entrevista)
14. [Exercícios](#14-exercícios)
15. [Próxima fase](#15-próxima-fase)

---

## 1. O problema

Queremos responder: *"esta senha já apareceu em algum vazamento de dados?"* O
HaveIBeenPwned (HIBP) mantém uma base com cerca de **2 bilhões** de hashes de senhas vazadas
(estimativa nossa: medimos ~2.100 hashes por prefixo, × 1.048.576 prefixos). Como consultar
sem entregar a senha?

| Ideia | Problema |
|---|---|
| Enviar a senha | Você passa a depender da honestidade do serviço — ele poderia guardá-la. |
| Enviar o hash completo | Dá quase no mesmo: o serviço tem a base de hashes; se o seu estiver lá, ele sabe exatamente qual senha é. |
| Baixar a base inteira | Dezenas de GB, e desatualiza. |

## 2. A solução: k-anonymity

Em 2018, o Troy Hunt (criador do HIBP) e a Cloudflare publicaram este modelo:

1. Calcula-se o SHA-1 da senha **localmente**: 40 caracteres hexadecimais.
2. Envia-se **só os 5 primeiros** (o *prefixo*). Existem 16⁵ = 1.048.576 prefixos possíveis.
3. A API devolve **todos** os hashes vazados que começam com aquele prefixo — só os 35
   caracteres restantes (os *sufixos*) e quantas vezes cada um apareceu.
4. A comparação com o nosso sufixo acontece **aqui**.

Resultado real, rodado na sua máquina com a senha de exemplo da documentação do HIBP:

```
  SUA MÁQUINA                                       api.pwnedpasswords.com
  ───────────                                       ──────────────────────
  "P@ssw0rd"
      │  SHA-1, calculado aqui
      v
  21BD1 2DC183F740EE76F27B78EB39C8AD972A757
  └─┬─┘ └───────────────┬─────────────────┘
 prefixo    sufixo (nunca sai daqui)
    │
    └──── GET /range/21BD1 ──────────────────────>  procura a faixa 21BD1:
                                                    1.925 hashes reais
    ┌──── 2.044 linhas "SUFIXO:CONTAGEM" <────────  + 119 falsas (padding)
    v
  procura 2DC183F7...A757 na lista, AQUI  ──>  6.421.042 vazamentos
```

**O "k" do k-anonymity:** a consulta é indistinguível entre os **1.925** hashes reais daquele
prefixo (e entre todas as outras senhas possíveis com esse prefixo, que não estão na base).
Nem a própria API sabe qual era o nosso.

**E o padding?** Mesmo com HTTPS, quem observa a rede vê o **tamanho** da resposta. Como cada
prefixo tem uma quantidade diferente de hashes, o tamanho poderia denunciar qual prefixo foi
consultado. Com o cabeçalho `Add-Padding: true`, a API mistura entradas falsas com contagem 0,
deixando as respostas com tamanhos parecidos. Na nossa medição: 1.925 linhas sem padding,
2.044 com padding (119 falsas). É um exemplo de defesa contra **canal lateral** (*side channel*).

## 3. SHA-1: por que ele, e por que ele não serve para guardar senhas

Uma função de hash criptográfica transforma qualquer entrada em um valor de tamanho fixo
(160 bits no SHA-1), é determinística, muda completamente com qualquer bit alterado
(*efeito avalanche*) e não pode ser invertida na prática.

- **O SHA-1 está quebrado** para assinaturas: em 2017, o Google e o CWI geraram dois PDFs
  diferentes com o mesmo SHA-1 (ataque *SHAttered*). Nada disso nos afeta: aqui o SHA-1 é só
  a **chave de busca** da base do HIBP, que foi montada com SHA-1. Não protegemos nada com ele.
- **Guardar senhas com SHA-1 (ou SHA-256) é errado**, mesmo com sal: esses hashes são
  rápidos demais, e uma GPU testa bilhões por segundo. Para guardar senhas usam-se funções
  **lentas de propósito**, como Argon2 ou bcrypt. É o que faremos no login da fase 4.

---

## 4. A estrutura do projeto

```
python/pwncheck/
├── app/                      <- o código (um "pacote": pasta com __init__.py)
│   ├── __init__.py
│   ├── kanonymity.py         <- funções PURAS: hash, divisão, parsing
│   ├── hibp_client.py        <- a única parte que fala com a rede
│   └── cli.py                <- ferramenta de linha de comando
├── tests/                    <- os testes (pytest encontra sozinho)
│   ├── __init__.py
│   ├── test_kanonymity.py
│   └── test_hibp_client.py
├── docs/tutorial/            <- esta lição
├── pyproject.toml            <- configuração do ruff e do pytest
├── requirements.txt          <- dependências de execução
├── requirements-dev.txt      <- + dependências de desenvolvimento
└── .venv/                    <- ambiente virtual (fora do Git)
```

**Por que separar `kanonymity.py` de `hibp_client.py`?** É o padrão *núcleo funcional, casca
imperativa* (*functional core, imperative shell*):

- O **núcleo** (`kanonymity.py`) só transforma dados: recebe texto e devolve texto ou dicts.
  Não faz rede, não lê arquivo, não acessa banco. Testar é trivial e instantâneo.
- A **casca** (`hibp_client.py`) faz a E/S e delega toda a lógica ao núcleo. Fica fina, com
  pouco o que dar errado.

É a mesma regra do `text_utils.py` do DocSage, e vale para todos os projetos do portfólio.

---

## 5. `kanonymity.py`: o núcleo puro

Abra o arquivo [`app/kanonymity.py`](../../app/kanonymity.py) ao lado.

### Constantes

```python
PREFIX_LENGTH = 5
SHA1_HEX_LENGTH = 40
```

Python não tem `const` nem `#define`: a convenção é o nome em MAIÚSCULAS dizer "não altere".
Nada impede tecnicamente; o ruff e a revisão de código garantem.

### `sha1_hex`

```python
def sha1_hex(password: str) -> str:
    data = password.encode("utf-8")  # o hash é calculado sobre BYTES, não sobre texto
    return hashlib.sha1(data, usedforsecurity=False).hexdigest().upper()
```

Linha por linha, comparando com o que você faria em C com o OpenSSL:

```c
// C: você gerencia os bytes, o buffer de saída e a conversão para hexadecimal
unsigned char md[SHA_DIGEST_LENGTH];                  // 20 bytes
SHA1((const unsigned char *)pwd, strlen(pwd), md);    // assume que pwd já está em UTF-8
char hex[41];
for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    sprintf(hex + 2 * i, "%02X", md[i]);              // maiúsculas, 2 dígitos por byte
```

- `password.encode("utf-8")` converte `str` (caracteres) em `bytes`. Em C a string já é um
  array de bytes, e a codificação fica implícita — e é aí que mora o bug. Aqui ela é
  **explícita**, e há um teste provando que ela importa (`"é"` tem outro hash em Latin-1).
- `hashlib.sha1(...)` chama **o mesmo OpenSSL** do exemplo em C: o `hashlib` é uma DLL
  (`_hashlib.pyd`) ligada ao OpenSSL 3.0.16.
- `.hexdigest()` devolve os 20 bytes como 40 caracteres hexadecimais minúsculos; `.upper()`
  põe em maiúsculas, o formato da API. Os métodos encadeados funcionam porque cada um devolve
  um objeto novo.
- `usedforsecurity=False` declara que o SHA-1 não está sendo usado como proteção. Sem isso,
  o ruff acusa a regra **S324** ("uso de hash inseguro") — e com razão, na maioria dos
  contextos. Esse parâmetro é a forma documentada de dizer "sei o que estou fazendo, e o
  motivo está na docstring".

### `split_hash`

```python
def split_hash(sha1_hash: str) -> tuple[str, str]:
    if len(sha1_hash) != SHA1_HEX_LENGTH:
        raise ValueError(
            f"O hash SHA-1 deve ter {SHA1_HEX_LENGTH} caracteres, recebido: {len(sha1_hash)}."
        )
    return sha1_hash[:PREFIX_LENGTH], sha1_hash[PREFIX_LENGTH:]
```

- `s[:5]` e `s[5:]` são fatias: do início até antes do 5, e do 5 até o fim. Cada fatia é uma
  string nova (cópia), sem aritmética de ponteiros.
- O retorno `a, b` é **uma tupla**, e quem chama desempacota: `prefix, suffix = split_hash(h)`.
- A validação levanta `ValueError` (argumento com valor inválido) em vez de devolver um
  código de erro. A mensagem mostra o **tamanho** recebido, não o valor: é um hábito
  saudável não ecoar entrada potencialmente sensível em mensagens de erro.

### `parse_range_response`

```python
def parse_range_response(body: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for line in body.splitlines():
        suffix, separator, count = line.strip().partition(":")
        if not separator:
            continue  # linha vazia ou sem ":": ignora
        occurrences = int(count)
        if occurrences > 0:
            counts[suffix.upper()] = occurrences
    return counts
```

- `splitlines()` quebra nas terminações `\n`, `\r\n` e `\r`. A API real usa `\r\n` — um
  `split("\n")` deixaria um `\r` grudado em cada contagem.
- `strip()` remove espaços e quebras das pontas.
- `partition(":")` sempre devolve uma tupla de 3 partes `(antes, separador, depois)` e
  **nunca levanta exceção**: se não houver `:`, o separador vem vazio (falso) e pulamos a
  linha. Com `a, b = line.split(":")`, uma linha sem `:` levantaria `ValueError` no
  desempacotamento.
- `int(count)` **levanta** `ValueError` se a contagem não for número. Isso é proposital:
  uma resposta corrompida não pode virar "senha segura" em silêncio. Falhar alto é mais
  seguro que adivinhar.
- Entradas com contagem 0 são o padding e são descartadas aqui, no núcleo — assim a casca
  nem precisa saber que padding existe.

---

## 6. `hibp_client.py`: a fronteira com a rede

Abra [`app/hibp_client.py`](../../app/hibp_client.py).

O **httpx** é um cliente HTTP (pense na libcurl, mas com uma API de alto nível). Ele cuida de
TLS, conexões reaproveitadas (*keep-alive*), redirecionamentos, compressão e timeouts.

```python
def fetch_range(client: httpx.Client, prefix: str) -> dict[str, int]:
    response = client.get(f"{API_BASE_URL}/range/{prefix}", headers=HEADERS)
    response.raise_for_status()  # status 4xx/5xx vira exceção (httpx.HTTPStatusError)
    return parse_range_response(response.text)


def check_password(client: httpx.Client, password: str) -> int:
    prefix, suffix = split_hash(sha1_hex(password))
    return fetch_range(client, prefix).get(suffix, 0)
```

- `raise_for_status()` transforma um erro HTTP em exceção. Sem ele, um erro 503 da API
  chegaria ao parser como um corpo vazio, e a senha seria dada como "não vazada". De novo:
  falhar alto.
- `response.text` é o corpo já decodificado para `str` (o httpx lê o charset do cabeçalho).
- `.get(suffix, 0)`: "a contagem desse sufixo, ou 0 se ele não estiver na lista".
- `HEADERS` leva o `User-Agent` (a API pede que o cliente se identifique) e o `Add-Padding`.

### Injeção de dependência

Repare que `check_password` **recebe** o `client` em vez de criar um lá dentro. Isso se chama
**injeção de dependência**, e é o mesmo que, em C, receber uma struct de ponteiros para
função em vez de chamar `send()` direto — ou, em C++, receber uma interface por referência.
Ganhos:

1. **Testabilidade:** nos testes, passamos um cliente cuja "rede" é uma função nossa (seção 9).
2. **Controle:** quem chama decide o timeout e reaproveita conexões entre várias consultas.
3. **Clareza:** a assinatura da função já diz que ela faz E/S.

---

## 7. `cli.py`: testando de verdade

Abra [`app/cli.py`](../../app/cli.py). É uma ferramenta pequena para ver o projeto
funcionando contra a API real, antes de existir a API web (fase 4).

```python
def main() -> int:
    password = getpass.getpass("Senha a verificar (não aparece enquanto você digita): ")
    ...
    try:
        with httpx.Client(timeout=10.0) as client:
            count = check_password(client, password)
    except httpx.HTTPError as exc:
        print(f"Falha ao consultar a API: {exc}")
        return 2
    ...


if __name__ == "__main__":
    sys.exit(main())
```

- `getpass.getpass()` lê sem mostrar o que é digitado — o equivalente a desligar o eco com
  `termios` no Linux, ou ler com `_getch()` do `conio.h` no Windows.
- **Por que não receber a senha como argumento** (`python -m app.cli minhasenha`)? Porque ela
  ficaria gravada no histórico do terminal e visível na lista de processos do sistema.
- `with httpx.Client(...) as client:` é o RAII (Lição 01, seção 11): as conexões são fechadas
  ao sair do bloco, com ou sem exceção.
- `except httpx.HTTPError` pega a família inteira de erros do httpx, graças à hierarquia de
  exceções: `ConnectError` (sem rede), `TimeoutException` e `HTTPStatusError` (o
  `raise_for_status`) são todos subclasses de `HTTPError`. É como capturar uma classe base
  em C++.
- `main() -> int` + `sys.exit(main())` reproduz o `int main()` do C: o número vira o código de
  saída do processo (0 = sucesso). No PowerShell, veja com `$LASTEXITCODE`.
- **Como rodar:** `python -m app.cli`, de dentro de `python/pwncheck`. O `-m` executa o módulo
  `app.cli` como programa principal e coloca a pasta atual no caminho de busca — é por isso
  que o `from app.hibp_client import ...` funciona.

---

## 8. Testes com pytest

O pytest é o GoogleTest do Python, com muito menos cerimônia:

| GoogleTest (C++) | pytest |
|---|---|
| `TEST(Suite, Nome) { ... }` | uma função `def test_nome():` num arquivo `test_*.py` |
| `EXPECT_EQ(a, b)` | `assert a == b` |
| `EXPECT_THROW(f(), std::invalid_argument)` | `with pytest.raises(ValueError): f()` |
| `TEST_P` + `INSTANTIATE_TEST_SUITE_P` | `@pytest.mark.parametrize(...)` |
| registrar os testes num `main` | nada: o pytest descobre sozinho |

- **Descoberta:** o pytest procura arquivos `test_*.py` na pasta `tests` (configurada no
  `pyproject.toml`) e executa cada função `test_*`.
- **`assert` puro:** o pytest reescreve os `assert` ao carregar os testes. Quando um falha, ele
  mostra os valores dos dois lados, sem precisar de um `EXPECT_EQ` para cada tipo de comparação.
- **Como `import app` funciona nos testes:** como `tests/` tem um `__init__.py`, o pytest
  coloca a pasta *acima* dela (a raiz do projeto) no caminho de busca, e o pacote `app` fica
  importável.
- **Nomes descritivos:** o código é em inglês, mas os nomes dos testes descrevem o
  comportamento esperado em português, como uma especificação legível
  (`test_somente_o_prefixo_sai_da_maquina`). Quando um falha, o nome já diz o que quebrou.

### Vetores de teste independentes

```python
# printf 'password' | sha1sum
PASSWORD_SHA1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


def test_sha1_hex_de_valor_conhecido():
    assert sha1_hex("password") == PASSWORD_SHA1
```

O valor esperado foi calculado com o `sha1sum` do Git Bash, **uma implementação diferente**.
Se tivéssemos gerado o valor esperado rodando o próprio `sha1_hex`, o teste passaria mesmo com
a função errada — um teste circular não prova nada.

### `parametrize`: um teste, vários casos

```python
@pytest.mark.parametrize("invalid", ["", "5BAA6", PASSWORD_SHA1 + "0"])
def test_split_hash_rejeita_tamanho_invalido(invalid):
    with pytest.raises(ValueError):
        split_hash(invalid)
```

O pytest roda a função uma vez para cada valor e mostra cada caso separado no relatório
(`test_split_hash_rejeita_tamanho_invalido[5BAA6]`). Os casos cobrem as bordas: vazio,
curto e um caractere a mais.

### Comandos úteis

```powershell
pytest              # roda tudo
pytest -v           # um teste por linha
pytest -k padding   # só os testes com "padding" no nome
pytest -x           # para no primeiro que falhar
pytest --lf         # roda só os que falharam da última vez
```

---

## 9. Mocks: testando rede sem rede

Testes que acessam a internet de verdade são **lentos**, **instáveis** (a rede cai, a API muda)
e, no CI, podem estourar o limite de requisições da API. A solução é simular a API.

O httpx separa o *cliente* (monta requisições, trata respostas) do *transporte* (a camada que
realmente envia bytes pela rede). O `httpx.MockTransport` troca o transporte por uma função
nossa:

```python
def fake_api(body: str, status: int = 200, sent: list[httpx.Request] | None = None) -> httpx.Client:
    """Cria um httpx.Client cuja "internet" é a função `handler` abaixo."""

    def handler(request: httpx.Request) -> httpx.Response:
        if sent is not None:
            sent.append(request)  # guarda a requisição para o teste inspecionar
        return httpx.Response(status, text=body)

    return httpx.Client(transport=httpx.MockTransport(handler))
```

- Em C, o equivalente seria linkar os testes com uma implementação falsa de `send()`/`recv()`
  (um *link seam*); em C++, injetar um objeto *mock* que implementa a mesma interface. Aqui
  basta uma função, graças à injeção de dependência da seção 6.
- `handler` é uma **closure** (Lição 01, seção 9): ela captura `body`, `status` e `sent` da
  função de fora.
- `sent: list[...] | None = None` evita a armadilha do argumento padrão mutável (Lição 01,
  seção 9). Com `sent=[]`, todos os testes compartilhariam a mesma lista.

### O teste mais importante do projeto

```python
def test_somente_o_prefixo_sai_da_maquina():
    """A garantia central do k-anonymity: nada além do prefixo trafega."""
    sent: list[httpx.Request] = []
    check_password(fake_api("", sent=sent), PASSWORD)

    assert len(sent) == 1  # exatamente uma consulta
    request = sent[0]
    assert request.url.path == f"/range/{PREFIX}"

    # Nada sensível em NENHUMA parte da requisição: URL, cabeçalhos ou corpo.
    everything_sent = f"{request.url} {request.headers} {request.content!r}".lower()
    for secret in (PASSWORD, FULL_HASH, SUFFIX):
        assert secret.lower() not in everything_sent
```

Este teste é a **promessa de segurança do projeto em forma executável**. Se alguém, numa
refatoração, enviar o hash completo por engano (ou colocar a senha num cabeçalho de
depuração), o CI falha antes de o código chegar à `main`. A comparação em minúsculas cobre o
hash em qualquer caixa.

**Fizemos o experimento** (é o exercício 2): alterando o código para enviar o hash completo,
**16 testes continuam passando** — afinal, a senha continua sendo verificada corretamente — e
**só este falha**:

```
>       assert request.url.path == f"/range/{PREFIX}"
E       AssertionError: assert '/range/F5ECC...806F6E7D551BD' == '/range/F5ECC'
E         - /range/F5ECC
E         + /range/F5ECC438433522CF2334104C54C806F6E7D551BD
```

A lição: **testes de funcionalidade não protegem propriedades de segurança.** O código
"funcionaria" e vazaria. Toda garantia de segurança importante merece um teste próprio.

---

## 10. Qualidade: ruff

O **ruff** faz dois trabalhos:

| Comando | Papel | Equivalente em C/C++ |
|---|---|---|
| `ruff check .` | lint: bugs prováveis, estilo, segurança | clang-tidy / cppcheck |
| `ruff format .` | formatação automática | clang-format |

As regras ativadas no `pyproject.toml`:

| Código | Família | Exemplo do que pega |
|---|---|---|
| `E`, `W` | estilo (pycodestyle) | linha longa, espaço sobrando |
| `F` | erros reais (pyflakes) | import não usado, nome indefinido |
| `I` | ordenação de imports | stdlib → terceiros → projeto |
| `B` | bugs comuns (bugbear) | o argumento padrão mutável da Lição 01! |
| `S` | segurança (bandit) | senha no código, hash fraco, SQL montado com strings |

### O que aconteceu nesta fase (e o que aprender com isso)

1. **S105 nos testes — um falso positivo.** O ruff acusou "possível senha escrita no código"
   em `PASSWORD = "minha-senha-super-secreta"`. Nos testes, isso é proposital. A solução
   certa foi desligar a regra **só para a pasta de testes**, com a justificativa escrita:

   ```toml
   [tool.ruff.lint.per-file-ignores]
   # ... senhas escritas no código (S105/S106) são dados de teste de propósito
   "tests/*" = ["S101", "S105", "S106"]
   ```

   A solução **errada** seria renomear a variável para `VALOR = ...` só para enganar o
   linter: a regra continuaria "valendo" no papel, mas não protegeria nada. Em `app/`, a
   regra continua ativa.

2. **S324 (hash inseguro)** foi evitado desde o início com `usedforsecurity=False` (seção 5).

3. **Formatação.** O `ruff format` ajustou 5 arquivos: acrescentou uma linha em branco depois
   da docstring de cada módulo e juntou numa linha só uma assinatura de função que cabia nas
   100 colunas. Com um formatador automático, estilo deixa de ser assunto de revisão de
   código. O CI exige o código formatado (`ruff format --check`); no VS Code, configure o
   *format on save* (Lição 00, seção 7).

---

## 11. CI: GitHub Actions

A cada `push`, o GitHub sobe uma máquina Ubuntu **nova e limpa**, baixa o repositório e roda
os passos do arquivo [`.github/workflows/pwncheck-ci.yml`](../../../../.github/workflows/pwncheck-ci.yml).
Se o código só funciona "na sua máquina", o CI descobre.

```yaml
on:
  push:
    branches: [ main ]
    paths:                       # monorepo: só roda se o PwnCheck mudou
      - "python/pwncheck/**"
      - ".github/workflows/pwncheck-ci.yml"
  workflow_dispatch:             # botão "Run workflow" na aba Actions (execução manual)

permissions:
  contents: read                 # menor privilégio: o token do CI só pode ler

defaults:
  run:
    working-directory: python/pwncheck   # todos os comandos rodam na pasta do projeto
```

São dois *jobs*, que rodam em paralelo:

| Job | Passos |
|---|---|
| `test` | instala o `requirements-dev.txt` → `ruff check` → `ruff format --check` → `pytest` |
| `security` | `pip-audit` (dependências com vulnerabilidades conhecidas) → `bandit` (análise estática de segurança) |

- **`permissions: contents: read`:** cada execução recebe um token de acesso ao repositório.
  Dependendo das configurações do repositório (ou da organização), ele pode ter permissão de
  escrita — e uma dependência maliciosa rodando no CI poderia usá-lo. Declarar `permissions`
  no workflow garante o mínimo necessário, independentemente dessas configurações: é o
  princípio do **menor privilégio**.
- **`pip-audit`** consulta bancos públicos de vulnerabilidades (CVEs) para cada pacote do
  `requirements.txt`, incluindo os transitivos.
- **`bandit`** procura padrões perigosos no código (`eval`, senha escrita no código, SQL
  montado com strings...).
- **Aqui os scans bloqueiam o CI**, diferente do DocSage. O projeto é pequeno e novo: se
  surgir uma vulnerabilidade numa dependência, queremos saber na hora e atualizar. Antes do
  primeiro push, os dois foram rodados localmente: *No known vulnerabilities found*, e nenhum
  alerta do bandit.

Os resultados aparecem na aba **Actions** do repositório no GitHub.

**Um detalhe que apareceu na prática:** no primeiro push, só o PwnCheck CI rodou — o do DocSage,
não. Num branch novo, o GitHub não tem um "antes" para comparar, e a avaliação do filtro
`paths` acabou considerando só o último commit enviado, que só mexia no PwnCheck. Por isso os
dois workflows ganharam o gatilho `workflow_dispatch`: com ele, qualquer workflow pode ser
rodado manualmente pela aba Actions (*Run workflow*), sem precisar de um push.

### O CI pegou um erro que tinha passado localmente

Nesse mesmo primeiro push, o job `test` **falhou** no passo de formatação — e na máquina local
o mesmo comando tinha dito *already formatted*. A causa: o `ruff format` também formata os
blocos de código Python **dentro de arquivos Markdown**, e esta lição foi escrita *depois* da
última verificação local. Um trecho tinha uma linha em branco antes de um `def`, e o padrão
pede duas. Duas lições:

1. **Rode as verificações sobre o estado final**, logo antes do commit, e não "um pouco antes".
   Existe uma ferramenta que automatiza isso, o *pre-commit*, que roda o ruff a cada
   `git commit`. Fica para uma fase futura.
2. **É exatamente para isso que o CI existe:** ele roda numa máquina limpa, sobre o commit
   exato, sem cache e sem "mas na minha máquina funcionou".

A correção foi tirar a pasta `docs/` do alcance do ruff (`extend-exclude` no
`pyproject.toml`): os trechos das lições são didáticos, e editar documentação não deveria
quebrar o CI.

---

## 12. Mão na massa

Rode você mesmo, num terminal **PowerShell 7**:

```powershell
cd "C:\Users\gmnas\OneDrive\Documentos\Projetos e ideias\python\pwncheck"
.\.venv\Scripts\Activate.ps1

pytest -v               # esperado: 17 passed
ruff check .            # esperado: All checks passed!
ruff format --check .   # esperado: 9 files already formatted
python -m app.cli       # digite uma senha fraca, como 123456, e depois uma senha forte
```

Depois, abra a pasta no VS Code (`code .`) e rode os testes pelo painel *Testing* (o frasco).
Coloque um breakpoint dentro de `parse_range_response`, rode um teste em modo depuração e
inspecione as variáveis a cada linha.

> **Sobre a codificação do terminal:** ao gerar o diagrama desta lição, um script falhou com
> `UnicodeEncodeError: 'charmap' codec can't encode...`. Com a saída redirecionada (pipe), o
> Python no Windows usa a codificação regional (`cp1252`), que não tem caracteres como `─`.
> A solução foi rodar com a variável `PYTHONUTF8=1`, que liga o *modo UTF-8* do Python. Se
> você vir esse erro, já sabe a causa.

---

## 13. Decisões de design (bom assunto para entrevista)

- **Por que k-anonymity e não "confie em nós"?** Porque privacidade que depende de promessa
  não é garantia. Com k-anonymity, mesmo um serviço mal-intencionado não consegue descobrir a
  senha.
- **Por que injetar o `httpx.Client`?** Testes sem rede, controle de timeout e reaproveitamento
  de conexões (seção 6).
- **Por que falhar alto em respostas estranhas?** Num verificador de segurança, o erro
  perigoso é o *falso negativo*: dizer "senha segura" porque a resposta veio corrompida.
- **Uma questão para a fase 4:** o k-anonymity protege a senha contra a API do HIBP. Mas
  quando existir a *nossa* API web (`POST /check`), o usuário vai mandar a senha para o
  **nosso** servidor. Ela chega por HTTPS e nunca é logada nem salva — mas o usuário
  precisa confiar em nós. Existe um desenho melhor: o próprio navegador calcular o hash e
  mandar só o prefixo, com o nosso servidor funcionando como um *cache* do `/range`. Vamos
  discutir essa troca quando chegarmos lá.

---

## 14. Exercícios

1. **Veja a codificação importar.** Em `kanonymity.py`, troque `"utf-8"` por `"latin-1"` e rode
   `pytest -v`. Qual teste falha, e por quê? Desfaça a alteração.
2. **Veja o teste de segurança funcionar.** Em `check_password`, troque
   `fetch_range(client, prefix)` por `fetch_range(client, prefix + suffix)` — ou seja, envie
   o hash completo. Rode os testes e leia a mensagem de falha do
   `test_somente_o_prefixo_sai_da_maquina`. Desfaça.
3. **Teste um caso novo.** Escreva um teste para `parse_range_response` com uma linha sem
   `:` **no meio** de linhas válidas. Ela deve ser ignorada sem afetar as outras.
4. **Valide prefixos.** Crie `is_valid_prefix(prefix: str) -> bool` em `kanonymity.py`
   (exatamente 5 caracteres, só `0-9` e `A-F`, aceitando minúsculas) e teste com
   `@pytest.mark.parametrize` — casos válidos e inválidos. Ela será útil na fase 4, quando a
   nossa API receber prefixos de fora.
5. **Melhore a CLI.** Faça o `cli.py` verificar várias senhas em sequência, até o usuário
   apertar Enter sem digitar nada.
6. **Desafio: meça o padding.** Num script à parte, use `httpx` e `time.perf_counter()` para
   consultar o prefixo `5BAA6` (da senha `password`) com e sem `Add-Padding` e compare
   quantidade de linhas, bytes e tempo — como fizemos com o `21BD1` na seção 2.

<details>
<summary>Dicas</summary>

1. Falha o `test_sha1_hex_codifica_em_utf8`: em Latin-1, `"é"` vira o byte `E9`, e não os
   bytes `C3 A9`, então o hash muda.
2. Resultado: `1 failed, 16 passed`. O teste falha já no
   `assert request.url.path == f"/range/{PREFIX}"`, e o pytest mostra o caminho que teria sido
   enviado, com o hash inteiro. Se o vazamento fosse mais sutil — o hash num cabeçalho, por
   exemplo —, quem pegaria seria o laço do `everything_sent`.
3. Use um `body` como `f"{PASSWORD_SUFFIX}:7\nlixo\n{OTHER_SUFFIX}:2\n"` e confira o
   dicionário resultante inteiro.
4. `all(c in "0123456789ABCDEF" for c in prefix.upper())` combina bem com `len(prefix) == 5`.
   Casos inválidos que valem a pena: `""`, `"5BAA"`, `"5BAA61"`, `"5BAG6"` e `"5BA 6"`.
5. Um `while True:` com `getpass`, e `break` quando a entrada vier vazia. Crie o
   `httpx.Client` **fora** do laço, para reaproveitar a conexão entre as consultas.

</details>

---

## 15. Próxima fase

**Fase 2 — Política de força de senha.** Não basta a senha não ter vazado: ela precisa ser
forte. Vamos implementar uma política inspirada nas recomendações atuais do NIST
(SP 800-63B): **comprimento acima de complexidade**, sem regras do tipo "uma maiúscula e um
símbolo", e verificação contra listas de senhas vazadas — que já temos. De novo, só funções
puras e testes, e de quebra você vai praticar `dataclass`, `enum` e expressões regulares.
