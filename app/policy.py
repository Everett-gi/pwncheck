"""Política de força de senha, baseada no NIST SP 800-63B-4 (seção 3.1.1.2, agosto de 2025).

O que o NIST pede, e o que este módulo faz:
    - COMPRIMENTO acima de complexidade: no mínimo 15 caracteres quando a senha é o único
      fator de autenticação, 8 quando há um segundo fator (MFA); aceitar pelo menos 64.
    - NADA de regras de composição ("uma maiúscula, um número e um símbolo").
    - Comparar a senha INTEIRA com uma lista de bloqueio: senhas comuns ou vazadas e palavras
      do contexto (nome do serviço, do usuário e derivados delas).
    - Sempre informar o MOTIVO da rejeição e orientar o usuário.

Como o kanonymity.py, este módulo é PURO: não faz rede nem acessa banco. A contagem de
vazamentos (que vem da API do HIBP) chega por parâmetro — quem chama faz a E/S. A única
leitura é a da lista de senhas comuns, um arquivo de dados que acompanha o código.
"""

import functools
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from importlib import resources

# O nome do serviço é sempre uma "palavra de contexto" (o NIST cita esse exemplo).
SERVICE_NAME = "pwncheck"

# Padrões só são procurados em trechos com pelo menos 3 caracteres: "ab" não é "sequência".
_MIN_PATTERN_LENGTH = 3


class Rule(StrEnum):
    """Regras que uma senha pode violar. O valor (texto) é o código estável usado na API."""

    TOO_SHORT = "too_short"
    TOO_LONG = "too_long"
    COMMON = "common"
    CONTEXT = "context"
    REPETITIVE = "repetitive"
    SEQUENTIAL = "sequential"
    BREACHED = "breached"


@dataclass(frozen=True, slots=True)
class Violation:
    """Uma regra violada e a explicação para o usuário (o NIST exige dizer o motivo)."""

    rule: Rule
    message: str


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    """Limites de comprimento, em caracteres (code points Unicode, depois da normalização)."""

    min_length: int
    max_length: int = 128

    def __post_init__(self) -> None:
        # Roda logo depois do __init__ gerado pelo @dataclass: valida a configuração.
        if not 1 <= self.min_length <= self.max_length:
            raise ValueError("É preciso ter 1 <= min_length <= max_length.")


# Os dois perfis do NIST: senha como único fator, ou senha + segundo fator (MFA).
SINGLE_FACTOR = PolicyConfig(min_length=15)
MULTI_FACTOR = PolicyConfig(min_length=8)


@dataclass(frozen=True, slots=True)
class PolicyResult:
    """Resultado da avaliação: o comprimento medido e as regras violadas (vazio = aceita)."""

    length: int
    violations: tuple[Violation, ...]

    @property
    def accepted(self) -> bool:
        return not self.violations


def normalize_password(password: str) -> str:
    """Normaliza para NFC, como o NIST recomenda antes de medir ou guardar a senha.

    Um mesmo texto pode chegar em bytes diferentes: "é" pode ser um code point (U+00E9) ou
    dois ("e" + acento combinante U+0301). Sem normalizar, a mesma senha digitada em dois
    teclados diferentes teria comprimentos — e hashes — diferentes.
    """
    return unicodedata.normalize("NFC", password)


def format_count(count: int) -> str:
    """Formata um número no padrão brasileiro: 1234567 -> "1.234.567"."""
    return f"{count:,}".replace(",", ".")


def email_context_words(email: str) -> set[str]:
    """Palavras de contexto de um e-mail: o endereço, a parte antes do @ e seus pedaços.

    "gil.monteiro@exemplo.com" -> {"gil.monteiro@exemplo.com", "gil.monteiro", "gil",
    "monteiro"}. Senhas derivadas delas ("monteiro2025!") serão rejeitadas.
    """
    local_part = email.partition("@")[0]
    pieces = re.split(r"[._+\-]+", local_part)
    return {word for word in (email, local_part, *pieces) if word}


# --- Lista de bloqueio ---------------------------------------------------------------------

# Tabela de tradução "leet speak" -> letra: p@ssw0rd -> password. É uma tabela de consulta
# por caractere, como um array de 256 posições em C indexado pelo próprio char.
_LEET_TABLE = str.maketrans(
    {"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t"}
)

# Tudo o que NÃO é letra, grudado nas pontas: dígitos, pontuação, espaços e "_".
# "\W" = não é caractere de palavra; "\d" = dígito. O "^" e o "$" ancoram nas pontas.
_EDGE_NOISE = re.compile(r"^[\W\d_]+|[\W\d_]+$")


def blocklist_keys(password: str) -> set[str]:
    """Formas da senha comparadas com a lista de bloqueio ("derivados", nas palavras do NIST).

    O NIST manda comparar a senha INTEIRA, não pedaços dela. Então não procuramos "senha"
    dentro de "minhasenhafavorita"; mas tiramos os enfeites óbvios antes de comparar:
        "Password123!" -> {"password123!", "password", "passwordi2ei"}
        "P@ssw0rd"     -> {"p@ssw0rd", "password"}
        "m0nte1r0"     -> {"m0nte1r0", "m0nte1r", "monteir", "monteiro"}
    Formas "estranhas" como "passwordi2ei" não atrapalham: só não casam com nada.
    """
    base = normalize_password(password).casefold()  # casefold: lower() mais agressivo
    trimmed = _EDGE_NOISE.sub("", base)
    # A tradução "leet" é aplicada nas duas formas: com o corte primeiro, "p@ssw0rd1" vira
    # "password"; sem o corte, "m0nte1r0" vira "monteiro" (o corte comeria o "0" final).
    keys = {base, trimmed, base.translate(_LEET_TABLE), trimmed.translate(_LEET_TABLE)}
    keys.discard("")  # uma senha só de dígitos/símbolos vira "" depois do corte
    return keys


@functools.cache  # lê o arquivo uma vez só; as chamadas seguintes devolvem o mesmo objeto
def common_passwords() -> frozenset[str]:
    """Carrega a lista de senhas comuns que acompanha o código (app/data/)."""
    data_file = resources.files("app").joinpath("data", "common-passwords.txt")
    lines = data_file.read_text(encoding="utf-8").splitlines()
    return frozenset(
        line.strip().casefold() for line in lines if line.strip() and not line.startswith("#")
    )


# --- Padrões previsíveis -------------------------------------------------------------------

# Um trecho repetido duas ou mais vezes, ocupando a senha inteira: "abcabcabc", "aaaaaa".
# "(.+?)" captura o trecho (o "?" pede o MENOR possível); "\1" exige repetir exatamente o
# que foi capturado (retrorreferência). DOTALL faz o "." aceitar também quebra de linha.
_REPEATED = re.compile(r"(.+?)\1+", re.DOTALL)

# Sequências óbvias: alfabeto, dígitos e as fileiras do teclado.
_SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm")


def is_repetitive(text: str) -> bool:
    """A senha inteira é um trecho repetido? ("abcabcabc" sim; "abcabcabd" não)."""
    return len(text) >= _MIN_PATTERN_LENGTH and _REPEATED.fullmatch(text) is not None


def is_sequential(text: str) -> bool:
    """A senha inteira é uma sequência (ou sequência circular) em qualquer direção?

    "abcdef", "987654" e "7890123" (dá a volta) são; "abcdeg" não é. O truque: repetir a
    sequência até ela ficar maior que o texto e procurar o texto dentro dela.
    """
    if len(text) < _MIN_PATTERN_LENGTH:
        return False
    for sequence in _SEQUENCES:
        for direction in (sequence, sequence[::-1]):  # [::-1] = invertida
            repeated = direction * (len(text) // len(direction) + 2)
            if text in repeated:
                return True
    return False


# --- Avaliação -----------------------------------------------------------------------------


def evaluate_password(
    password: str,
    *,
    config: PolicyConfig = SINGLE_FACTOR,
    context_words: Iterable[str] = (),
    breach_count: int | None = None,
    blocklist: frozenset[str] | None = None,
) -> PolicyResult:
    """Avalia a senha contra a política e devolve TODAS as regras violadas.

    Args:
        config: limites de comprimento (SINGLE_FACTOR ou MULTI_FACTOR).
        context_words: nome de usuário, e-mail etc. O nome do serviço é sempre incluído.
        breach_count: vezes que a senha apareceu em vazamentos (consultado por quem chama);
            None = não verificado.
        blocklist: lista de senhas comuns; None = a lista que acompanha o código.

    O "*" na assinatura torna os parâmetros seguintes obrigatoriamente nomeados:
    evaluate_password(pw, breach_count=3), nunca evaluate_password(pw, SINGLE_FACTOR, (), 3).
    """
    normalized = normalize_password(password)
    length = len(normalized)  # len() conta code points, não bytes (ao contrário do strlen)

    # Senha longa demais: nem roda o resto. Além de inútil, os padrões com retrorreferência
    # ficam caros em textos enormes (veja a lição sobre ReDoS).
    if length > config.max_length:
        message = f"A senha tem {length} caracteres; o máximo aceito é {config.max_length}."
        return PolicyResult(length, (Violation(Rule.TOO_LONG, message),))

    violations: list[Violation] = []

    if length < config.min_length:
        violations.append(
            Violation(
                Rule.TOO_SHORT,
                f"A senha tem {length} caracteres; o mínimo é {config.min_length}. Dica: uma "
                "frase com quatro ou cinco palavras aleatórias é longa, fácil de lembrar e "
                "difícil de adivinhar.",
            )
        )

    keys = blocklist_keys(normalized)
    words = common_passwords() if blocklist is None else blocklist
    if keys & words:  # "&" entre conjuntos = interseção
        violations.append(
            Violation(
                Rule.COMMON,
                "Esta senha, ou uma variação simples dela, está entre as mais usadas do mundo. "
                "Trocar letras por números ou símbolos, ou acrescentá-los no fim, não a torna "
                "segura.",
            )
        )

    context = {normalize_password(w).casefold() for w in (SERVICE_NAME, *context_words)}
    if keys & context:
        violations.append(
            Violation(
                Rule.CONTEXT,
                "A senha é derivada do nome do serviço, do seu usuário ou do seu e-mail — é das "
                "primeiras coisas que um atacante tenta.",
            )
        )

    # Padrões: na senha como veio e sem os enfeites das pontas ("aaaaaaaa123" -> "aaaaaaaa").
    pattern_candidates = {normalized.casefold(), _EDGE_NOISE.sub("", normalized.casefold())}
    if any(is_repetitive(c) for c in pattern_candidates):
        violations.append(
            Violation(
                Rule.REPETITIVE,
                "A senha é um mesmo trecho repetido (como 'abcabcabc'). Repetir não a torna "
                "mais forte.",
            )
        )
    if any(is_sequential(c) for c in pattern_candidates):
        violations.append(
            Violation(
                Rule.SEQUENTIAL,
                "A senha é uma sequência do alfabeto, de números ou do teclado (como 'abcdef', "
                "'123456' ou 'qwerty').",
            )
        )

    if breach_count:  # None (não verificado) e 0 (não vazou) são falsos
        violations.append(
            Violation(
                Rule.BREACHED,
                f"Esta senha já apareceu {format_count(breach_count)} vezes em vazamentos de "
                "dados. Mesmo que pareça forte, ela está nas listas que os atacantes testam "
                "primeiro.",
            )
        )

    return PolicyResult(length, tuple(violations))
