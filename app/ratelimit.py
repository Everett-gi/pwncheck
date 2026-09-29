"""Rate limit por janela deslizante — as contas, sem banco nem rede (fase 5).

O problema da janela FIXA ("10 por minuto, zerando no minuto cheio"): quem manda 10
requisições às 12:00:59 e mais 10 às 12:01:00 faz 20 em dois segundos.

A janela DESLIZANTE aproximada corrige isso com dois contadores — o da janela atual e o da
anterior — e uma média ponderada pelo tempo:

        janela anterior (8)       janela atual (3)
    |─────────────────────────|──────────┬──────────────|
    12:00                     12:01    12:01:15        12:02
                                         └ 25% da janela atual já passou

    estimativa = 8 × (1 − 0,25) + 3 = 9    (os 75% finais da anterior + toda a atual)

É o que a Cloudflare usa em escala. Custa dois contadores por chave, em vez de guardar o
instante de cada requisição.
"""

import hashlib
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from fractions import Fraction

_UNITS = {
    "second": timedelta(seconds=1),
    "minute": timedelta(minutes=1),
    "hour": timedelta(hours=1),
    "day": timedelta(days=1),
}
_RATE_PATTERN = re.compile(r"\s*(\d+)\s*/\s*(second|minute|hour|day)\s*")


@dataclass(frozen=True, slots=True)
class Rate:
    """Um limite: no máximo `limit` requisições por `window`."""

    limit: int
    window: timedelta

    def __post_init__(self) -> None:
        if self.limit < 1 or self.window <= timedelta(0):
            raise ValueError("O limite precisa ser >= 1 e a janela, positiva.")


def parse_rate(text: str | Rate) -> Rate:
    """Lê um limite escrito como "10/minute" (formato usado no .env)."""
    if isinstance(text, Rate):  # já convertido (útil para o Pydantic)
        return text
    match = _RATE_PATTERN.fullmatch(text)
    if match is None:
        raise ValueError(f"Limite inválido: {text!r}. Use o formato '10/minute'.")
    count, unit = match.groups()  # os dois grupos (...) da regex
    return Rate(limit=int(count), window=_UNITS[unit])


_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def window_start(now: datetime, window: timedelta) -> datetime:
    """Início da janela que contém `now`: arredonda para baixo, em múltiplos da janela
    contados desde 1970 — como `ts - ts % n` com um time_t em C.

    `timedelta % timedelta` é conta INTEIRA (em microssegundos): sem os erros de
    arredondamento que um float teria bem na borda da janela.
    """
    return now - (now - _EPOCH) % window


_MICROSECOND = timedelta(microseconds=1)


def elapsed_fraction(now: datetime, window: timedelta) -> Fraction:
    """Quanto da janela atual já passou, de 0 (acabou de começar) a quase 1.

    Devolve uma FRAÇÃO EXATA (numerador/denominador inteiros), não um float. Com float,
    (1 - 59/60 + 0.5) * 60 dá 31.000000000000004 — e o teto disso seria 32, não 31.
    `timedelta // timedelta` é divisão inteira: o número de microssegundos.
    """
    return Fraction((now - _EPOCH) % window // _MICROSECOND, window // _MICROSECOND)


def estimate(previous: int, current: int, fraction: Fraction | float) -> Fraction | float:
    """A contagem estimada na janela deslizante (a média ponderada do topo do arquivo)."""
    return previous * (1 - fraction) + current


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    retry_after: int  # segundos até a próxima requisição caber no limite (0 se permitida)


def decide(rate: Rate, *, previous: int, current: int, now: datetime) -> Decision:
    """Decide se a requisição passa. `current` JÁ INCLUI a requisição sendo decidida.

    Requisições recusadas também contam: quem insiste em bater no limite continua bloqueado
    (e o Retry-After cresce), em vez de ganhar uma tentativa a cada instante.
    """
    fraction = elapsed_fraction(now, rate.window)
    if estimate(previous, current, fraction) <= rate.limit:
        return Decision(allowed=True, retry_after=0)
    return Decision(
        allowed=False, retry_after=retry_after(rate, previous=previous, current=current, now=now)
    )


def retry_after(rate: Rate, *, previous: int, current: int, now: datetime) -> int:
    """Menor espera (em segundos inteiros) para uma NOVA requisição caber no limite.

    Uma nova requisição conta +1 na janela em que chegar. Resolvemos a desigualdade
    "estimativa + 1 <= limite" em dois cenários:
        1. ainda nesta janela, na fração x:  previous·(1−x) + current + 1 <= limite
        2. na próxima janela, na fração y:   current·(1−y) + 1 <= limite
           (a janela atual vira a "anterior"; a nova começa só com esta requisição)
    Duas janelas depois, a conta é só 1 <= limite: sempre cabe.
    """
    window = Fraction(rate.window // _MICROSECOND, 1_000_000)  # em segundos, exato
    fraction = elapsed_fraction(now, rate.window)
    free = rate.limit - current - 1  # vagas que sobram nesta janela para a nova requisição
    if free >= 0 and previous > 0:
        x = 1 - Fraction(free, previous)
        if x < 1:
            return max(1, math.ceil((x - fraction) * window))
    y = max(Fraction(0), 1 - Fraction(rate.limit - 1, current)) if current > 0 else Fraction(0)
    return max(1, math.ceil((1 - fraction + y) * window))


def rate_key(scope: str, identifier: str) -> str:
    """Chave do contador: "login-ip:3f2a...". O IP ou e-mail entra como SHA-256 (truncado).

    É PSEUDONIMIZAÇÃO, não anonimato: um IPv4 tem só 2^32 valores e o hash pode ser
    revertido por força bruta. Mas o banco não guarda o dado em claro, e as linhas são
    apagadas em dois dias (python -m app.manage purge-rate-limits).
    """
    digest = hashlib.sha256(identifier.encode("utf-8")).hexdigest()[:32]
    return f"{scope}:{digest}"
