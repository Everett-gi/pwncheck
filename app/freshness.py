"""Regras puras de validade do cache: uma cópia guardada ainda serve? (fase 3)

Como kanonymity.py e policy.py, este módulo não faz rede nem acessa banco: recebe datas e
devolve uma classificação. O relógio ("agora") também entra por parâmetro — ler o relógio
é uma forma de E/S, e um teste não pode depender da hora em que roda.

    idade da cópia:  0 ──────── ttl ──────────── ttl + stale_if_error ──────────>
                     │  FRESH   │      STALE          │        EXPIRED
                     │ usa sem  │ só se o HIBP        │ nunca usa
                     │ consultar│ estiver fora do ar  │
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum


@dataclass(frozen=True, slots=True)
class CachePolicy:
    """Por quanto tempo uma cópia é fresca, e por quanto tempo ainda serve em emergência."""

    ttl: timedelta
    stale_if_error: timedelta


class Freshness(StrEnum):
    FRESH = "fresh"  # dentro do TTL: usa sem consultar a API
    STALE = "stale"  # passou do TTL, mas serve se a API falhar
    EXPIRED = "expired"  # velha demais: nunca usar


def classify(fetched_at: datetime, now: datetime, policy: CachePolicy) -> Freshness:
    """Classifica uma cópia pela idade. As duas datas precisam ter fuso horário.

    Misturar data com fuso ("aware") e sem fuso ("naive") levanta TypeError na subtração —
    o Python se recusa a adivinhar. Aqui tudo é UTC.
    """
    age = now - fetched_at
    if age < policy.ttl:  # idade negativa (relógio adiantado em outro servidor) cai aqui
        return Freshness.FRESH
    if age < policy.ttl + policy.stale_if_error:
        return Freshness.STALE
    return Freshness.EXPIRED


def expiry_cutoff(now: datetime, policy: CachePolicy) -> datetime:
    """Cópias buscadas ANTES deste instante estão expiradas (e podem ser apagadas)."""
    return now - (policy.ttl + policy.stale_if_error)
