"""Métricas de uso por dia (fase 5): contadores agregados, sem nada que identifique alguém.

Cada evento soma 1 (ou mais) em colunas da linha do dia, com o mesmo upsert atômico do
cache e do rate limit:

    INSERT INTO usage_metrics (day, checks, cache_hits) VALUES ('2026-09-29', 1, 1)
    ON CONFLICT (day) DO UPDATE SET checks = usage_metrics.checks + excluded.checks,
                                    cache_hits = usage_metrics.cache_hits + excluded.cache_hits
"""

from datetime import date, timedelta

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models import UsageMetrics
from app.prefix_cache import CacheSource

# As colunas de contagem, na ordem em que aparecem no relatório.
COUNTERS = (
    "checks",
    "policies",
    "ranges",
    "breached",
    "cache_hits",
    "cache_misses",
    "cache_stale",
    "registrations",
    "rate_limited",
)

# De onde veio a faixa -> qual contador incrementar.
CACHE_COUNTER = {
    CacheSource.HIT: "cache_hits",
    CacheSource.MISS: "cache_misses",
    CacheSource.STALE: "cache_stale",
}


def record(session: Session, day: date, **increments: int) -> None:
    """Soma os incrementos na linha do dia (criando-a se preciso). Não faz commit.

    Ex.: record(session, hoje, checks=1, cache_hits=1)
    `**increments` recolhe os argumentos nomeados num dicionário {"checks": 1, ...}.
    """
    unknown = set(increments) - set(COUNTERS)
    if unknown:
        raise ValueError(f"Contadores desconhecidos: {sorted(unknown)}")
    statement = insert(UsageMetrics).values(day=day, **increments)
    statement = statement.on_conflict_do_update(
        index_elements=[UsageMetrics.day],
        set_={
            name: getattr(UsageMetrics, name) + getattr(statement.excluded, name)
            for name in increments
        },
    )
    session.execute(statement)


def daily_report(session: Session, *, today: date, days: int) -> list[UsageMetrics]:
    """As linhas dos últimos `days` dias (incluindo hoje), da mais recente para a mais antiga.
    Dias sem nenhum evento não têm linha."""
    since = today - timedelta(days=days - 1)
    return list(
        session.scalars(
            select(UsageMetrics).where(UsageMetrics.day >= since).order_by(UsageMetrics.day.desc())
        )
    )
