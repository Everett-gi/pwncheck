"""Rate limit guardado no PostgreSQL (fase 5): as contas vêm de ratelimit.py (puro).

Por que no banco, e não num dicionário em memória? Porque a aplicação pode rodar em vários
processos (workers do uvicorn, ou várias máquinas): cada um teria o próprio dicionário, e o
limite real seria multiplicado. O banco é compartilhado — e já existe (sem Redis).

Cada verificação faz duas consultas: um upsert que INCREMENTA e devolve a contagem da janela
atual (atômico: duas requisições simultâneas recebem contagens diferentes), e uma leitura da
janela anterior.
"""

from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models import RateLimitCounter
from app.ratelimit import Decision, Rate, decide, window_start

# Contadores mais velhos que isso já não influenciam nenhuma decisão (a maior janela
# configurável é de um dia, e só a janela anterior é consultada).
COUNTER_RETENTION = timedelta(days=2)


def hit(session: Session, key: str, rate: Rate, *, now: datetime) -> Decision:
    """Conta uma requisição para `key` e decide se ela passa. Não faz commit."""
    start = window_start(now, rate.window)
    statement = (
        insert(RateLimitCounter)
        .values(key=key, window_start=start, hits=1)
        .on_conflict_do_update(
            index_elements=[RateLimitCounter.key, RateLimitCounter.window_start],
            set_={"hits": RateLimitCounter.hits + 1},  # "hits = rate_limit_counters.hits + 1"
        )
        .returning(RateLimitCounter.hits)  # a contagem DEPOIS do incremento
    )
    current = session.execute(statement).scalar_one()
    previous = session.scalar(
        select(RateLimitCounter.hits).where(
            RateLimitCounter.key == key,
            RateLimitCounter.window_start == start - rate.window,
        )
    )
    return decide(rate, previous=previous or 0, current=current, now=now)


def purge_counters(session: Session, *, now: datetime) -> int:
    """Apaga os contadores antigos e devolve quantos foram apagados."""
    statement = delete(RateLimitCounter).where(
        RateLimitCounter.window_start < now - COUNTER_RETENTION
    )
    return session.execute(statement).rowcount
