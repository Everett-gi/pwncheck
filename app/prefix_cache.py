"""Cache das faixas do HIBP no PostgreSQL (fase 3).

Fluxo de get_range(prefixo):
    1. procura o prefixo na tabela prefix_cache;
    2. cópia FRESCA -> devolve sem tocar na rede ("hit");
    3. senão, consulta a API do HIBP e grava a resposta (upsert) -> devolve ("miss");
    4. se a API falhar e houver uma cópia VELHA mas ainda utilizável -> devolve a cópia
       ("stale"); sem cópia utilizável, a exceção sobe: sem dados, não há resposta honesta.

Privacidade: só o PREFIXO chega ao banco. O sufixo é comparado aqui, em Python. Seria mais
"eficiente" pedir ao banco só a contagem do sufixo (suffixes ->> 'ABC...'), mas isso levaria
o hash completo da senha ao servidor de banco — e, potencialmente, aos logs dele.

Transações: estas funções NÃO fazem commit. Quem abriu a sessão decide quando confirmar
(a CLI, os comandos de manutenção e, na fase 4, a API).
"""

import logging
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

import httpx
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.freshness import CachePolicy, Freshness, classify, expiry_cutoff
from app.hibp_client import fetch_range
from app.kanonymity import sha1_hex, split_hash
from app.models import PrefixCache

# Um logger por módulo, nomeado pelo caminho do módulo ("app.prefix_cache").
logger = logging.getLogger(__name__)


class CacheSource(StrEnum):
    """De onde veio a faixa."""

    HIT = "hit"  # cópia fresca do banco
    MISS = "miss"  # buscada agora na API do HIBP
    STALE = "stale"  # cópia velha, usada porque a API falhou


@dataclass(frozen=True, slots=True)
class RangeResult:
    suffixes: dict[str, int]
    source: CacheSource
    fetched_at: datetime


def load_entry(session: Session, prefix: str) -> PrefixCache | None:
    """Busca a cópia de um prefixo pela chave primária (None se não houver).

    `populate_existing=True` força reler do banco mesmo que o objeto já esteja no mapa de
    identidade da sessão — senão, depois de um upsert, veríamos os valores antigos.
    """
    return session.get(PrefixCache, prefix, populate_existing=True)


def save_entry(
    session: Session, prefix: str, suffixes: dict[str, int], fetched_at: datetime
) -> None:
    """Grava a faixa: insere, ou atualiza se o prefixo já existir ("upsert").

    Em SQL: INSERT ... ON CONFLICT (prefix) DO UPDATE SET ... — uma operação ATÔMICA.
    Duas requisições simultâneas para o mesmo prefixo não geram erro de chave duplicada:
    a segunda simplesmente atualiza a linha que a primeira criou.
    """
    statement = insert(PrefixCache).values(prefix=prefix, suffixes=suffixes, fetched_at=fetched_at)
    statement = statement.on_conflict_do_update(
        index_elements=[PrefixCache.prefix],
        # "excluded" é a linha que TENTAMOS inserir e que conflitou.
        set_={"suffixes": statement.excluded.suffixes, "fetched_at": statement.excluded.fetched_at},
    )
    session.execute(statement)


def get_range(
    session: Session,
    client: httpx.Client,
    prefix: str,
    *,
    policy: CachePolicy,
    now: datetime | None = None,
) -> RangeResult:
    """Devolve os sufixos vazados de um prefixo, do cache ou da API (veja o fluxo no topo)."""
    now = now or datetime.now(UTC)
    entry = load_entry(session, prefix)
    freshness = classify(entry.fetched_at, now, policy) if entry else Freshness.EXPIRED

    if entry is not None and freshness is Freshness.FRESH:
        return RangeResult(entry.suffixes, CacheSource.HIT, entry.fetched_at)

    try:
        suffixes = fetch_range(client, prefix)
    except httpx.HTTPError:
        if entry is not None and freshness is Freshness.STALE:
            # Só o prefixo vai para o log: ele não identifica a senha (k-anonymity).
            logger.warning("HIBP indisponível; usando a cópia antiga do prefixo %s", prefix)
            return RangeResult(entry.suffixes, CacheSource.STALE, entry.fetched_at)
        raise  # sem cópia utilizável: o erro sobe para quem chamou

    save_entry(session, prefix, suffixes, now)
    return RangeResult(suffixes, CacheSource.MISS, now)


def check_password_cached(
    session: Session,
    client: httpx.Client,
    password: str,
    *,
    policy: CachePolicy,
    now: datetime | None = None,
) -> tuple[int, CacheSource]:
    """Como hibp_client.check_password, mas passando pelo cache.

    Devolve (nº de vazamentos, origem da faixa).
    """
    prefix, suffix = split_hash(sha1_hex(password))
    result = get_range(session, client, prefix, policy=policy, now=now)
    return result.suffixes.get(suffix, 0), result.source


def cache_stats(session: Session, *, policy: CachePolicy, now: datetime) -> Counter[Freshness]:
    """Conta as cópias por estado (fresca, velha, expirada). Lê só as datas, não os sufixos."""
    dates = session.scalars(select(PrefixCache.fetched_at))
    return Counter(classify(fetched_at, now, policy) for fetched_at in dates)


def purge_expired(session: Session, *, policy: CachePolicy, now: datetime) -> int:
    """Apaga as cópias expiradas e devolve quantas foram apagadas."""
    statement = delete(PrefixCache).where(PrefixCache.fetched_at < expiry_cutoff(now, policy))
    return session.execute(statement).rowcount
