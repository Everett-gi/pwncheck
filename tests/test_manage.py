"""Testes dos comandos de manutenção (precisam de banco)."""

from datetime import UTC, datetime, timedelta

from app.freshness import CachePolicy
from app.manage import cmd_cache_stats, cmd_purge_cache
from app.prefix_cache import save_entry

POLICY = CachePolicy(ttl=timedelta(hours=24), stale_if_error=timedelta(hours=168))
NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)


def test_cache_stats_mostra_os_tres_estados(db_session):
    save_entry(db_session, "AAAAA", {}, NOW)
    save_entry(db_session, "BBBBB", {}, NOW - timedelta(days=60))

    output = cmd_cache_stats(db_session, POLICY, NOW)

    assert output.splitlines() == [
        "2 faixa(s) no cache:",
        "  fresh    1",
        "  stale    0",
        "  expired  1",
    ]


def test_purge_cache(db_session):
    save_entry(db_session, "AAAAA", {}, NOW)
    save_entry(db_session, "BBBBB", {}, NOW - timedelta(days=60))

    assert cmd_purge_cache(db_session, POLICY, NOW) == "1 faixa(s) expirada(s) apagada(s)."
    assert cmd_purge_cache(db_session, POLICY, NOW) == "0 faixa(s) expirada(s) apagada(s)."
