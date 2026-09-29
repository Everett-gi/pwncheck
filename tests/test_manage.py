"""Testes dos comandos de manutenção (precisam de banco)."""

import argparse
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from app.freshness import CachePolicy
from app.manage import (
    CommandError,
    Context,
    build_parser,
    cmd_cache_stats,
    cmd_maintenance,
    cmd_make_admin,
    cmd_purge_cache,
    cmd_purge_refresh_tokens,
)
from app.models import RateLimitCounter, RefreshToken, User
from app.prefix_cache import save_entry

POLICY = CachePolicy(ttl=timedelta(hours=24), stale_if_error=timedelta(hours=168))
NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)


def context(db_session, *argv: str) -> Context:
    args = build_parser().parse_args(argv) if argv else argparse.Namespace()
    return Context(db_session, POLICY, NOW, args)


def test_cache_stats_mostra_os_tres_estados(db_session):
    save_entry(db_session, "AAAAA", {}, NOW)
    save_entry(db_session, "BBBBB", {}, NOW - timedelta(days=60))

    assert cmd_cache_stats(context(db_session)).splitlines() == [
        "2 faixa(s) no cache:",
        "  fresh    1",
        "  stale    0",
        "  expired  1",
    ]


def test_purge_cache(db_session):
    save_entry(db_session, "AAAAA", {}, NOW)
    save_entry(db_session, "BBBBB", {}, NOW - timedelta(days=60))

    assert cmd_purge_cache(context(db_session)) == "1 faixa(s) expirada(s) apagada(s)."
    assert cmd_purge_cache(context(db_session)) == "0 faixa(s) expirada(s) apagada(s)."


def _user(db_session, email="admin@exemplo.com") -> User:
    user = User(email=email, password_hash="x", terms_accepted_at=NOW)
    db_session.add(user)
    db_session.flush()
    return user


def test_make_admin_e_revoke(db_session):
    user = _user(db_session)

    assert cmd_make_admin(context(db_session, "make-admin", "Admin@Exemplo.com")) == (
        "admin@exemplo.com agora é administrador."
    )
    assert user.is_admin is True

    cmd_make_admin(context(db_session, "make-admin", "admin@exemplo.com", "--revoke"))
    assert user.is_admin is False


def test_make_admin_email_inexistente(db_session):
    with pytest.raises(CommandError):
        cmd_make_admin(context(db_session, "make-admin", "ninguem@exemplo.com"))


def test_purge_refresh_tokens_mantem_os_que_ainda_detectam_reuso(db_session):
    user = _user(db_session)
    family = uuid.uuid4()

    def token(name: str, **fields) -> None:
        values = {"expires_at": NOW + timedelta(days=1)} | fields
        db_session.add(RefreshToken(user_id=user.id, family_id=family, token_hash=name, **values))

    token("valido")
    token("usado-e-valido", used_at=NOW - timedelta(hours=1))  # fica: detecta reuso
    token("expirado", expires_at=NOW - timedelta(seconds=1))
    token("revogado-antigo", revoked_at=NOW - timedelta(days=8))
    token("revogado-recente", revoked_at=NOW - timedelta(days=1))  # fica: auditoria
    db_session.flush()

    assert cmd_purge_refresh_tokens(context(db_session)) == "2 refresh token(s) apagado(s)."
    remaining = set(db_session.scalars(select(RefreshToken.token_hash)))
    assert remaining == {"valido", "usado-e-valido", "revogado-recente"}


def test_maintenance_roda_as_tres_limpezas(db_session):
    save_entry(db_session, "BBBBB", {}, NOW - timedelta(days=60))
    db_session.add(RateLimitCounter(key="x", window_start=NOW - timedelta(days=3), hits=5))
    db_session.add(RateLimitCounter(key="y", window_start=NOW, hits=1))
    db_session.flush()

    assert cmd_maintenance(context(db_session)).splitlines() == [
        "1 faixa(s) expirada(s) apagada(s).",
        "1 contador(es) de rate limit apagado(s).",
        "0 refresh token(s) apagado(s).",
    ]
    assert db_session.scalar(select(func.count()).select_from(RateLimitCounter)) == 1
