"""Tabelas do banco, no estilo declarativo do SQLAlchemy 2 (fase 3).

Cada classe é uma tabela; cada atributo `Mapped[...]` é uma coluna. O tipo Python entre
colchetes diz o que a coluna guarda; `mapped_column(...)` dá os detalhes do lado do banco.
Mudou uma classe aqui? Gere uma migração: alembic revision --autogenerate -m "..."
"""

import uuid
from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Identity,
    String,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class PrefixCache(Base):
    """Uma faixa do HIBP guardada localmente: prefixo -> {sufixo: nº de vazamentos}.

    Só o PREFIXO (5 caracteres, compartilhado por ~2 mil hashes) vai para o banco; o sufixo
    da senha consultada nunca é gravado nem enviado em consultas SQL.
    """

    __tablename__ = "prefix_cache"
    __table_args__ = (
        # Validação também no banco: nenhum código com bug consegue gravar um prefixo
        # inválido. "~" é o operador de expressão regular do PostgreSQL.
        CheckConstraint("prefix ~ '^[0-9A-F]{5}$'", name="prefix_hex"),
    )

    prefix: Mapped[str] = mapped_column(String(5), primary_key=True)
    # JSONB: JSON guardado em formato binário, que o PostgreSQL entende e indexa.
    suffixes: Mapped[dict[str, int]] = mapped_column(JSONB)
    # timezone=True -> tipo "timestamptz": o instante é guardado em UTC, sem ambiguidade.
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    def __repr__(self) -> str:
        # Sem as ~2 mil entradas de `suffixes`: um repr enorme inundaria logs e o depurador.
        return f"PrefixCache(prefix={self.prefix!r}, fetched_at={self.fetched_at!r})"


class User(Base):
    """Uma conta. Coleta mínima (LGPD): só o e-mail e o hash da senha — nunca a senha."""

    __tablename__ = "users"

    # BigInteger + Identity: o banco gera o id (1, 2, 3...), como um contador atômico.
    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    # Sempre em minúsculas (quem grava normaliza). "unique" cria um índice único: dois
    # cadastros simultâneos com o mesmo e-mail não passam, mesmo se o código falhar.
    email: Mapped[str] = mapped_column(String(254), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_admin: Mapped[bool] = mapped_column(default=False, server_default=text("false"))
    terms_accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # server_default=func.now(): o PRÓPRIO BANCO preenche com a hora da gravação.
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self) -> str:
        return f"User(id={self.id!r})"  # sem e-mail: dado pessoal não vai para logs


class RefreshToken(Base):
    """Um token de renovação emitido. Guardamos só o HASH dele.

    Tokens de uma mesma sessão de login formam uma FAMÍLIA: cada renovação cria o próximo
    token da família e marca o anterior como usado. Se um token já usado aparecer de novo,
    alguém o copiou — e a família inteira é revogada (detecção de reuso).
    """

    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    # ondelete="CASCADE": apagar o usuário apaga os tokens dele (no próprio banco).
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    family_id: Mapped[uuid.UUID] = mapped_column(index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)  # SHA-256 em hexadecimal
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self) -> str:
        return f"RefreshToken(id={self.id!r}, user_id={self.user_id!r})"


class RateLimitCounter(Base):
    """Um contador do rate limit: quantas requisições uma chave fez numa janela (fase 5).

    Chave primária composta (key, window_start): uma linha por chave por janela. O upsert
    "INSERT ... ON CONFLICT DO UPDATE SET hits = hits + 1" incrementa de forma atômica.
    """

    __tablename__ = "rate_limit_counters"

    key: Mapped[str] = mapped_column(String(80), primary_key=True)  # "login-ip:<sha256>"
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    hits: Mapped[int]


class UsageMetrics(Base):
    """Contadores de uso por dia (fase 5). Só números agregados: nada identifica ninguém.

    A coluna do dia se chama `day`, não `date`: um atributo `date` dentro da classe
    esconderia o tipo `date` importado, nas anotações que viessem depois dele.
    """

    __tablename__ = "usage_metrics"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    day: Mapped[date] = mapped_column(Date, unique=True)
    checks: Mapped[int] = mapped_column(default=0, server_default=text("0"))  # POST /check
    policies: Mapped[int] = mapped_column(default=0, server_default=text("0"))  # POST /policy
    ranges: Mapped[int] = mapped_column(default=0, server_default=text("0"))  # GET /range
    breached: Mapped[int] = mapped_column(default=0, server_default=text("0"))  # achou vazamento
    cache_hits: Mapped[int] = mapped_column(default=0, server_default=text("0"))
    cache_misses: Mapped[int] = mapped_column(default=0, server_default=text("0"))
    cache_stale: Mapped[int] = mapped_column(default=0, server_default=text("0"))
    registrations: Mapped[int] = mapped_column(default=0, server_default=text("0"))
    rate_limited: Mapped[int] = mapped_column(default=0, server_default=text("0"))  # 429s
