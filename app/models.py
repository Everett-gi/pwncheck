"""Tabelas do banco, no estilo declarativo do SQLAlchemy 2 (fase 3).

Cada classe é uma tabela; cada atributo `Mapped[...]` é uma coluna. O tipo Python entre
colchetes diz o que a coluna guarda; `mapped_column(...)` dá os detalhes do lado do banco.
Mudou uma classe aqui? Gere uma migração: alembic revision --autogenerate -m "..."
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
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
