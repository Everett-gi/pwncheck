"""Tabelas do banco, no estilo declarativo do SQLAlchemy 2 (fase 3).

Cada classe é uma tabela; cada atributo `Mapped[...]` é uma coluna. O tipo Python entre
colchetes diz o que a coluna guarda; `mapped_column(...)` dá os detalhes do lado do banco.
Mudou uma classe aqui? Gere uma migração: alembic revision --autogenerate -m "..."
"""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, String
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
