"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
${imports if imports else ""}

# Identificadores usados pelo Alembic para montar a corrente de migrações.
revision: str = ${repr(up_revision)}
down_revision: str | Sequence[str] | None = ${repr(down_revision)}
branch_labels: str | Sequence[str] | None = ${repr(branch_labels)}
depends_on: str | Sequence[str] | None = ${repr(depends_on)}


def upgrade() -> None:
    """Aplica a migração (avança o esquema)."""
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    """Desfaz a migração (volta o esquema ao estado anterior)."""
    ${downgrades if downgrades else "pass"}
