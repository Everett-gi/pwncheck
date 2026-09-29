"""Conexão com o PostgreSQL via SQLAlchemy 2 (fase 3).

Três peças, da mais baixa para a mais alta:

    Engine          o "motor": guarda a URL e um POOL de conexões abertas, reaproveitadas
                    entre requisições (abrir conexão TCP + autenticar custa caro).
    sessionmaker    a fábrica de sessões, configurada uma vez.
    Session         uma "conversa" com o banco: agrupa operações numa transação e mantém
                    o mapa de identidade (cada linha carregada vira UM objeto Python).
"""

from sqlalchemy import Engine, MetaData, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

# Nomes previsíveis para índices e restrições (constraints). Sem isso, o PostgreSQL inventa
# nomes, e o Alembic não consegue apagá-los numa migração futura sem saber como se chamam.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Classe-mãe de todas as tabelas. O `metadata` é o catálogo com o esquema inteiro."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def create_db_engine(url: str) -> Engine:
    """Cria o Engine. `pool_pre_ping` testa a conexão antes de usá-la (evita erro com
    conexões que o banco derrubou por ociosidade)."""
    return create_engine(url, pool_pre_ping=True)


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Fábrica de sessões. `expire_on_commit=False` mantém os atributos dos objetos
    carregados depois do commit (senão, lê-los de novo dispararia outra consulta)."""
    return sessionmaker(bind=engine, expire_on_commit=False)
