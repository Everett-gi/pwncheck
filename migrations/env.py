"""Ambiente do Alembic: diz a ele COMO conectar e QUAL é o esquema esperado.

Roda a cada comando `alembic ...` (upgrade, downgrade, revision --autogenerate, check).
Diferenças para o arquivo gerado pelo `alembic init`:
    - a URL do banco vem das variáveis de ambiente / .env (DatabaseSettings), nunca de um
      arquivo versionado — ela contém a senha;
    - aceita uma conexão pronta em config.attributes["connection"] (os testes usam isso para
      rodar as migrações na mesma conexão do teste).
"""

import logging

from alembic import context
from sqlalchemy import Connection, create_engine, pool

import app.models  # noqa: F401  (importar registra as tabelas no Base.metadata)
from app.config import DatabaseSettings
from app.database import Base

config = context.config

# O esquema "desejado", descrito pelas classes de app/models.py. O --autogenerate compara
# isto com o banco real para escrever a migração.
target_metadata = Base.metadata

# Sem alembic.ini, não há configuração de log: mostramos as mensagens do Alembic
# ("Running upgrade ...") no terminal. Se quem chamou já configurou o log (pytest), nada muda.
if not logging.getLogger().handlers:
    logging.basicConfig(format="%(levelname)-5.5s [%(name)s] %(message)s")
    logging.getLogger("alembic").setLevel(logging.INFO)


def run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:  # conexão emprestada (testes): não abrimos nem fechamos
        run_migrations(connection)
        return

    url = DatabaseSettings().database_url.get_secret_value()
    # NullPool: sem pool de conexões; um comando de migração usa uma conexão e termina.
    engine = create_engine(url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        run_migrations(connection)


if context.is_offline_mode():
    # Modo offline (alembic upgrade --sql) gera o SQL sem conectar. Não usamos.
    raise SystemExit("Modo offline não suportado: rode as migrações com o banco no ar.")

run_migrations_online()
