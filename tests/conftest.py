"""Fixtures compartilhadas pelos testes (o pytest carrega este arquivo sozinho).

Uma FIXTURE é uma função que prepara algo para os testes; o teste a pede pelo nome do
parâmetro (`def test_x(db_session): ...`) e o pytest a executa antes, injetando o resultado.

Testes que usam `db_session` precisam de um PostgreSQL de verdade, indicado por
TEST_DATABASE_URL (veja o .env.example). Sem a variável, esses testes são PULADOS — exceto
com PWNCHECK_REQUIRE_DB=1 (o CI liga isso), quando FALHAM: um teste que nunca roda não
protege nada.
"""

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import Connection, Engine, create_engine, text
from sqlalchemy.orm import Session

from app.config import Settings
from app.deps import get_db, get_hibp_client
from app.main import create_app
from tests.fakes import FakeHIBP

ROOT = Path(__file__).resolve().parent.parent  # a pasta do projeto


class _TestSettings(BaseSettings):
    """Lê TEST_DATABASE_URL do ambiente ou do .env da raiz do projeto."""

    model_config = SettingsConfigDict(env_file=ROOT / ".env", extra="ignore")
    test_database_url: str | None = None


def alembic_config(connection: Connection) -> Config:
    """Configuração do Alembic que roda as migrações NESTA conexão (veja migrations/env.py)."""
    config = Config(toml_file=ROOT / "pyproject.toml")
    config.attributes["connection"] = connection
    return config


@pytest.fixture(scope="session")  # uma vez por execução do pytest, compartilhada por todos
def db_engine() -> Iterator[Engine]:
    url = _TestSettings().test_database_url
    if not url:
        if os.environ.get("PWNCHECK_REQUIRE_DB") == "1":
            pytest.fail("PWNCHECK_REQUIRE_DB=1, mas TEST_DATABASE_URL não foi definida.")
        pytest.skip("Defina TEST_DATABASE_URL para rodar os testes que usam o banco.")

    engine = create_engine(url)
    with engine.begin() as connection:
        # Começa do zero: apaga o esquema inteiro (tabelas de uma execução anterior, de outro
        # branch...) e recria tudo com as MIGRAÇÕES — assim elas também são testadas.
        connection.execute(text("DROP SCHEMA public CASCADE"))
        connection.execute(text("CREATE SCHEMA public"))
        command.upgrade(alembic_config(connection), "head")
    yield engine  # tudo depois do yield é a "limpeza", que roda no fim da sessão de testes
    engine.dispose()


@pytest.fixture
def db_session(db_engine: Engine) -> Iterator[Session]:
    """Uma sessão cujas alterações são DESFEITAS no fim de cada teste.

    Truque: abrimos uma transação "de fora" e a sessão trabalha dentro dela, usando
    SAVEPOINTs. Até o `session.commit()` do código testado só confirma o savepoint. No fim,
    o rollback da transação de fora apaga tudo, e o próximo teste encontra o banco limpo.
    """
    with db_engine.connect() as connection:
        transaction = connection.begin()
        session = Session(bind=connection, join_transaction_mode="create_savepoint")
        try:
            yield session
        finally:
            session.close()
            transaction.rollback()


# --- Fixtures da API (fase 4) ------------------------------------------------------------------

TEST_JWT_SECRET = "segredo-so-dos-testes-com-mais-de-32-caracteres"


@pytest.fixture
def settings() -> Settings:
    """Configuração dos testes: nada vem do .env (_env_file=None), tudo é fixo."""
    return Settings(
        _env_file=None,
        database_url=_TestSettings().test_database_url or "postgresql+psycopg://sem-banco/x",
        jwt_secret=TEST_JWT_SECRET,
    )


@pytest.fixture
def fake_hibp() -> FakeHIBP:
    """HIBP simulado. Os testes acrescentam senhas "vazadas" em fake_hibp.leaked."""
    return FakeHIBP(leaked={})


@pytest.fixture
def api(db_session: Session, fake_hibp: FakeHIBP, settings: Settings) -> Iterator[TestClient]:
    """Um cliente HTTP falando com a aplicação inteira — rotas, middlewares, validação —
    mas com o banco transacional e o HIBP simulado no lugar das dependências reais."""
    app = create_app(settings)
    hibp_client = fake_hibp.client()
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_hibp_client] = lambda: hibp_client
    with TestClient(app) as client:  # o "with" roda o lifespan (subida e desligamento)
        yield client
