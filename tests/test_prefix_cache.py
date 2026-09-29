"""Testes do cache de prefixos com um PostgreSQL DE VERDADE e a API do HIBP SIMULADA.

Por que banco de verdade, e não um mock? Porque o que queremos testar é justamente o que o
banco faz: o upsert (ON CONFLICT), o JSONB, a restrição CHECK, as datas com fuso. Um mock
só confirmaria que chamamos as funções que achamos que deveríamos chamar.
"""

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import event, func, select
from sqlalchemy.exc import IntegrityError

from app.freshness import CachePolicy, Freshness
from app.kanonymity import sha1_hex, split_hash
from app.models import PrefixCache
from app.prefix_cache import (
    CacheSource,
    cache_stats,
    check_password_cached,
    get_range,
    load_entry,
    purge_expired,
    save_entry,
)
from tests.fakes import FakeHIBP

POLICY = CachePolicy(ttl=timedelta(hours=24), stale_if_error=timedelta(hours=168))
NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)

PASSWORD = "password"
PREFIX, SUFFIX = split_hash(sha1_hex(PASSWORD))  # 5BAA6 / 1E4C9B93F3F0682250B6CF8331B7EE68FD8
# Outra senha com o MESMO prefixo (achada por força bruta e conferida com o sha1sum):
#   printf 'outra-senha-315727' | sha1sum  ->  5baa6e406facb04632ffcc0efea7577d7836bdb7
SAME_PREFIX_PASSWORD = "outra-senha-315727"
OTHER_SUFFIX = "E406FACB04632FFCC0EFEA7577D7836BDB7"
RANGE_BODY = f"{SUFFIX}:42\r\n011053FD0102E94D6AE2F8B83D76FAF94F6:3\r\n"

pytestmark = pytest.mark.usefixtures("db_session")  # todos os testes deste arquivo usam banco


def test_primeira_consulta_busca_na_api_e_a_segunda_vem_do_cache(db_session):
    api = FakeHIBP(RANGE_BODY)
    client = api.client()

    first = get_range(db_session, client, PREFIX, policy=POLICY, now=NOW)
    assert first.source is CacheSource.MISS
    assert first.suffixes[SUFFIX] == 42

    second = get_range(db_session, client, PREFIX, policy=POLICY, now=NOW + timedelta(hours=1))
    assert second.source is CacheSource.HIT
    assert second.suffixes == first.suffixes
    assert api.calls == 1  # a segunda não tocou na rede


def test_copia_velha_e_renovada_quando_a_api_responde(db_session):
    save_entry(db_session, PREFIX, {SUFFIX: 1}, NOW - timedelta(hours=30))  # passou do TTL
    api = FakeHIBP(RANGE_BODY)

    result = get_range(db_session, api.client(), PREFIX, policy=POLICY, now=NOW)

    assert result.source is CacheSource.MISS
    assert result.suffixes[SUFFIX] == 42  # dado novo
    assert load_entry(db_session, PREFIX).fetched_at == NOW  # e gravado
    assert api.calls == 1


def test_upsert_nao_deixa_objeto_desatualizado_na_sessao(db_session):
    """Regressão: o upsert (Core) muda o banco sem avisar os objetos que a sessão já tem.

    O mapa de identidade guarda referências FRACAS: enquanto alguém segura o objeto (aqui,
    `held`), ele continua no mapa, com os valores antigos. Sem o populate_existing de
    load_entry, a segunda consulta veria a data velha e chamaria a API de novo.
    """
    save_entry(db_session, PREFIX, {SUFFIX: 1}, NOW - timedelta(hours=30))
    held = load_entry(db_session, PREFIX)  # referência forte: mantém o objeto no mapa
    api = FakeHIBP(RANGE_BODY)
    client = api.client()

    assert get_range(db_session, client, PREFIX, policy=POLICY, now=NOW).source is CacheSource.MISS
    later = NOW + timedelta(hours=1)
    assert get_range(db_session, client, PREFIX, policy=POLICY, now=later).source is CacheSource.HIT
    assert api.calls == 1
    assert held.fetched_at == NOW  # o próprio objeto foi atualizado


def test_copia_velha_serve_se_a_api_falhar(db_session, caplog):
    save_entry(db_session, PREFIX, {SUFFIX: 7}, NOW - timedelta(hours=30))
    api = FakeHIBP(status=503)

    with caplog.at_level(logging.WARNING):  # caplog: fixture do pytest que captura os logs
        result = get_range(db_session, api.client(), PREFIX, policy=POLICY, now=NOW)

    assert result.source is CacheSource.STALE
    assert result.suffixes == {SUFFIX: 7}
    assert PREFIX in caplog.text  # o aviso cita o prefixo...
    assert SUFFIX not in caplog.text  # ...e nada além dele


@pytest.mark.parametrize("age", [None, timedelta(days=30)])  # sem cópia / cópia expirada
def test_sem_copia_utilizavel_o_erro_da_api_sobe(db_session, age):
    if age is not None:
        save_entry(db_session, PREFIX, {SUFFIX: 7}, NOW - age)
    with pytest.raises(httpx.HTTPStatusError):
        get_range(db_session, FakeHIBP(status=503).client(), PREFIX, policy=POLICY, now=NOW)


def test_save_entry_e_um_upsert(db_session):
    save_entry(db_session, PREFIX, {SUFFIX: 1}, NOW - timedelta(days=1))
    save_entry(db_session, PREFIX, {SUFFIX: 2}, NOW)  # mesmo prefixo: atualiza, não duplica

    assert db_session.scalar(select(func.count()).select_from(PrefixCache)) == 1
    entry = load_entry(db_session, PREFIX)
    assert entry.suffixes == {SUFFIX: 2}
    assert entry.fetched_at == NOW


@pytest.mark.parametrize("invalid", ["5baa6", "5BAG6", "5BAA", "5BAA61"])
def test_banco_recusa_prefixo_invalido(db_session, invalid):
    # A restrição CHECK é a última linha de defesa, mesmo que o código tenha um bug.
    # (Com 6 caracteres, quem recusa é o VARCHAR(5) — outro erro, mas também do banco.)
    with pytest.raises(Exception) as error:
        save_entry(db_session, invalid, {}, NOW)
        db_session.flush()
    assert isinstance(error.value, IntegrityError) or "too long" in str(error.value)


def test_check_password_cached(db_session):
    client = FakeHIBP(RANGE_BODY).client()
    assert check_password_cached(db_session, client, PASSWORD, policy=POLICY, now=NOW) == (
        42,
        CacheSource.MISS,
    )
    # A outra senha tem o mesmo prefixo: a faixa já está no cache, e ela não vazou.
    assert check_password_cached(
        db_session, client, SAME_PREFIX_PASSWORD, policy=POLICY, now=NOW
    ) == (0, CacheSource.HIT)


@contextmanager
def record_sql(db_session) -> Iterator[list[tuple[str, dict]]]:
    """Liga um "grampo" na conexão enquanto o bloco `with` roda: guarda cada comando SQL.

    @contextmanager transforma este gerador num gerenciador de contexto: o código antes do
    `yield` roda na entrada do `with`; o do `finally`, na saída (com ou sem exceção) — como
    construtor e destrutor no RAII do C++.
    """
    statements: list[tuple[str, dict]] = []
    connection = db_session.connection()

    def capture(conn, cursor, statement, parameters, context, executemany):
        if "prefix_cache" in statement:  # ignora SAVEPOINT/RELEASE da fixture
            # O psycopg embrulha o JSON num objeto Jsonb, que não sabe se comparar com "==";
            # desembrulhamos (.obj) para comparar o CONTEÚDO enviado.
            values = {key: getattr(value, "obj", value) for key, value in parameters.items()}
            statements.append((statement, values))

    event.listen(connection, "before_cursor_execute", capture)
    try:
        yield statements
    finally:
        event.remove(connection, "before_cursor_execute", capture)


def test_o_banco_nao_consegue_distinguir_senhas_com_o_mesmo_prefixo(db_session):
    """O k-anonymity vale também para o NOSSO banco: tudo o que chega a ele depende só do
    prefixo. Duas senhas diferentes com o mesmo prefixo geram exatamente os mesmos comandos
    SQL, com os mesmos parâmetros."""
    assert split_hash(sha1_hex(SAME_PREFIX_PASSWORD))[0] == PREFIX

    recordings = []
    for password in (PASSWORD, SAME_PREFIX_PASSWORD):
        savepoint = db_session.begin_nested()  # cada senha começa com o cache vazio
        with record_sql(db_session) as statements:
            client = FakeHIBP(RANGE_BODY).client()
            check_password_cached(db_session, client, password, policy=POLICY, now=NOW)
        recordings.append(statements)
        savepoint.rollback()

    assert recordings[0] == recordings[1]
    assert len(recordings[0]) == 2  # um SELECT (cache vazio) e um INSERT ... ON CONFLICT
    sql_text = " ".join(statement for statement, _ in recordings[0])
    assert OTHER_SUFFIX not in sql_text and SUFFIX not in sql_text


def test_consulta_com_cache_quente_so_envia_o_prefixo(db_session):
    save_entry(db_session, PREFIX, {SUFFIX: 42}, NOW)

    with record_sql(db_session) as statements:
        check_password_cached(
            db_session, FakeHIBP(RANGE_BODY).client(), PASSWORD, policy=POLICY, now=NOW
        )

    assert len(statements) == 1  # só o SELECT
    _, parameters = statements[0]
    assert list(parameters.values()) == [PREFIX]


def test_cache_stats_e_purge_expired(db_session):
    save_entry(db_session, "00000", {}, NOW - timedelta(hours=1))  # fresca
    save_entry(db_session, "11111", {}, NOW - timedelta(hours=30))  # velha
    save_entry(db_session, "22222", {}, NOW - timedelta(days=30))  # expirada
    save_entry(db_session, "33333", {}, NOW - timedelta(days=60))  # expirada

    stats = cache_stats(db_session, policy=POLICY, now=NOW)
    assert stats == {Freshness.FRESH: 1, Freshness.STALE: 1, Freshness.EXPIRED: 2}

    assert purge_expired(db_session, policy=POLICY, now=NOW) == 2
    remaining = set(db_session.scalars(select(PrefixCache.prefix)))
    assert remaining == {"00000", "11111"}
