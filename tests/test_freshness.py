"""Testes das regras de validade do cache (funções puras: sem rede, sem banco)."""

from datetime import UTC, datetime, timedelta

import pytest

from app.freshness import CachePolicy, Freshness, classify, expiry_cutoff

POLICY = CachePolicy(ttl=timedelta(hours=24), stale_if_error=timedelta(hours=168))
NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)  # "agora" fixo: o teste não depende do relógio
SECOND = timedelta(seconds=1)


@pytest.mark.parametrize(
    ("age", "expected"),
    [
        (timedelta(0), Freshness.FRESH),
        (POLICY.ttl - SECOND, Freshness.FRESH),  # a borda: um segundo antes do TTL
        (POLICY.ttl, Freshness.STALE),  # exatamente no TTL já não é fresca
        (POLICY.ttl + POLICY.stale_if_error - SECOND, Freshness.STALE),
        (POLICY.ttl + POLICY.stale_if_error, Freshness.EXPIRED),
        (timedelta(days=365), Freshness.EXPIRED),
        (-timedelta(minutes=5), Freshness.FRESH),  # relógio de outro servidor adiantado
    ],
)
def test_classify_pelas_bordas(age, expected):
    assert classify(NOW - age, NOW, POLICY) is expected


def test_sem_janela_de_emergencia_passa_direto_para_expirada():
    policy = CachePolicy(ttl=timedelta(hours=1), stale_if_error=timedelta(0))
    assert classify(NOW - timedelta(hours=1), NOW, policy) is Freshness.EXPIRED


def test_misturar_data_com_e_sem_fuso_e_erro():
    naive = datetime(2026, 9, 29, 12, 0)  # sem tzinfo: "naive"
    with pytest.raises(TypeError):
        classify(naive, NOW, POLICY)


def test_expiry_cutoff():
    assert expiry_cutoff(NOW, POLICY) == NOW - timedelta(hours=24 + 168)
    # Coerência entre as duas funções: exatamente no corte, a cópia está expirada.
    assert classify(expiry_cutoff(NOW, POLICY), NOW, POLICY) is Freshness.EXPIRED
