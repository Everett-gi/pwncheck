"""Testes das contas do rate limit (funções puras: sem banco, sem rede)."""

import itertools
from datetime import UTC, datetime, timedelta

import pytest

from app.ratelimit import (
    Decision,
    Rate,
    decide,
    elapsed_fraction,
    estimate,
    parse_rate,
    rate_key,
    retry_after,
    window_start,
)

MINUTE = Rate(limit=10, window=timedelta(minutes=1))
NOW = datetime(2026, 9, 29, 12, 1, 15, tzinfo=UTC)  # 25% dentro da janela 12:01


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("10/minute", Rate(10, timedelta(minutes=1))),
        (" 5 / hour ", Rate(5, timedelta(hours=1))),
        ("1/second", Rate(1, timedelta(seconds=1))),
        ("100/day", Rate(100, timedelta(days=1))),
    ],
)
def test_parse_rate(text, expected):
    assert parse_rate(text) == expected


@pytest.mark.parametrize("text", ["", "10", "10/minutes", "dez/minute", "0/minute", "-1/hour"])
def test_parse_rate_recusa_formato_invalido(text):
    with pytest.raises(ValueError):
        parse_rate(text)


def test_window_start_e_fracao():
    assert window_start(NOW, MINUTE.window) == datetime(2026, 9, 29, 12, 1, tzinfo=UTC)
    assert elapsed_fraction(NOW, MINUTE.window) == 0.25
    hour = timedelta(hours=1)
    assert window_start(NOW, hour) == datetime(2026, 9, 29, 12, 0, tzinfo=UTC)


def test_estimativa_do_exemplo_da_documentacao():
    # 8 na janela anterior, 3 na atual, 25% da atual já passou: 8 × 0,75 + 3 = 9.
    assert estimate(previous=8, current=3, fraction=0.25) == 9


def test_a_janela_fixa_deixaria_passar_o_dobro_e_a_deslizante_nao():
    # 10 requisições às 12:00:59 e mais 10 às 12:01:00 (a janela fixa zeraria a contagem).
    just_after = datetime(2026, 9, 29, 12, 1, 0, tzinfo=UTC)
    decision = decide(MINUTE, previous=10, current=10, now=just_after)
    assert not decision.allowed


def test_decide_permite_e_recusa():
    assert decide(MINUTE, previous=8, current=3, now=NOW) == Decision(True, 0)
    blocked = decide(MINUTE, previous=8, current=5, now=NOW)  # 8 × 0,75 + 5 = 11 > 10
    assert blocked == Decision(False, 15)  # às 12:01:30: 8 × 0,5 + 6 = 10, cabe


def _decide_after(rate: Rate, previous: int, current: int, now: datetime, wait: int) -> Decision:
    """Simula uma NOVA requisição `wait` segundos depois, atualizando os contadores."""
    later = now + timedelta(seconds=wait)
    windows_passed = (
        window_start(later, rate.window) - window_start(now, rate.window)
    ) / rate.window
    if windows_passed == 0:
        counts = (previous, current + 1)  # mesma janela: +1 na atual
    elif windows_passed == 1:
        counts = (current, 1)  # a atual virou a anterior
    else:
        counts = (0, 1)  # duas janelas depois: só esta requisição
    return decide(rate, previous=counts[0], current=counts[1], now=later)


def test_retry_after_nunca_mente():
    """Para milhares de situações de bloqueio: esperar o Retry-After basta, e esperar um
    segundo a menos não basta. Um Retry-After errado faria clientes bem-comportados
    baterem de novo no limite."""
    checked = 0
    for limit, window_seconds in [(1, 60), (3, 60), (10, 60), (5, 3600)]:
        rate = Rate(limit, timedelta(seconds=window_seconds))
        for previous, current, offset in itertools.product(
            range(0, 25), range(1, 25), [0, 1, 7, 30, 59]
        ):
            now = datetime(2026, 9, 29, 12, 0, tzinfo=UTC) + timedelta(seconds=offset)
            if decide(rate, previous=previous, current=current, now=now).allowed:
                continue
            wait = retry_after(rate, previous=previous, current=current, now=now)
            assert _decide_after(rate, previous, current, now, wait).allowed
            if wait > 1:
                assert not _decide_after(rate, previous, current, now, wait - 1).allowed
            checked += 1
    assert checked > 1000  # o teste realmente exercitou muitos casos


def test_rate_key_pseudonimiza():
    key = rate_key("login-ip", "203.0.113.7")
    assert key.startswith("login-ip:") and len(key) == len("login-ip:") + 32
    assert "203.0.113.7" not in key
    assert key == rate_key("login-ip", "203.0.113.7")  # determinístico: mesma chave, mesmo IP
    assert key != rate_key("login-email", "203.0.113.7")  # escopos separados
