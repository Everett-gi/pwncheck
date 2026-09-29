"""Testes das primitivas de segurança: Argon2, JWT e refresh tokens (sem banco, sem rede)."""

import base64
import json
import string
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from argon2 import PasswordHasher

from app.security import (
    InvalidTokenError,
    create_access_token,
    decode_access_token,
    hash_password,
    hash_refresh_token,
    new_refresh_token,
    password_needs_rehash,
    verify_password,
)

SECRET = "segredo-so-dos-testes-com-mais-de-32-caracteres"
NOW = datetime.now(UTC)  # JWT confere "exp" contra o relógio real: usamos o agora de verdade
TTL = timedelta(minutes=15)


# --- Argon2 ------------------------------------------------------------------------------------


def test_hash_e_argon2id_com_sal_e_nao_contem_a_senha():
    first = hash_password("cavalo correto bateria grampo")
    second = hash_password("cavalo correto bateria grampo")
    assert first.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert first != second  # sal aleatório: mesma senha, hashes diferentes
    assert "cavalo" not in first


def test_verify_password():
    stored = hash_password("cavalo correto bateria grampo")
    assert verify_password(stored, "cavalo correto bateria grampo")
    assert not verify_password(stored, "cavalo correto bateria grampO")


def test_verify_password_normaliza_unicode():
    # Cadastro com "é" composto, login com "e" + acento combinante: é a mesma senha (NFC).
    stored = hash_password("café com pão de queijo")
    assert verify_password(stored, "café com pão de queijo")


def test_verify_password_com_hash_corrompido_devolve_false():
    assert not verify_password("isto-nao-e-um-hash", "qualquer")


def test_hash_com_parametros_antigos_precisa_ser_refeito():
    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash("x")
    assert password_needs_rehash(weak)
    assert not password_needs_rehash(hash_password("x"))


# --- JWT ---------------------------------------------------------------------------------------


def test_token_de_acesso_ida_e_volta():
    access = create_access_token(42, secret=SECRET, ttl=TTL, now=NOW)
    assert access.expires_in == 15 * 60
    assert access.token.count(".") == 2  # header.payload.assinatura
    assert decode_access_token(access.token, secret=SECRET) == 42


def test_payload_do_jwt_e_legivel_por_qualquer_um():
    # Assinado, NÃO cifrado: nada sensível pode ir no payload.
    token = create_access_token(42, secret=SECRET, ttl=TTL, now=NOW).token
    payload_b64 = token.split(".")[1]
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
    assert payload["sub"] == "42"
    assert set(payload) == {"sub", "iss", "iat", "exp", "typ"}


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def _tampered() -> str:
    """Token legítimo com o payload trocado (sub 42 -> 1), mantendo a assinatura original."""
    header, _, signature = create_access_token(42, secret=SECRET, ttl=TTL, now=NOW).token.split(".")
    exp = int((NOW + TTL).timestamp())
    fake = {"sub": "1", "iss": "pwncheck", "iat": int(NOW.timestamp()), "exp": exp}
    return f"{header}.{_b64(fake | {'typ': 'access'})}.{signature}"


def _alg_none() -> str:
    """Token SEM assinatura ("alg": "none") — o ataque clássico contra bibliotecas JWT."""
    payload = {"sub": "1", "iss": "pwncheck", "iat": 0, "exp": 9_999_999_999, "typ": "access"}
    return f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(payload)}."


@pytest.mark.parametrize(
    "token",
    [
        pytest.param(
            create_access_token(1, secret=SECRET, ttl=TTL, now=NOW - timedelta(hours=1)).token,
            id="expirado",
        ),
        pytest.param(
            create_access_token(1, secret="outra-chave-" * 4, ttl=TTL, now=NOW).token,
            id="outra-chave",
        ),
        pytest.param(_tampered(), id="payload-adulterado"),
        pytest.param(_alg_none(), id="alg-none"),
        pytest.param(
            jwt.encode(
                {"sub": "1", "iss": "outro", "iat": NOW, "exp": NOW + TTL, "typ": "access"},
                SECRET,
                algorithm="HS256",
            ),
            id="outro-emissor",
        ),
        pytest.param(
            jwt.encode(
                {"sub": "1", "iss": "pwncheck", "iat": NOW, "exp": NOW + TTL, "typ": "refresh"},
                SECRET,
                algorithm="HS256",
            ),
            id="outro-tipo",
        ),
        pytest.param(
            jwt.encode({"sub": "1", "iss": "pwncheck", "typ": "access"}, SECRET, algorithm="HS256"),
            id="sem-exp",
        ),
        pytest.param("nao.e.jwt", id="lixo"),
    ],
)
def test_tokens_invalidos_sao_recusados(token):
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, secret=SECRET)


# --- Refresh tokens ----------------------------------------------------------------------------


def test_refresh_token_e_aleatorio_e_url_safe():
    tokens = {new_refresh_token() for _ in range(100)}
    assert len(tokens) == 100  # nenhuma repetição
    allowed = set(string.ascii_letters + string.digits + "-_")
    assert all(len(t) == 43 and set(t) <= allowed for t in tokens)  # 32 bytes em base64url


def test_hash_do_refresh_token_e_sha256_deterministico():
    token = new_refresh_token()
    assert hash_refresh_token(token) == hash_refresh_token(token)
    assert len(hash_refresh_token(token)) == 64
    assert token not in hash_refresh_token(token)
