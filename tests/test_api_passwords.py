"""Testes das rotas de senhas (/check, /policy, /range) e das proteções HTTP da API."""

import logging

import pytest

from app.kanonymity import sha1_hex, split_hash
from tests.fakes import FILLER_SUFFIX

EMAIL = "usuario.api@exemplo.com"
PASSWORD = "cavalo correto bateria grampo azul"
LEAKED = "P@ssw0rd"  # prefixo 21BD1


@pytest.fixture
def headers(api) -> dict[str, str]:
    """Cabeçalho de autorização de um usuário cadastrado e logado."""
    body = {"email": EMAIL, "password": PASSWORD, "accept_terms": True}
    assert api.post("/auth/register", json=body).status_code == 201
    token = api.post("/auth/login", json={"email": EMAIL, "password": PASSWORD}).json()
    return {"Authorization": f"Bearer {token['access_token']}"}


# --- /check ------------------------------------------------------------------------------------


def test_check_exige_login(api):
    assert api.post("/check", json={"password": LEAKED}).status_code == 401


def test_check_senha_vazada_e_nao_vazada(api, headers, fake_hibp):
    fake_hibp.leaked[LEAKED] = 6421042

    leaked = api.post("/check", json={"password": LEAKED}, headers=headers)
    assert leaked.status_code == 200
    assert leaked.json() == {"breached": True, "count": 6421042}

    safe = api.post("/check", json={"password": "outra frase longa e aleatoria"}, headers=headers)
    assert safe.json() == {"breached": False, "count": 0}


def test_check_so_manda_o_prefixo_ao_hibp_e_usa_o_cache(api, headers, fake_hibp):
    calls_before = fake_hibp.calls
    for _ in range(3):
        api.post("/check", json={"password": LEAKED}, headers=headers)

    assert fake_hibp.calls == calls_before + 1  # uma ida à API; as outras, do cache
    request = fake_hibp.requests[-1]
    prefix, suffix = split_hash(sha1_hex(LEAKED))
    assert request.url.path == f"/range/{prefix}"
    assert suffix not in str(request.url) and LEAKED not in str(request.url)


def test_check_com_hibp_fora_do_ar(api, headers, fake_hibp):
    fake_hibp.status = 503
    response = api.post("/check", json={"password": "algo que nao esta em cache"}, headers=headers)
    assert response.status_code == 503


def test_erro_de_validacao_nao_ecoa_a_senha(api, headers):
    long_password = "segredo-" * 200  # 1.600 caracteres: passa do limite de 1.024
    response = api.post("/check", json={"password": long_password}, headers=headers)

    assert response.status_code == 422
    error = response.json()["detail"][0]
    assert set(error) == {"loc", "type", "msg"}  # sem "input" (o padrão do FastAPI o incluiria)
    assert error["loc"] == ["body", "password"]
    assert "segredo-" not in response.text


# --- /policy -----------------------------------------------------------------------------------


def test_policy_aceita_senha_boa(api, headers):
    response = api.post("/policy", json={"password": PASSWORD}, headers=headers)
    assert response.json() == {
        "accepted": True,
        "length": len(PASSWORD),
        "breach_count": 0,
        "violations": [],
    }


def test_policy_explica_as_violacoes(api, headers, fake_hibp):
    fake_hibp.leaked["gilberto123"] = 10
    body = {"password": "gilberto123", "context": ["gilberto"]}

    response = api.post("/policy", json=body, headers=headers).json()

    assert response["accepted"] is False
    assert response["breach_count"] == 10
    assert [v["rule"] for v in response["violations"]] == ["too_short", "context", "breached"]
    assert all(v["message"] for v in response["violations"])


def test_policy_com_mfa_aceita_8_caracteres(api, headers):
    body = {"password": "kfjwqzmxnvb", "mfa": True}  # 11 caracteres aleatórios
    assert api.post("/policy", json=body, headers=headers).json()["accepted"] is True
    body["mfa"] = False
    assert api.post("/policy", json=body, headers=headers).json()["accepted"] is False


# --- /range ------------------------------------------------------------------------------------


def test_range_e_publico_e_usa_o_formato_do_hibp(api, fake_hibp):
    fake_hibp.leaked[LEAKED] = 6421042
    prefix, suffix = split_hash(sha1_hex(LEAKED))

    response = api.get(f"/range/{prefix.lower()}")  # minúsculas também valem

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert response.text.split("\r\n") == sorted([f"{suffix}:6421042", f"{FILLER_SUFFIX}:1"])
    assert fake_hibp.requests[-1].url.path == f"/range/{prefix}"  # normalizado para maiúsculas


@pytest.mark.parametrize("prefix", ["XYZ12", "1234", "123456", "12 45"])
def test_range_recusa_prefixo_invalido(api, fake_hibp, prefix):
    assert api.get(f"/range/{prefix}").status_code in (404, 422)
    assert fake_hibp.calls == 0  # nem chegou perto do HIBP


def test_range_com_hibp_fora_do_ar(api, fake_hibp):
    fake_hibp.status = 503
    assert api.get("/range/ABCDE").status_code == 503


# --- Proteções HTTP ----------------------------------------------------------------------------


def test_cabecalhos_de_seguranca_na_api(api):
    response = api.get("/health")
    assert response.json() == {"status": "ok"}
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["Cache-Control"] == "no-store"
    assert (
        response.headers["Content-Security-Policy"] == "default-src 'none'; frame-ancestors 'none'"
    )


def test_pagina_inicial_tem_csp_propria_e_docs_nao(api):
    page = api.get("/")
    assert page.status_code == 200
    assert "script-src 'self'" in page.headers["Content-Security-Policy"]
    assert "form-action 'none'" in page.headers["Content-Security-Policy"]
    assert api.get("/static/app.js").status_code == 200
    docs = api.get("/docs")
    assert docs.status_code == 200
    assert "Content-Security-Policy" not in docs.headers  # o Swagger carrega scripts de CDN


def test_corpo_grande_demais_com_content_length(api):
    response = api.post(
        "/check", content=b"a" * 20_000, headers={"content-type": "application/json"}
    )
    assert response.status_code == 413
    assert response.headers["X-Content-Type-Options"] == "nosniff"  # também leva os cabeçalhos


def test_corpo_grande_demais_em_pedacos_sem_content_length(api):
    def chunks():  # "Transfer-Encoding: chunked": o tamanho não é declarado antes
        for _ in range(20):
            yield b"a" * 1_000

    response = api.post("/check", content=chunks(), headers={"content-type": "application/json"})
    assert response.status_code == 413


def test_senha_do_check_nunca_aparece_nos_logs(api, headers, caplog):
    with caplog.at_level(logging.DEBUG):
        api.post("/check", json={"password": LEAKED}, headers=headers)
        api.post("/policy", json={"password": LEAKED}, headers=headers)
    assert LEAKED not in caplog.text
    assert split_hash(sha1_hex(LEAKED))[1] not in caplog.text  # nem o sufixo do hash
