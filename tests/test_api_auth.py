"""Testes das rotas de autenticação, de ponta a ponta (HTTP -> rota -> banco de verdade)."""

import logging
from datetime import UTC, datetime, timedelta

import pytest
from argon2 import PasswordHasher
from sqlalchemy import func, select, update

from app.models import RefreshToken, User
from app.security import create_access_token, verify_password
from tests.conftest import TEST_JWT_SECRET

EMAIL = "gil.monteiro@exemplo.com"
PASSWORD = "cavalo correto bateria grampo azul"


def register(api, email=EMAIL, password=PASSWORD, accept_terms=True):
    body = {"email": email, "password": password, "accept_terms": accept_terms}
    return api.post("/auth/register", json=body)


def login(api, email=EMAIL, password=PASSWORD):
    return api.post("/auth/login", json={"email": email, "password": password})


def auth_header(access_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}"}


@pytest.fixture
def tokens(api) -> dict:
    """Uma conta cadastrada e logada: devolve o JSON do login (access + refresh)."""
    assert register(api).status_code == 201
    response = login(api)
    assert response.status_code == 200
    return response.json()


# --- Cadastro ----------------------------------------------------------------------------------


def test_cadastro_cria_conta_e_guarda_so_o_hash(api, db_session):
    response = register(api, email="Gil.Monteiro@Exemplo.COM")

    assert response.status_code == 201
    body = response.json()
    assert body["email"] == EMAIL  # normalizado para minúsculas
    assert set(body) == {"id", "email", "is_admin", "created_at"}  # nada de senha ou hash
    user = db_session.scalar(select(User).where(User.email == EMAIL))
    assert user.password_hash.startswith("$argon2id$")
    assert PASSWORD not in user.password_hash
    assert verify_password(user.password_hash, PASSWORD)
    assert user.terms_accepted_at is not None


def test_cadastro_exige_aceitar_os_termos(api):
    response = register(api, accept_terms=False)
    assert response.status_code == 422
    assert response.json()["detail"] == "É preciso aceitar os termos de uso."


def test_cadastro_rejeita_senha_fraca_explicando_os_motivos(api):
    response = register(api, password="Monteiro2025!")

    assert response.status_code == 422
    detail = response.json()["detail"]
    rules = {violation["rule"] for violation in detail["violations"]}
    assert rules == {"too_short", "context"}  # curta e derivada do e-mail
    assert "Monteiro2025!" not in response.text  # a senha não volta na resposta


def test_cadastro_rejeita_senha_vazada(api, fake_hibp):
    fake_hibp.leaked[PASSWORD] = 3  # a frase "forte" apareceu num vazamento
    response = register(api)
    assert response.status_code == 422
    assert [v["rule"] for v in response.json()["detail"]["violations"]] == ["breached"]


def test_cadastro_com_hibp_fora_do_ar_falha_fechado(api, fake_hibp):
    fake_hibp.status = 503
    response = register(api)
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "30"


def test_email_duplicado_mesmo_com_outra_caixa(api):
    assert register(api).status_code == 201
    response = register(api, email=EMAIL.upper())
    assert response.status_code == 409
    assert response.json()["detail"] == "Este e-mail já está cadastrado."


@pytest.mark.parametrize(
    "body",
    [
        {"email": "sem-arroba", "password": PASSWORD, "accept_terms": True},
        {"email": EMAIL, "password": "", "accept_terms": True},
        {"email": EMAIL, "password": PASSWORD},  # falta accept_terms
        {"email": EMAIL, "password": PASSWORD, "accept_terms": True, "is_admin": True},
    ],
    ids=["email-invalido", "senha-vazia", "sem-termos", "campo-extra"],
)
def test_cadastro_valida_o_corpo(api, body):
    # "campo-extra": ninguém vira administrador mandando is_admin (extra="forbid").
    response = api.post("/auth/register", json=body)
    assert response.status_code == 422


# --- Login -------------------------------------------------------------------------------------


def test_login_devolve_tokens_que_funcionam(api, tokens):
    assert tokens["token_type"] == "bearer"
    assert tokens["expires_in"] == 15 * 60
    response = api.get("/auth/me", headers=auth_header(tokens["access_token"]))
    assert response.status_code == 200
    assert response.json()["email"] == EMAIL


def test_login_nao_revela_se_o_email_existe(api):
    assert register(api).status_code == 201
    wrong_password = login(api, password="senha errada")
    unknown_email = login(api, email="ninguem@exemplo.com")
    assert wrong_password.status_code == unknown_email.status_code == 401
    assert wrong_password.json() == unknown_email.json() == {"detail": "E-mail ou senha inválidos."}


def test_login_refaz_hash_com_parametros_antigos(api, db_session):
    weak_hash = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(PASSWORD)
    user = User(email=EMAIL, password_hash=weak_hash, terms_accepted_at=datetime.now(UTC))
    db_session.add(user)
    db_session.flush()

    assert login(api).status_code == 200

    db_session.refresh(user)
    assert user.password_hash != weak_hash
    assert user.password_hash.startswith("$argon2id$v=19$m=65536,t=3,p=4$")


# --- Token de acesso ---------------------------------------------------------------------------


def test_rota_protegida_sem_token(api):
    response = api.get("/auth/me")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "token",
    [
        create_access_token(
            1,
            secret=TEST_JWT_SECRET,
            ttl=timedelta(minutes=1),
            now=datetime(2020, 1, 1, tzinfo=UTC),
        ).token,
        create_access_token(
            1, secret="outra-chave-" * 4, ttl=timedelta(minutes=15), now=datetime.now(UTC)
        ).token,
        "lixo",
    ],
    ids=["expirado", "outra-chave", "lixo"],
)
def test_rota_protegida_com_token_invalido(api, token):
    response = api.get("/auth/me", headers=auth_header(token))
    assert response.status_code == 401
    assert response.json() == {"detail": "Token de acesso inválido ou expirado."}


# --- Refresh: rotação e detecção de reuso ------------------------------------------------------


def refresh(api, refresh_token):
    return api.post("/auth/refresh", json={"refresh_token": refresh_token})


def test_refresh_troca_por_um_par_novo(api, tokens):
    response = refresh(api, tokens["refresh_token"])
    assert response.status_code == 200
    new = response.json()
    assert new["refresh_token"] != tokens["refresh_token"]
    assert api.get("/auth/me", headers=auth_header(new["access_token"])).status_code == 200


def test_reuso_de_refresh_token_revoga_a_sessao_inteira(api, tokens, caplog):
    second = refresh(api, tokens["refresh_token"]).json()  # uso legítimo: R1 -> R2

    with caplog.at_level(logging.WARNING):
        reuse = refresh(api, tokens["refresh_token"])  # R1 de novo: alguém o copiou!
    assert reuse.status_code == 401
    assert "Reuso de refresh token" in caplog.text

    # A família foi revogada: nem o R2, que era legítimo, funciona mais.
    assert refresh(api, second["refresh_token"]).status_code == 401


def test_refresh_expirado(api, tokens, db_session):
    db_session.execute(
        update(RefreshToken).values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
    )
    assert refresh(api, tokens["refresh_token"]).status_code == 401


def test_refresh_desconhecido(api):
    assert refresh(api, "token-que-nunca-existiu").status_code == 401


def test_logout_encerra_a_sessao(api, tokens):
    response = api.post("/auth/logout", json={"refresh_token": tokens["refresh_token"]})
    assert response.status_code == 204
    assert refresh(api, tokens["refresh_token"]).status_code == 401
    # Token desconhecido: 204 também — o logout não confirma nada para quem testa tokens.
    assert api.post("/auth/logout", json={"refresh_token": "x"}).status_code == 204


# --- A própria conta (LGPD) --------------------------------------------------------------------


def test_excluir_conta_exige_a_senha(api, tokens, db_session):
    headers = auth_header(tokens["access_token"])

    wrong = api.request("DELETE", "/auth/me", headers=headers, json={"password": "errada"})
    assert wrong.status_code == 403

    response = api.request("DELETE", "/auth/me", headers=headers, json={"password": PASSWORD})
    assert response.status_code == 204
    assert db_session.scalar(select(func.count()).select_from(User)) == 0
    assert db_session.scalar(select(func.count()).select_from(RefreshToken)) == 0  # CASCADE
    # O token de acesso ainda não expirou, mas o dono não existe mais: 401.
    assert api.get("/auth/me", headers=headers).status_code == 401
    assert refresh(api, tokens["refresh_token"]).status_code == 401


def test_a_senha_nunca_aparece_nos_logs(api, caplog):
    with caplog.at_level(logging.DEBUG):  # até o nível mais detalhado
        register(api)
        login(api)
        login(api, password="senha errada qualquer")
    assert PASSWORD not in caplog.text
    assert "senha errada qualquer" not in caplog.text
