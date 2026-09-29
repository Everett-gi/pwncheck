"""Testes do rate limit e das métricas, de ponta a ponta (HTTP -> banco de verdade)."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.limiter import hit
from app.models import RateLimitCounter, User
from app.ratelimit import Rate, window_start

EMAIL = "limites@exemplo.com"
PASSWORD = "cavalo correto bateria grampo azul"


def login(api, email=EMAIL, password="senha errada"):
    return api.post("/auth/login", json={"email": email, "password": password})


def register_and_login(api, email=EMAIL) -> dict[str, str]:
    body = {"email": email, "password": PASSWORD, "accept_terms": True}
    assert api.post("/auth/register", json=body).status_code == 201
    token = login(api, email=email, password=PASSWORD).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# --- O contador no banco -----------------------------------------------------------------------


def test_hit_conta_de_forma_atomica_e_usa_a_janela_anterior(db_session):
    rate = Rate(3, timedelta(minutes=1))
    now = datetime(2026, 9, 29, 12, 1, 30, tzinfo=UTC)  # metade da janela 12:01
    # 4 requisições na janela anterior: 4 × 0,5 = 2 ainda "pesam" agora.
    db_session.add(
        RateLimitCounter(key="k", window_start=window_start(now, rate.window) - rate.window, hits=4)
    )

    decisions = [hit(db_session, "k", rate, now=now).allowed for _ in range(3)]

    assert decisions == [True, False, False]  # 2 + 1 = 3 cabe; 2 + 2 = 4 não
    counter = db_session.get(RateLimitCounter, ("k", window_start(now, rate.window)))
    assert counter.hits == 3  # as recusadas também contam


# --- 429 nas rotas -----------------------------------------------------------------------------


def test_login_por_ip_responde_429_com_retry_after(make_api):
    api = make_api(rate_limit_login_ip="3/minute", rate_limit_login_email="100/hour")

    statuses = [login(api, email=f"u{i}@exemplo.com").status_code for i in range(4)]

    assert statuses == [401, 401, 401, 429]  # 3 tentativas erradas; a 4ª é barrada
    response = login(api)
    assert response.status_code == 429
    # A espera pode passar de 60 s: as tentativas barradas também contam e "pesam" na
    # janela seguinte. O teto é duas janelas (depois disso, a janela anterior já não pesa).
    assert 1 <= int(response.headers["Retry-After"]) < 120
    assert response.json() == {
        "detail": "Muitas requisições. Espere um pouco antes de tentar de novo."
    }


def test_login_por_email_pega_ataque_distribuido(make_api):
    # Limite por IP alto (o atacante troca de IP), limite por conta baixo.
    api = make_api(rate_limit_login_ip="100/minute", rate_limit_login_email="2/hour")
    assert [login(api).status_code for _ in range(3)] == [401, 401, 429]
    # Outra conta não é afetada.
    assert login(api, email="outra@exemplo.com").status_code == 401


def test_limite_barra_ate_a_senha_certa(make_api):
    """Quem bateu no limite não pode continuar tentando, nem acertando: senão o limite não
    serviria contra força bruta (a senha certa passaria assim que fosse encontrada)."""
    api = make_api(rate_limit_login_email="2/hour")
    register_and_login(api)  # 1 login (certo)
    assert login(api).status_code == 401  # 2º: errado
    assert login(api, password=PASSWORD).status_code == 429  # 3º: certo, mas barrado


def test_check_limita_por_usuario(make_api):
    api = make_api(rate_limit_check_user="2/minute")
    headers = register_and_login(api)
    statuses = [
        api.post("/check", json={"password": "x"}, headers=headers).status_code for _ in range(3)
    ]
    assert statuses == [200, 200, 429]

    # Outro usuário (mesmo IP) tem o próprio contador.
    other = register_and_login(api, email="outro@exemplo.com")
    assert api.post("/check", json={"password": "x"}, headers=other).status_code == 200


def test_check_sem_login_da_401_e_nao_429(make_api):
    api = make_api(rate_limit_check_user="1/minute")
    assert [api.post("/check", json={"password": "x"}).status_code for _ in range(3)] == [401] * 3


def test_range_limita_por_ip(make_api):
    api = make_api(rate_limit_range_ip="2/minute")
    assert [api.get("/range/ABCDE").status_code for _ in range(3)] == [200, 200, 429]


def test_rate_limit_pode_ser_desligado(make_api):
    api = make_api(rate_limit_enabled=False, rate_limit_range_ip="1/minute")
    assert [api.get("/range/ABCDE").status_code for _ in range(3)] == [200, 200, 200]


def test_configuracao_invalida_do_limite(make_settings):
    with pytest.raises(ValueError):
        make_settings(rate_limit_login_ip="muitos por minuto")


def test_limites_lidos_de_variaveis_de_ambiente(make_settings, monkeypatch):
    # Regressão: vindo do AMBIENTE (e não do construtor), "10/minute" era tratado como JSON.
    # monkeypatch.setenv define a variável só durante este teste.
    monkeypatch.setenv("RATE_LIMIT_LOGIN_IP", "7/hour")
    assert make_settings().rate_limit_login_ip == Rate(7, timedelta(hours=1))


# --- Métricas ----------------------------------------------------------------------------------


def make_admin(db_session, email=EMAIL) -> None:
    db_session.scalar(select(User).where(User.email == email)).is_admin = True
    db_session.flush()


def test_metricas_so_para_administradores(api, db_session):
    headers = register_and_login(api)
    assert api.get("/admin/metrics").status_code == 401
    forbidden = api.get("/admin/metrics", headers=headers)
    assert forbidden.status_code == 403
    assert forbidden.json() == {"detail": "Acesso restrito a administradores."}

    make_admin(db_session)
    assert api.get("/admin/metrics", headers=headers).status_code == 200


def test_metricas_contam_o_uso(make_api, db_session, fake_hibp):
    api = make_api(rate_limit_range_ip="3/minute")
    fake_hibp.leaked["P@ssw0rd"] = 10
    headers = register_and_login(api)
    make_admin(db_session)

    api.post("/check", json={"password": "P@ssw0rd"}, headers=headers)  # vazada, cache: miss
    api.post("/check", json={"password": "P@ssw0rd"}, headers=headers)  # vazada, cache: hit
    api.post("/policy", json={"password": "outra frase comprida"}, headers=headers)
    for _ in range(4):
        api.get("/range/21BD1")  # 3 passam (hits), a 4ª é barrada

    report = api.get("/admin/metrics", headers=headers).json()

    today = datetime.now(UTC).date().isoformat()
    assert [day["day"] for day in report["days"]] == [today]
    totals = report["totals"]
    assert totals["checks"] == 2
    assert totals["policies"] == 1
    assert totals["ranges"] == 3
    assert totals["breached"] == 2
    assert totals["registrations"] == 1
    assert totals["rate_limited"] == 1
    # 2 checks (miss, hit) + policy (miss) + 3 ranges (hits: a faixa 21BD1 já está no cache).
    assert (totals["cache_misses"], totals["cache_hits"]) == (2, 4)
    assert report["cache_hit_rate"] == round(4 / 6, 4)


def test_metricas_sem_uso(api, db_session):
    headers = register_and_login(api)
    make_admin(db_session)
    report = api.get("/admin/metrics?days=1", headers=headers).json()
    assert report["totals"]["registrations"] == 1
    assert api.get("/admin/metrics?days=0", headers=headers).status_code == 422
    assert api.get("/admin/metrics?days=91", headers=headers).status_code == 422
