"""Rotas de senhas (fases 4 e 5): /check, /policy e /range/{prefixo}.

Dois jeitos de usar o PwnCheck, com níveis diferentes de confiança:

    POST /check           o cliente manda a SENHA (por HTTPS) e confia que não a guardamos.
    GET  /range/{prefixo} o cliente calcula o SHA-1 e manda só o PREFIXO: nós nunca vemos a
                          senha (o mesmo k-anonymity que usamos com o HIBP). É o que a página
                          inicial faz, no navegador.

Cada rota tem um rate limit (fase 5) e registra métricas de uso agregadas por dia.
"""

from datetime import UTC, datetime
from typing import Annotated

import httpx
from fastapi import APIRouter, HTTPException, Path, status
from fastapi.responses import PlainTextResponse

from app import metrics
from app.deps import CurrentUser, DbSession, HibpClient, SettingsDep, limit_by_ip, limit_by_user
from app.policy import MULTI_FACTOR, SINGLE_FACTOR, evaluate_password
from app.prefix_cache import check_password_cached, get_range
from app.schemas import (
    CheckRequest,
    CheckResponse,
    ErrorResponse,
    PolicyRequest,
    PolicyResponse,
    ViolationResponse,
)

router = APIRouter(tags=["senhas"])

# Respostas de erro documentadas no /docs (além das de sucesso).
AUTH_ERRORS = {401: {"model": ErrorResponse, "description": "Sem token, ou token inválido."}}
HIBP_ERRORS = {503: {"model": ErrorResponse, "description": "O HIBP não respondeu."}}
LIMIT_ERRORS = {429: {"model": ErrorResponse, "description": "Limite de requisições atingido."}}


def hibp_unavailable() -> HTTPException:
    """Sem resposta do HIBP e sem cópia utilizável no cache: não há resposta honesta."""
    return HTTPException(
        status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Não foi possível consultar a base de vazamentos agora. Tente de novo em instantes.",
        headers={"Retry-After": "30"},  # "tente de novo daqui a 30 segundos"
    )


@router.post(
    "/check",
    response_model=CheckResponse,
    responses=AUTH_ERRORS | HIBP_ERRORS | LIMIT_ERRORS,
    dependencies=[limit_by_user("check-user", lambda s: s.rate_limit_check_user)],
)
def check(
    body: CheckRequest,
    session: DbSession,
    client: HibpClient,
    settings: SettingsDep,
    user: CurrentUser,
) -> CheckResponse:
    """Diz se a senha apareceu em vazamentos, e quantas vezes.

    A senha chega por HTTPS, é usada só em memória e nunca é gravada nem registrada em log.
    Para não precisar confiar nem nisso, use GET /range/{prefixo}.
    """
    password = body.password.get_secret_value()
    try:
        count, source = check_password_cached(
            session, client, password, policy=settings.cache_policy()
        )
    except httpx.HTTPError:
        raise hibp_unavailable() from None
    metrics.record(
        session,
        datetime.now(UTC).date(),
        checks=1,
        breached=int(count > 0),
        **{metrics.CACHE_COUNTER[source]: 1},  # ex.: cache_hits=1
    )
    session.commit()  # grava a faixa no cache (se veio da API) e as métricas
    return CheckResponse(breached=count > 0, count=count)


@router.post(
    "/policy",
    response_model=PolicyResponse,
    responses=AUTH_ERRORS | HIBP_ERRORS | LIMIT_ERRORS,
    dependencies=[limit_by_user("policy-user", lambda s: s.rate_limit_check_user)],
)
def policy(
    body: PolicyRequest,
    session: DbSession,
    client: HibpClient,
    settings: SettingsDep,
    user: CurrentUser,
) -> PolicyResponse:
    """Avalia a senha contra a política (NIST SP 800-63B-4), incluindo vazamentos.

    `context`: palavras que a senha não deve imitar (o nome de usuário, o e-mail, o nome do
    seu serviço). `mfa`: true se a senha for usada junto com um segundo fator.
    """
    password = body.password.get_secret_value()
    try:
        count, source = check_password_cached(
            session, client, password, policy=settings.cache_policy()
        )
    except httpx.HTTPError:
        raise hibp_unavailable() from None
    metrics.record(
        session,
        datetime.now(UTC).date(),
        policies=1,
        breached=int(count > 0),
        **{metrics.CACHE_COUNTER[source]: 1},
    )
    session.commit()

    result = evaluate_password(
        password,
        config=MULTI_FACTOR if body.mfa else SINGLE_FACTOR,
        context_words=body.context,
        breach_count=count,
    )
    return PolicyResponse(
        accepted=result.accepted,
        length=result.length,
        breach_count=count,
        violations=[ViolationResponse(rule=v.rule, message=v.message) for v in result.violations],
    )


# O prefixo vem na URL: 5 caracteres hexadecimais (maiúsculos ou minúsculos). Um prefixo
# inválido nem chega à função: o FastAPI responde 422 sozinho.
PrefixPath = Annotated[
    str,
    Path(
        pattern=r"^[0-9A-Fa-f]{5}$",
        description="Os 5 primeiros caracteres do SHA-1 da senha.",
        examples=["21BD1"],
    ),
]


RANGE_EXAMPLE = {
    "content": {"text/plain": {"example": "2DC183F740EE76F27B78EB39C8AD972A757:6421042"}}
}


@router.get(
    "/range/{prefix}",
    response_class=PlainTextResponse,
    responses=HIBP_ERRORS | LIMIT_ERRORS | {200: RANGE_EXAMPLE},
    dependencies=[limit_by_ip("range-ip", lambda s: s.rate_limit_range_ip)],
)
def range_(prefix: PrefixPath, session: DbSession, client: HibpClient, settings: SettingsDep):
    """Todos os sufixos vazados que começam com o prefixo, no mesmo formato do HIBP
    ("SUFIXO:CONTAGEM", uma linha por sufixo). Público: não exige login.

    A senha nunca chega aqui: calcule o SHA-1 no cliente, mande só o prefixo e procure o
    seu sufixo na resposta. Nós não temos como saber qual deles é o seu.
    """
    prefix = prefix.upper()
    try:
        result = get_range(session, client, prefix, policy=settings.cache_policy())
    except httpx.HTTPError:
        raise hibp_unavailable() from None
    metrics.record(
        session, datetime.now(UTC).date(), ranges=1, **{metrics.CACHE_COUNTER[result.source]: 1}
    )
    session.commit()
    lines = (f"{suffix}:{count}" for suffix, count in sorted(result.suffixes.items()))
    return PlainTextResponse("\r\n".join(lines))
