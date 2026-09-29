"""Rotas de autenticação (fase 4): cadastro, login, renovação, logout e a própria conta.

POST   /auth/register   cria a conta (a senha passa pela NOSSA política, com o HIBP)
POST   /auth/login      e-mail + senha -> token de acesso (15 min) + refresh token (7 dias)
POST   /auth/refresh    refresh token -> par novo (o antigo deixa de valer: rotação)
POST   /auth/logout     encerra a sessão (revoga a família do refresh token)
GET    /auth/me         os dados da conta (LGPD: direito de acesso)
DELETE /auth/me         apaga a conta, confirmando a senha (LGPD: direito à exclusão)
"""

from datetime import UTC, datetime

import httpx
from fastapi import APIRouter, HTTPException, status

from app import accounts, metrics
from app.deps import (
    CurrentUser,
    DbSession,
    HibpClient,
    SettingsDep,
    TokenConfigDep,
    enforce_rate_limit,
    limit_by_ip,
)
from app.policy import SINGLE_FACTOR, email_context_words, evaluate_password
from app.prefix_cache import check_password_cached
from app.routers.passwords import LIMIT_ERRORS, hibp_unavailable
from app.schemas import (
    DeleteAccountRequest,
    ErrorResponse,
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.security import verify_password

router = APIRouter(prefix="/auth", tags=["autenticação"])

INVALID_CREDENTIALS = "E-mail ou senha inválidos."
INVALID_SESSION = "Sessão inválida ou expirada. Faça login de novo."


def _token_response(pair: accounts.TokenPair) -> TokenResponse:
    return TokenResponse(
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        expires_in=pair.expires_in,
    )


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        409: {"model": ErrorResponse, "description": "E-mail já cadastrado."},
        422: {"description": "Dados inválidos, termos não aceitos ou senha fraca."},
        503: {"model": ErrorResponse, "description": "O HIBP não respondeu."},
    }
    | LIMIT_ERRORS,
    dependencies=[limit_by_ip("register-ip", lambda s: s.rate_limit_register_ip)],
)
def register(
    body: RegisterRequest, session: DbSession, client: HibpClient, settings: SettingsDep
) -> UserResponse:
    """Cria uma conta. A senha precisa passar pela política completa (NIST SP 800-63B-4):
    no mínimo 15 caracteres, fora das listas de senhas comuns e vazadas, e sem derivar do
    e-mail."""
    if not body.accept_terms:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, detail="É preciso aceitar os termos de uso."
        )
    if accounts.get_user_by_email(session, body.email) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Este e-mail já está cadastrado.")

    password = body.password.get_secret_value()
    try:
        breach_count, _ = check_password_cached(
            session, client, password, policy=settings.cache_policy()
        )
    except httpx.HTTPError:
        # Falha fechada: sem a verificação de vazamentos, não aceitamos a senha.
        raise hibp_unavailable() from None
    session.commit()  # guarda a faixa no cache, mesmo que a senha seja rejeitada

    result = evaluate_password(
        password,
        config=SINGLE_FACTOR,
        context_words=email_context_words(body.email),
        breach_count=breach_count,
    )
    if not result.accepted:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "message": "A senha não atende à política de senhas.",
                "violations": [{"rule": v.rule, "message": v.message} for v in result.violations],
            },
        )

    try:
        user = accounts.create_user(
            session, email=body.email, password=password, now=datetime.now(UTC)
        )
    except accounts.EmailAlreadyRegisteredError:  # outro cadastro igual no mesmo instante
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="Este e-mail já está cadastrado."
        ) from None
    metrics.record(session, datetime.now(UTC).date(), registrations=1)
    session.commit()
    return UserResponse.model_validate(user)


@router.post(
    "/login",
    response_model=TokenResponse,
    responses={401: {"model": ErrorResponse, "description": INVALID_CREDENTIALS}} | LIMIT_ERRORS,
    dependencies=[limit_by_ip("login-ip", lambda s: s.rate_limit_login_ip)],
)
def login(
    body: LoginRequest, session: DbSession, config: TokenConfigDep, settings: SettingsDep
) -> TokenResponse:
    """Troca e-mail e senha por um token de acesso e um refresh token.

    Dois limites: por IP (quem tenta muitas contas) e por e-mail (muitos IPs atacando uma
    mesma conta — um ataque distribuído que o limite por IP sozinho não pegaria)."""
    enforce_rate_limit(
        session,
        settings,
        scope="login-email",
        identifier=accounts.normalize_email(body.email),
        rate=settings.rate_limit_login_email,
    )
    try:
        user = accounts.authenticate(
            session, email=body.email, password=body.password.get_secret_value()
        )
    except accounts.InvalidCredentialsError:
        # A mesma mensagem para "e-mail não existe" e "senha errada": não revela quem tem conta.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=INVALID_CREDENTIALS) from None
    pair = accounts.issue_tokens(session, user, config=config, now=datetime.now(UTC))
    session.commit()
    return _token_response(pair)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    responses={401: {"model": ErrorResponse, "description": INVALID_SESSION}} | LIMIT_ERRORS,
    dependencies=[limit_by_ip("refresh-ip", lambda s: s.rate_limit_refresh_ip)],
)
def refresh(body: RefreshRequest, session: DbSession, config: TokenConfigDep) -> TokenResponse:
    """Troca o refresh token por um par novo. O token usado deixa de valer; se ele for
    apresentado de novo, a sessão inteira é revogada (proteção contra token roubado)."""
    try:
        pair = accounts.rotate_refresh_token(
            session, body.refresh_token.get_secret_value(), config=config, now=datetime.now(UTC)
        )
    except accounts.RefreshTokenReuseError:
        session.commit()  # a revogação da família PRECISA ser gravada, mesmo com erro
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=INVALID_SESSION) from None
    except accounts.InvalidRefreshTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=INVALID_SESSION) from None
    session.commit()
    return _token_response(pair)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(body: RefreshRequest, session: DbSession) -> None:
    """Encerra a sessão. Responde 204 mesmo se o token não existir (não confirma nada a
    quem está testando tokens)."""
    accounts.logout(session, body.refresh_token.get_secret_value(), now=datetime.now(UTC))
    session.commit()


@router.get("/me", response_model=UserResponse, responses={401: {"model": ErrorResponse}})
def me(user: CurrentUser) -> UserResponse:
    """Os dados da sua conta — que são só estes (coleta mínima)."""
    return UserResponse.model_validate(user)


@router.delete(
    "/me",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
)
def delete_me(body: DeleteAccountRequest, user: CurrentUser, session: DbSession) -> None:
    """Apaga a sua conta e todas as sessões. Pede a senha de novo: um token de acesso
    roubado não basta para uma ação irreversível."""
    if not verify_password(user.password_hash, body.password.get_secret_value()):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Senha incorreta.")
    accounts.delete_account(session, user)
    session.commit()
