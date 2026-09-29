"""Dependências das rotas (fase 4): o que o FastAPI injeta em cada requisição.

Uma rota declara do que precisa nos parâmetros, e o FastAPI resolve:

    def check(body: CheckRequest, session: DbSession, user: CurrentUser): ...
                                   │                     └─ get_current_user (que por sua vez
                                   │                        pede o token, a sessão e a config)
                                   └─ get_db: abre uma sessão e a fecha no fim da requisição

É injeção de dependência, como nas fases anteriores — só que automática. Nos testes, basta
trocar uma dependência (app.dependency_overrides) para usar o banco de teste ou a API falsa.
"""

from collections.abc import Iterator
from typing import Annotated

import httpx
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.accounts import TokenConfig
from app.config import Settings
from app.models import User
from app.security import InvalidTokenError, decode_access_token


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_db(request: Request) -> Iterator[Session]:
    """Uma sessão por requisição. O `with` fecha a sessão (e desfaz o que não teve commit)
    quando a requisição termina, com ou sem erro."""
    with request.app.state.session_factory() as session:
        yield session


def get_hibp_client(request: Request) -> httpx.Client:
    """O cliente HTTP do HIBP, criado uma vez na subida da aplicação (conexões reaproveitadas)."""
    return request.app.state.hibp_client


SettingsDep = Annotated[Settings, Depends(get_settings)]
DbSession = Annotated[Session, Depends(get_db)]
HibpClient = Annotated[httpx.Client, Depends(get_hibp_client)]


def get_token_config(settings: SettingsDep) -> TokenConfig:
    return TokenConfig(
        secret=settings.jwt_secret.get_secret_value(),
        access_ttl=settings.access_token_ttl(),
        refresh_ttl=settings.refresh_token_ttl(),
    )


TokenConfigDep = Annotated[TokenConfig, Depends(get_token_config)]

# Lê o cabeçalho "Authorization: Bearer <token>". auto_error=False: nós mesmos respondemos
# 401, com a mensagem em português. Também faz aparecer o botão "Authorize" no /docs.
_bearer = HTTPBearer(auto_error=False, description="Token de acesso obtido em /auth/login.")


def _unauthorized(message: str) -> HTTPException:
    # O cabeçalho WWW-Authenticate é exigido pelo padrão HTTP numa resposta 401.
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED, detail=message, headers={"WWW-Authenticate": "Bearer"}
    )


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    session: DbSession,
    config: TokenConfigDep,
) -> User:
    """O usuário dono do token de acesso. 401 se o token faltar, for inválido ou expirado,
    ou se a conta tiver sido apagada depois que o token foi emitido."""
    if credentials is None:
        raise _unauthorized("Autenticação necessária: envie o token de acesso.")
    try:
        user_id = decode_access_token(credentials.credentials, secret=config.secret)
    except InvalidTokenError:
        raise _unauthorized("Token de acesso inválido ou expirado.") from None
    user = session.get(User, user_id)
    if user is None:
        raise _unauthorized("Token de acesso inválido ou expirado.")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_admin(user: CurrentUser) -> User:
    """Autorização (RBAC simples): só administradores passam. 403 = "sei quem você é, mas
    você não pode"; 401 = "não sei quem você é"."""
    if not user.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Acesso restrito a administradores.")
    return user


AdminUser = Annotated[User, Depends(require_admin)]
