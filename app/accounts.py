"""Contas e sessões (fase 4): cadastro, login, renovação com rotação, logout e exclusão.

Como em prefix_cache.py, as funções recebem a Session e NÃO fazem commit: a rota decide.
Erros de negócio viram exceções próprias; a rota as traduz em códigos HTTP.

Rotação de refresh tokens, com detecção de reuso:

    login ──> R1 (família F)
    R1 ──renova──> R2 (R1 marcado como usado)
    R2 ──renova──> R3 (R2 usado)
    R1 de novo?! Alguém copiou um token antigo ──> TODA a família F é revogada
                  (R3 para de funcionar também: o dono legítimo terá de logar de novo)
"""

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import RefreshToken, User
from app.security import (
    burn_password_check_time,
    create_access_token,
    hash_password,
    hash_refresh_token,
    new_refresh_token,
    password_needs_rehash,
    verify_password,
)

logger = logging.getLogger(__name__)


class EmailAlreadyRegisteredError(Exception):
    """Já existe uma conta com este e-mail."""


class InvalidCredentialsError(Exception):
    """E-mail ou senha não conferem (de propósito, sem dizer qual dos dois)."""


class InvalidRefreshTokenError(Exception):
    """Refresh token inexistente, expirado, revogado ou reutilizado."""


class RefreshTokenReuseError(InvalidRefreshTokenError):
    """Um token JÁ USADO apareceu de novo: sinal de roubo. A família foi revogada."""


@dataclass(frozen=True, slots=True)
class TokenConfig:
    """O necessário para emitir tokens (montado a partir das Settings)."""

    secret: str
    access_ttl: timedelta
    refresh_ttl: timedelta


@dataclass(frozen=True, slots=True)
class TokenPair:
    access_token: str
    refresh_token: str
    expires_in: int  # validade do token de acesso, em segundos


def normalize_email(email: str) -> str:
    """E-mails são comparados sem diferenciar maiúsculas: "Gil@X.com" == "gil@x.com"."""
    return email.strip().lower()


def get_user_by_email(session: Session, email: str) -> User | None:
    return session.scalar(select(User).where(User.email == normalize_email(email)))


def create_user(session: Session, *, email: str, password: str, now: datetime) -> User:
    """Cria a conta (a senha já deve ter passado pela política). Guarda só o hash."""
    user = User(
        email=normalize_email(email),
        password_hash=hash_password(password),
        terms_accepted_at=now,
    )
    try:
        # SAVEPOINT: se o INSERT falhar (e-mail duplicado), só este trecho é desfeito, e a
        # sessão continua utilizável. O índice único do banco é quem garante a unicidade,
        # mesmo com dois cadastros simultâneos.
        with session.begin_nested():
            session.add(user)
    except IntegrityError:
        raise EmailAlreadyRegisteredError from None  # "from None": esconde o erro do banco
    return user


def authenticate(session: Session, *, email: str, password: str) -> User:
    """Confere e-mail e senha. Levanta InvalidCredentialsError se não conferirem."""
    user = get_user_by_email(session, email)
    if user is None:
        burn_password_check_time(password)  # mesmo tempo de resposta: não revela o e-mail
        raise InvalidCredentialsError
    if not verify_password(user.password_hash, password):
        raise InvalidCredentialsError
    if password_needs_rehash(user.password_hash):
        # Os parâmetros do Argon2 ficaram mais fortes desde o cadastro: é a única hora em que
        # temos a senha em mãos para refazer o hash.
        user.password_hash = hash_password(password)
    return user


def issue_tokens(
    session: Session,
    user: User,
    *,
    config: TokenConfig,
    now: datetime,
    family_id: uuid.UUID | None = None,
) -> TokenPair:
    """Emite um token de acesso (JWT) e um refresh token (guardado como hash)."""
    refresh = new_refresh_token()
    session.add(
        RefreshToken(
            user_id=user.id,
            family_id=family_id or uuid.uuid4(),  # login = família nova
            token_hash=hash_refresh_token(refresh),
            expires_at=now + config.refresh_ttl,
        )
    )
    access = create_access_token(user.id, secret=config.secret, ttl=config.access_ttl, now=now)
    return TokenPair(access.token, refresh, access.expires_in)


def _find_refresh_token(session: Session, token: str) -> RefreshToken | None:
    return session.scalar(
        select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(token))
    )


def revoke_family(session: Session, family_id: uuid.UUID, *, now: datetime) -> None:
    session.execute(
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now)
    )


def rotate_refresh_token(
    session: Session, token: str, *, config: TokenConfig, now: datetime
) -> TokenPair:
    """Troca um refresh token válido por um par novo, na mesma família."""
    stored = _find_refresh_token(session, token)
    if stored is None or stored.revoked_at is not None or stored.expires_at <= now:
        raise InvalidRefreshTokenError

    # Marca como usado de forma ATÔMICA. "UPDATE ... WHERE used_at IS NULL" só afeta a linha
    # se ninguém a usou antes — nem outra requisição no mesmo instante (o banco serializa as
    # duas). Ler used_at em Python e depois gravar teria uma janela de corrida (TOCTOU).
    claimed = session.execute(
        update(RefreshToken)
        .where(RefreshToken.id == stored.id, RefreshToken.used_at.is_(None))
        .values(used_at=now)
        .returning(RefreshToken.id)
    ).first()
    if claimed is None:
        revoke_family(session, stored.family_id, now=now)
        logger.warning("Reuso de refresh token (usuário %s): sessão revogada.", stored.user_id)
        raise RefreshTokenReuseError

    user = session.get(User, stored.user_id)
    return issue_tokens(session, user, config=config, now=now, family_id=stored.family_id)


def logout(session: Session, token: str, *, now: datetime) -> None:
    """Revoga a família do token (encerra a sessão). Token desconhecido: não faz nada."""
    stored = _find_refresh_token(session, token)
    if stored is not None:
        revoke_family(session, stored.family_id, now=now)


def delete_account(session: Session, user: User) -> None:
    """Apaga a conta (LGPD: direito à exclusão). Os tokens caem junto (ON DELETE CASCADE)."""
    session.delete(user)


# Tokens revogados ficam um tempo no banco, para a auditoria do reuso; depois, são apagados.
REVOKED_TOKEN_RETENTION = timedelta(days=7)


def purge_refresh_tokens(session: Session, *, now: datetime) -> int:
    """Apaga refresh tokens expirados ou revogados há mais de 7 dias. Devolve quantos.

    Tokens usados (rotacionados) mas ainda dentro da validade FICAM: são eles que permitem
    detectar o reuso de um token roubado.
    """
    statement = delete(RefreshToken).where(
        or_(
            RefreshToken.expires_at < now,
            RefreshToken.revoked_at < now - REVOKED_TOKEN_RETENTION,
        )
    )
    return session.execute(statement).rowcount
