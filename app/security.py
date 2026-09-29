"""Primitivas de segurança da autenticação (fase 4): senhas, tokens de acesso e de renovação.

Nada aqui acessa banco ou rede. Três ferramentas diferentes, cada uma para um problema:

    Senha do usuário      -> Argon2id  (LENTO de propósito: atrasa quem tenta adivinhar)
    Token de acesso       -> JWT HS256 (assinado: o servidor confere sem consultar o banco)
    Token de renovação    -> 256 bits aleatórios, guardados como SHA-256 (RÁPIDO basta:
                             ninguém adivinha 2^256 possibilidades)
"""

import functools
import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from app.policy import normalize_password

# --- Senhas: Argon2id ------------------------------------------------------------------------

# Os parâmetros padrão do argon2-cffi seguem a RFC 9106 (perfil de pouca memória):
# 3 passadas, 64 MiB de memória, 4 linhas paralelas. ~50 ms por hash numa CPU atual.
_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Gera o hash para guardar no banco. O sal aleatório vai DENTRO da string:
    $argon2id$v=19$m=65536,t=3,p=4$<sal em base64>$<hash em base64>

    A senha é normalizada (NFC) antes, como o NIST recomenda: assim "é" composto e "é"
    decomposto são a mesma senha no cadastro e no login.
    """
    return _hasher.hash(normalize_password(password))


def verify_password(password_hash: str, password: str) -> bool:
    """Confere a senha. Devolve False (nunca levanta exceção) se não bater."""
    try:
        return _hasher.verify(password_hash, normalize_password(password))
    except (VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    """True se o hash foi feito com parâmetros antigos (mais fracos que os atuais)."""
    return _hasher.check_needs_rehash(password_hash)


@functools.cache
def _dummy_hash() -> str:
    return _hasher.hash("senha-que-ninguem-tem")


def burn_password_check_time(password: str) -> None:
    """Gasta o mesmo tempo de um login de verdade, quando o e-mail não existe.

    Sem isso, "e-mail inexistente" responderia em 1 ms e "senha errada" em 50 ms — e um
    atacante descobriria quais e-mails têm conta só medindo o tempo (ataque de temporização).
    """
    verify_password(_dummy_hash(), password)


# --- Token de acesso: JWT --------------------------------------------------------------------

JWT_ALGORITHM = "HS256"  # HMAC com SHA-256: a mesma chave assina e confere
JWT_ISSUER = "pwncheck"


@dataclass(frozen=True, slots=True)
class AccessToken:
    token: str
    expires_in: int  # segundos até expirar


def create_access_token(user_id: int, *, secret: str, ttl: timedelta, now: datetime) -> AccessToken:
    """Cria um JWT de acesso: header.payload.assinatura, em base64url.

    O payload NÃO é secreto (qualquer um decodifica); ele só não pode ser ALTERADO sem a
    chave. Por isso nada sensível vai nele — só o id do usuário e as datas.
    """
    payload = {
        "sub": str(user_id),  # subject: de quem é o token (o padrão exige texto)
        "iss": JWT_ISSUER,  # issuer: quem emitiu
        "iat": now,  # issued at: quando foi emitido
        "exp": now + ttl,  # expiration: até quando vale
        "typ": "access",  # para não confundir com outros tipos de token no futuro
    }
    token = jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)
    return AccessToken(token=token, expires_in=int(ttl.total_seconds()))


class InvalidTokenError(Exception):
    """Token de acesso inválido, expirado ou adulterado."""


def decode_access_token(token: str, *, secret: str) -> int:
    """Confere assinatura, emissor e validade, e devolve o id do usuário.

    `algorithms=[...]` é OBRIGATÓRIO: sem ele, um atacante poderia mandar um token com
    "alg": "none" (sem assinatura) ou trocar o algoritmo — o clássico ataque de confusão
    de algoritmo em bibliotecas JWT.
    """
    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            options={"require": ["sub", "iss", "iat", "exp"]},
        )
    except jwt.InvalidTokenError as exc:  # assinatura, expiração, formato...
        raise InvalidTokenError(str(exc)) from exc
    if payload.get("typ") != "access" or not str(payload["sub"]).isdigit():
        raise InvalidTokenError("Token de tipo inesperado.")
    return int(payload["sub"])


# --- Token de renovação (refresh) -------------------------------------------------------------


def new_refresh_token() -> str:
    """256 bits do gerador criptográfico do sistema, em base64url (43 caracteres).

    `secrets` usa o gerador do sistema operacional (/dev/urandom, BCryptGenRandom), feito
    para segredos. O módulo `random` NÃO serve: ele é previsível (Mersenne Twister).
    """
    return secrets.token_urlsafe(32)


def hash_refresh_token(token: str) -> str:
    """SHA-256 do token, em hexadecimal: é isto que vai para o banco.

    Se o banco vazar, os hashes não servem para nada: não dá para voltar ao token. E aqui um
    hash RÁPIDO é seguro, ao contrário das senhas: o token tem 256 bits aleatórios, então
    testar possibilidades é inútil, por mais rápido que seja cada teste.
    """
    return hashlib.sha256(token.encode("ascii")).hexdigest()
