"""Formatos de entrada e saída da API, validados pelo Pydantic (fase 4).

Cada classe descreve um JSON. O FastAPI usa estas classes para:
    1. VALIDAR o corpo da requisição (tipo, tamanho, formato) antes de chamar a rota;
    2. FILTRAR a resposta (só os campos declarados saem — nada "vaza" por engano);
    3. DOCUMENTAR a API em /docs, automaticamente.

Senhas são SecretStr: não aparecem em print, log ou repr. extra="forbid" rejeita campos
desconhecidos (um erro de digitação no cliente vira 422, em vez de ser ignorado em silêncio).
"""

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr

from app.policy import Rule

# Limites de tamanho: nada de strings gigantes chegando às funções (veja ReDoS, na fase 2).
PasswordField = Annotated[SecretStr, Field(min_length=1, max_length=1024)]
EmailField = Annotated[str, Field(min_length=3, max_length=254)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --- Autenticação ------------------------------------------------------------------------------


class RegisterRequest(StrictModel):
    email: EmailStr = Field(max_length=254)
    password: PasswordField
    accept_terms: bool = Field(description="É preciso aceitar os termos de uso (LGPD).")


class LoginRequest(StrictModel):
    email: EmailField
    password: PasswordField


class RefreshRequest(StrictModel):
    refresh_token: Annotated[SecretStr, Field(min_length=1, max_length=128)]


class DeleteAccountRequest(StrictModel):
    password: PasswordField = Field(description="Confirme a senha para apagar a conta.")


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    # "bearer" é o TIPO do token (RFC 6750: "quem porta o token tem o acesso"), não uma
    # senha. O ruff/bandit (S105) vê "token" + texto fixo e desconfia: falso positivo.
    token_type: str = "bearer"  # noqa: S105
    expires_in: int = Field(description="Validade do token de acesso, em segundos.")


class UserResponse(BaseModel):
    # from_attributes: permite montar a resposta a partir do objeto User do SQLAlchemy.
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    is_admin: bool
    created_at: datetime


# --- Senhas ------------------------------------------------------------------------------------


class CheckRequest(StrictModel):
    password: PasswordField


class CheckResponse(BaseModel):
    breached: bool
    count: int = Field(description="Quantas vezes a senha apareceu em vazamentos.")


class PolicyRequest(StrictModel):
    password: PasswordField
    mfa: bool = Field(
        default=False, description="A senha será usada com um segundo fator? (mínimo 8, não 15)"
    )
    context: list[Annotated[str, Field(max_length=254)]] = Field(
        default_factory=list,
        max_length=20,
        description="Palavras do contexto: nome de usuário, e-mail, nome do seu serviço...",
    )


class ViolationResponse(BaseModel):
    rule: Rule
    message: str


class PolicyResponse(BaseModel):
    accepted: bool
    length: int
    breach_count: int
    violations: list[ViolationResponse]


class ErrorResponse(BaseModel):
    detail: str
