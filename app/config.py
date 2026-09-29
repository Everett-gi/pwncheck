"""Configurações, lidas de variáveis de ambiente (e do arquivo .env, no desenvolvimento).

Nenhum segredo fica no código: a URL do banco (que contém a senha) vem do ambiente.
As classes formam uma escada, e cada ferramenta pede só o degrau de que precisa:

    DatabaseSettings        URL do banco                  <- migrações (Alembic)
      └── CacheSettings     + timeout do HIBP e validade  <- CLI e comandos de manutenção
            │                 do cache
            └── Settings    + segredo dos tokens, limites  <- a API web (fase 4)
"""

from datetime import timedelta

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.freshness import CachePolicy


class DatabaseSettings(BaseSettings):
    """Só o necessário para conectar ao banco."""

    # Cada campo é lido da variável de ambiente de mesmo nome, sem diferenciar maiúsculas
    # (database_url <- DATABASE_URL). Se ela não existir, o .env é consultado. Variáveis
    # desconhecidas no .env são ignoradas (extra="ignore"): o .env é compartilhado com o
    # Docker Compose, que tem as dele.
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # SecretStr esconde o valor em print/log/repr ("**********"). Para usar de verdade:
    # settings.database_url.get_secret_value().
    database_url: SecretStr


class CacheSettings(DatabaseSettings):
    """Banco + consulta ao HIBP + validade do cache de prefixos."""

    hibp_timeout_seconds: float = Field(default=10.0, gt=0)
    # Por quanto tempo uma faixa guardada é usada sem consultar o HIBP de novo.
    cache_ttl_hours: int = Field(default=24, ge=1)
    # Depois do TTL, por quanto tempo a cópia ainda serve SE o HIBP estiver fora do ar.
    cache_stale_if_error_hours: int = Field(default=168, ge=0)

    def cache_policy(self) -> CachePolicy:
        return CachePolicy(
            ttl=timedelta(hours=self.cache_ttl_hours),
            stale_if_error=timedelta(hours=self.cache_stale_if_error_hours),
        )


class Settings(CacheSettings):
    """Tudo o que a API web precisa."""

    # Chave que assina os tokens JWT. Quem a tiver pode fabricar tokens de qualquer usuário:
    # longa, aleatória e só no ambiente. Gere com: python -c "import secrets;
    # print(secrets.token_urlsafe(48))"
    jwt_secret: SecretStr = Field(min_length=32)
    access_token_ttl_minutes: int = Field(default=15, ge=1)
    refresh_token_ttl_days: int = Field(default=7, ge=1)
    # Tamanho máximo do corpo de uma requisição. Nenhum endpoint precisa de mais que isso.
    max_body_bytes: int = Field(default=16 * 1024, ge=1024)
    log_level: str = "INFO"

    def access_token_ttl(self) -> timedelta:
        return timedelta(minutes=self.access_token_ttl_minutes)

    def refresh_token_ttl(self) -> timedelta:
        return timedelta(days=self.refresh_token_ttl_days)
