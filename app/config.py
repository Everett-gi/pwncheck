"""Configurações, lidas de variáveis de ambiente (e do arquivo .env, no desenvolvimento).

Nenhum segredo fica no código: a URL do banco (que contém a senha) vem do ambiente.
As classes formam uma escada, e cada ferramenta pede só o degrau de que precisa:

    DatabaseSettings        URL do banco                  <- migrações (Alembic)
      └── CacheSettings     + timeout do HIBP e validade  <- CLI e comandos de manutenção
                              do cache
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
