"""Linha de comando para testar o PwnCheck com a API real (fases 1 a 3).

Uso (dentro da pasta do projeto, com o .venv ativo):
    python -m app.cli             # consulta direto a API do HIBP
    python -m app.cli --cache     # passa pelo cache no PostgreSQL (precisa do banco no ar)
    python -m app.cli --help      # ajuda gerada pelo argparse

A senha é lida sem eco na tela (getpass) e nunca é impressa, logada ou salva.
Não passe senhas como argumento de linha de comando: elas ficam gravadas no
histórico do terminal e visíveis na lista de processos do sistema.
"""

import argparse
import getpass
import sys

import httpx
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.config import CacheSettings
from app.database import create_db_engine
from app.hibp_client import check_password
from app.policy import evaluate_password, format_count
from app.prefix_cache import CacheSource, check_password_cached

# Como explicar ao usuário de onde veio a resposta.
SOURCE_LABELS = {
    CacheSource.HIT: "cache (cópia fresca no PostgreSQL; a API nem foi consultada)",
    CacheSource.MISS: "API do HIBP (a resposta foi gravada no cache)",
    CacheSource.STALE: "cache (cópia antiga: a API do HIBP não respondeu)",
}


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m app.cli",
        description="Verifica se uma senha vazou (k-anonymity) e avalia a política de senha.",
    )
    parser.add_argument(
        "--cache",
        action="store_true",  # sem valor: presente = True, ausente = False
        help="consulta através do cache no PostgreSQL (exige DATABASE_URL e o banco no ar)",
    )
    return parser.parse_args(argv)  # argv=None -> usa sys.argv[1:]


def check_with_cache(password: str) -> tuple[int, CacheSource]:
    """Consulta passando pelo cache e confirma (commit) o que foi gravado."""
    settings = CacheSettings()  # lê DATABASE_URL etc. do ambiente / .env
    engine = create_db_engine(settings.database_url.get_secret_value())
    try:
        with (
            Session(engine) as session,
            httpx.Client(timeout=settings.hibp_timeout_seconds) as client,
        ):
            result = check_password_cached(
                session, client, password, policy=settings.cache_policy()
            )
            session.commit()
            return result
    finally:
        engine.dispose()  # fecha as conexões do pool antes de o programa terminar


def main(argv: list[str] | None = None) -> int:
    """Pergunta a senha, consulta a API e devolve o código de saída do processo."""
    args = parse_args(argv)
    password = getpass.getpass("Senha a verificar (não aparece enquanto você digita): ")
    if not password:
        print("Nenhuma senha informada.")
        return 1

    source = None
    try:
        if args.cache:
            count, source = check_with_cache(password)
        else:
            with httpx.Client(timeout=10.0) as client:
                count = check_password(client, password)
    except ValidationError:
        # A mensagem da validação cita o campo que faltou, nunca o valor dos outros.
        print("Configuração incompleta: defina DATABASE_URL (copie o .env.example para .env).")
        return 1
    except httpx.HTTPError as exc:
        # A URL da mensagem só contém o prefixo do hash, que não é sensível.
        print(f"Falha ao consultar a API: {exc}")
        return 2
    except SQLAlchemyError as exc:
        # Só a primeira linha: o suficiente para o diagnóstico ("connection refused"...).
        print(f"Falha ao acessar o banco (ele está no ar? docker compose ps): {exc}".split("\n")[0])
        return 3

    if count:
        print(f"ALERTA: esta senha apareceu {format_count(count)} vezes em vazamentos. Não use!")
    else:
        print("OK: esta senha não aparece na base de vazamentos conhecidos.")
    if source is not None:
        print(f"Fonte: {SOURCE_LABELS[source]}")

    # Fase 2: a política completa, com a contagem que acabamos de obter.
    result = evaluate_password(password, breach_count=count)
    print(f"\nPolítica de senha (NIST SP 800-63B-4), {result.length} caracteres:")
    if result.accepted:
        print("  Aceita.")
    for violation in result.violations:
        print(f"  - [{violation.rule}] {violation.message}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
