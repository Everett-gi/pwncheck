"""Comandos de manutenção: python -m app.manage <comando>  (fase 3)

    cache-stats     quantas faixas há no cache, por estado (fresca, velha, expirada)
    purge-cache     apaga as faixas expiradas

Cada comando é uma função que recebe uma sessão e devolve o texto a mostrar. O `main` só
cuida da "fiação": argumentos, configuração, conexão e commit. Assim os comandos são
testáveis com a sessão transacional dos testes.
"""

import argparse
import sys
from collections.abc import Callable
from datetime import UTC, datetime

from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.config import CacheSettings
from app.database import create_db_engine
from app.freshness import CachePolicy, Freshness
from app.prefix_cache import cache_stats, purge_expired

# Assinatura comum dos comandos: (sessão, política, agora) -> texto para o terminal.
Command = Callable[[Session, CachePolicy, datetime], str]


def cmd_cache_stats(session: Session, policy: CachePolicy, now: datetime) -> str:
    stats = cache_stats(session, policy=policy, now=now)
    total = sum(stats.values())
    lines = [f"{total} faixa(s) no cache:"]
    for state in Freshness:  # percorrer um Enum devolve os membros, na ordem da declaração
        lines.append(f"  {state:<8} {stats[state]}")  # Counter devolve 0 para o que falta
    return "\n".join(lines)


def cmd_purge_cache(session: Session, policy: CachePolicy, now: datetime) -> str:
    deleted = purge_expired(session, policy=policy, now=now)
    return f"{deleted} faixa(s) expirada(s) apagada(s)."


COMMANDS: dict[str, tuple[Command, str]] = {
    "cache-stats": (cmd_cache_stats, "mostra quantas faixas há no cache, por estado"),
    "purge-cache": (cmd_purge_cache, "apaga as faixas expiradas do cache"),
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m app.manage", description="Comandos de manutenção do PwnCheck."
    )
    subparsers = parser.add_subparsers(dest="command", required=True, metavar="comando")
    for name, (_, help_text) in COMMANDS.items():
        subparsers.add_parser(name, help=help_text)
    args = parser.parse_args(argv)

    try:
        settings = CacheSettings()
    except ValidationError:
        print("Configuração incompleta: defina DATABASE_URL (copie o .env.example para .env).")
        return 1

    command, _ = COMMANDS[args.command]
    engine = create_db_engine(settings.database_url.get_secret_value())
    try:
        with Session(engine) as session:
            output = command(session, settings.cache_policy(), datetime.now(UTC))
            session.commit()
    finally:
        engine.dispose()
    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
