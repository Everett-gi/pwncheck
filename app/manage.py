"""Comandos de manutenção (fases 3 e 5): python -m app.manage <comando>

    cache-stats             quantas faixas há no cache, por estado (fresca, velha, expirada)
    purge-cache             apaga as faixas expiradas
    purge-rate-limits       apaga contadores de rate limit que já não influenciam nada
    purge-refresh-tokens    apaga refresh tokens expirados ou revogados há mais de 7 dias
    maintenance             as três limpezas de uma vez (para o cron do servidor)
    make-admin EMAIL        dá (ou, com --revoke, tira) o papel de administrador

Cada comando é uma função que recebe um Context e devolve o texto a mostrar. O `main` só
cuida da "fiação": argumentos, configuração, conexão e commit. Assim os comandos são
testáveis com a sessão transacional dos testes.
"""

import argparse
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.accounts import get_user_by_email, purge_refresh_tokens
from app.config import CacheSettings
from app.database import create_db_engine
from app.freshness import CachePolicy, Freshness
from app.limiter import purge_counters
from app.prefix_cache import cache_stats, purge_expired


class CommandError(Exception):
    """Erro esperado de um comando (ex.: e-mail não encontrado): vira mensagem + código 1."""


@dataclass(frozen=True, slots=True)
class Context:
    """O que todo comando recebe: a sessão, a política do cache, o "agora" e os argumentos."""

    session: Session
    policy: CachePolicy
    now: datetime
    args: argparse.Namespace


def cmd_cache_stats(ctx: Context) -> str:
    stats = cache_stats(ctx.session, policy=ctx.policy, now=ctx.now)
    lines = [f"{sum(stats.values())} faixa(s) no cache:"]
    for state in Freshness:  # percorrer um Enum devolve os membros, na ordem da declaração
        lines.append(f"  {state:<8} {stats[state]}")  # Counter devolve 0 para o que falta
    return "\n".join(lines)


def cmd_purge_cache(ctx: Context) -> str:
    deleted = purge_expired(ctx.session, policy=ctx.policy, now=ctx.now)
    return f"{deleted} faixa(s) expirada(s) apagada(s)."


def cmd_purge_rate_limits(ctx: Context) -> str:
    return f"{purge_counters(ctx.session, now=ctx.now)} contador(es) de rate limit apagado(s)."


def cmd_purge_refresh_tokens(ctx: Context) -> str:
    return f"{purge_refresh_tokens(ctx.session, now=ctx.now)} refresh token(s) apagado(s)."


def cmd_maintenance(ctx: Context) -> str:
    purges = (cmd_purge_cache, cmd_purge_rate_limits, cmd_purge_refresh_tokens)
    return "\n".join(command(ctx) for command in purges)


def cmd_make_admin(ctx: Context) -> str:
    user = get_user_by_email(ctx.session, ctx.args.email)
    if user is None:
        raise CommandError(f"Nenhuma conta com o e-mail {ctx.args.email}.")
    user.is_admin = not ctx.args.revoke
    return f"{user.email} {'deixou de ser' if ctx.args.revoke else 'agora é'} administrador."


Command = Callable[[Context], str]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.manage", description="Comandos de manutenção do PwnCheck."
    )
    subparsers = parser.add_subparsers(dest="command", required=True, metavar="comando")

    simple: dict[str, tuple[Command, str]] = {
        "cache-stats": (cmd_cache_stats, "mostra quantas faixas há no cache, por estado"),
        "purge-cache": (cmd_purge_cache, "apaga as faixas expiradas do cache"),
        "purge-rate-limits": (cmd_purge_rate_limits, "apaga contadores antigos do rate limit"),
        "purge-refresh-tokens": (cmd_purge_refresh_tokens, "apaga refresh tokens vencidos"),
        "maintenance": (cmd_maintenance, "roda as três limpezas (use no cron)"),
    }
    for name, (handler, help_text) in simple.items():
        # set_defaults guarda a função no resultado do parse: args.handler(...) a chama.
        subparsers.add_parser(name, help=help_text).set_defaults(handler=handler)

    make_admin = subparsers.add_parser("make-admin", help="dá o papel de administrador a uma conta")
    make_admin.add_argument("email", help="e-mail da conta")
    make_admin.add_argument("--revoke", action="store_true", help="tira o papel, em vez de dar")
    make_admin.set_defaults(handler=cmd_make_admin)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        settings = CacheSettings()
    except ValidationError:
        print("Configuração incompleta: defina DATABASE_URL (copie o .env.example para .env).")
        return 1

    engine = create_db_engine(settings.database_url.get_secret_value())
    try:
        with Session(engine) as session:
            ctx = Context(session, settings.cache_policy(), datetime.now(UTC), args)
            output = args.handler(ctx)
            session.commit()
    except CommandError as exc:
        print(exc)
        return 1
    finally:
        engine.dispose()
    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
