"""Linha de comando para testar o PwnCheck com a API real (fases 1 e 2).

Uso (dentro da pasta do projeto, com o .venv ativo):
    python -m app.cli

A senha é lida sem eco na tela (getpass) e nunca é impressa, logada ou salva.
Não passe senhas como argumento de linha de comando: elas ficam gravadas no
histórico do terminal e visíveis na lista de processos do sistema.
"""

import getpass
import sys

import httpx

from app.hibp_client import check_password
from app.policy import evaluate_password, format_count


def main() -> int:
    """Pergunta a senha, consulta a API e devolve o código de saída do processo."""
    password = getpass.getpass("Senha a verificar (não aparece enquanto você digita): ")
    if not password:
        print("Nenhuma senha informada.")
        return 1

    try:
        with httpx.Client(timeout=10.0) as client:
            count = check_password(client, password)
    except httpx.HTTPError as exc:
        # A URL da mensagem só contém o prefixo do hash, que não é sensível.
        print(f"Falha ao consultar a API: {exc}")
        return 2

    if count:
        print(f"ALERTA: esta senha apareceu {format_count(count)} vezes em vazamentos. Não use!")
    else:
        print("OK: esta senha não aparece na base de vazamentos conhecidos.")

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
