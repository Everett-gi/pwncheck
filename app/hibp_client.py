"""Cliente HTTP da API Pwned Passwords (HaveIBeenPwned), no modelo k-anonymity.

Documentação: https://haveibeenpwned.com/API/v3#PwnedPasswords
A consulta por faixa (/range) é gratuita e não exige chave de API.
"""

import httpx

from app.kanonymity import parse_range_response, sha1_hex, split_hash

API_BASE_URL = "https://api.pwnedpasswords.com"

HEADERS = {
    # A API pede um User-Agent que identifique quem está consultando.
    "User-Agent": "PwnCheck (projeto de portfolio)",
    # Padding: a API completa a resposta com entradas falsas (contagem 0), deixando
    # todas as respostas com tamanho parecido. Assim o TAMANHO da resposta não revela
    # qual prefixo foi consultado — mesmo com HTTPS, o tamanho do tráfego é visível.
    "Add-Padding": "true",
}


def fetch_range(client: httpx.Client, prefix: str) -> dict[str, int]:
    """Busca na API todos os sufixos vazados que começam com `prefix`."""
    response = client.get(f"{API_BASE_URL}/range/{prefix}", headers=HEADERS)
    response.raise_for_status()  # status 4xx/5xx vira exceção (httpx.HTTPStatusError)
    return parse_range_response(response.text)


def check_password(client: httpx.Client, password: str) -> int:
    """Retorna quantas vezes a senha apareceu em vazamentos (0 = nenhuma).

    Só o prefixo de 5 caracteres do hash trafega; a senha e o hash completo
    nunca saem desta função.

    O `client` vem de fora (injeção de dependência): quem chama decide timeout e
    reaproveitamento de conexões — e os testes passam um cliente com a rede simulada.
    """
    prefix, suffix = split_hash(sha1_hex(password))
    return fetch_range(client, prefix).get(suffix, 0)
