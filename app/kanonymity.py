"""Funções puras do modelo k-anonymity usado pela API Pwned Passwords.

Como funciona:
    1. Calculamos o SHA-1 da senha AQUI (40 caracteres hexadecimais).
    2. Só os 5 primeiros caracteres (o prefixo) são enviados à API.
    3. A API devolve TODOS os sufixos de hashes vazados com esse prefixo
       (centenas deles), e a comparação com o nosso sufixo acontece aqui.

Quem observa a consulta só vê um prefixo compartilhado por centenas de hashes
diferentes — não dá para saber qual deles é o nosso. Esse é o "k" do k-anonymity.

Este módulo NÃO faz rede nem acessa banco, de propósito: funções puras são
testáveis de forma rápida e isolada (mesma regra do text_utils.py do DocSage).
"""

import hashlib

# Tamanho do prefixo aceito pela API: 16^5 = 1.048.576 "faixas" possíveis.
PREFIX_LENGTH = 5

# SHA-1 = 160 bits = 20 bytes = 40 caracteres hexadecimais.
SHA1_HEX_LENGTH = 40


def sha1_hex(password: str) -> str:
    """Calcula o SHA-1 da senha em hexadecimal maiúsculo, o formato usado pela API.

    SHA-1 é inseguro para assinar arquivos ou guardar senhas, mas aqui ele não
    protege nada: é só a chave de busca da base do HaveIBeenPwned, que foi montada
    com SHA-1. O `usedforsecurity=False` declara isso explicitamente — e é o que
    faz o linter de segurança (regra S324) aceitar o uso.
    """
    data = password.encode("utf-8")  # o hash é calculado sobre BYTES, não sobre texto
    return hashlib.sha1(data, usedforsecurity=False).hexdigest().upper()


def split_hash(sha1_hash: str) -> tuple[str, str]:
    """Divide o hash em (prefixo, sufixo). Só o prefixo pode sair da máquina."""
    if len(sha1_hash) != SHA1_HEX_LENGTH:
        raise ValueError(
            f"O hash SHA-1 deve ter {SHA1_HEX_LENGTH} caracteres, recebido: {len(sha1_hash)}."
        )
    return sha1_hash[:PREFIX_LENGTH], sha1_hash[PREFIX_LENGTH:]


def parse_range_response(body: str) -> dict[str, int]:
    """Converte a resposta da API em um dicionário {sufixo: nº de vazamentos}.

    A API responde uma entrada por linha, no formato  SUFIXO:CONTAGEM  (ex.:
    "1E4C9B93F3F0682250B6CF8331B7EE68FD8:42"). Entradas com contagem 0 são
    "padding" (enchimento falso, veja o cabeçalho Add-Padding) e são descartadas.
    Uma contagem que não é número levanta ValueError: resposta corrompida não pode
    virar "senha segura" em silêncio.
    """
    counts: dict[str, int] = {}
    for line in body.splitlines():
        suffix, separator, count = line.strip().partition(":")
        if not separator:
            continue  # linha vazia ou sem ":": ignora
        occurrences = int(count)
        if occurrences > 0:
            counts[suffix.upper()] = occurrences
    return counts
