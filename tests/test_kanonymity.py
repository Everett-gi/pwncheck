"""Testes das funções puras do k-anonymity (rápidos: sem rede, sem banco)."""

import pytest

from app.kanonymity import PREFIX_LENGTH, parse_range_response, sha1_hex, split_hash

# Valores esperados calculados com uma ferramenta INDEPENDENTE (o sha1sum do Git Bash),
# para o teste não depender do próprio código que ele verifica:
#   printf 'password' | sha1sum
PASSWORD_SHA1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
PASSWORD_SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
OTHER_SUFFIX = "011053FD0102E94D6AE2F8B83D76FAF94F6"


def test_sha1_hex_de_valor_conhecido():
    assert sha1_hex("password") == PASSWORD_SHA1


def test_sha1_hex_retorna_40_caracteres_maiusculos():
    result = sha1_hex("qualquer coisa")
    assert len(result) == 40
    assert result == result.upper()


def test_sha1_hex_codifica_em_utf8():
    # O hash é calculado sobre BYTES. "é" em UTF-8 são 2 bytes (C3 A9); em Latin-1
    # seria 1 byte (E9) e o hash seria outro (1599E9FA...). A base do HIBP usa UTF-8:
    # com a codificação errada, a busca falharia em silêncio.
    #   printf '\xc3\xa9' | sha1sum
    assert sha1_hex("é") == "BF15BE717AC1B080B4F1C456692825891FF5073D"


def test_split_hash_separa_prefixo_e_sufixo():
    prefix, suffix = split_hash(PASSWORD_SHA1)
    assert prefix == "5BAA6"
    assert suffix == PASSWORD_SUFFIX
    assert len(prefix) == PREFIX_LENGTH
    assert prefix + suffix == PASSWORD_SHA1  # nada se perde na divisão


@pytest.mark.parametrize("invalid", ["", "5BAA6", PASSWORD_SHA1 + "0"])
def test_split_hash_rejeita_tamanho_invalido(invalid):
    with pytest.raises(ValueError):
        split_hash(invalid)


def test_parse_range_response_le_sufixos_e_contagens():
    # A API real separa as linhas com CRLF (\r\n); splitlines() trata os dois formatos.
    body = f"{PASSWORD_SUFFIX}:42\r\n{OTHER_SUFFIX}:1\r\n"
    assert parse_range_response(body) == {PASSWORD_SUFFIX: 42, OTHER_SUFFIX: 1}


def test_parse_range_response_descarta_padding_e_linhas_vazias():
    padding = f"{OTHER_SUFFIX}:0"  # entrada falsa do Add-Padding (contagem 0)
    body = f"{padding}\n\n   \n{PASSWORD_SUFFIX}:7\n"
    assert parse_range_response(body) == {PASSWORD_SUFFIX: 7}


def test_parse_range_response_normaliza_para_maiusculas():
    body = f"{PASSWORD_SUFFIX.lower()}:3"
    assert parse_range_response(body) == {PASSWORD_SUFFIX: 3}


def test_parse_range_response_falha_com_contagem_invalida():
    # Resposta corrompida não pode virar "senha segura" em silêncio.
    with pytest.raises(ValueError):
        parse_range_response(f"{PASSWORD_SUFFIX}:abc")
