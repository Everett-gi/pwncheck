"""Testes da política de senha (funções puras: sem rede, sem banco)."""

import dataclasses

import pytest

from app.policy import (
    MULTI_FACTOR,
    SINGLE_FACTOR,
    PolicyConfig,
    Rule,
    blocklist_keys,
    common_passwords,
    email_context_words,
    evaluate_password,
    format_count,
    is_repetitive,
    is_sequential,
    normalize_password,
)

# Uma senha que passa em tudo: frase longa, palavras aleatórias, nada previsível.
GOOD_PASSWORD = "cavalo correto bateria grampo"

# Lista de bloqueio pequena e fixa: os testes não dependem do arquivo de dados.
BLOCKLIST = frozenset({"password", "dragon", "letmein"})


def rules(password: str, **kwargs) -> set[Rule]:
    """Atalho: avalia e devolve só o conjunto de regras violadas."""
    kwargs.setdefault("blocklist", BLOCKLIST)
    return {v.rule for v in evaluate_password(password, **kwargs).violations}


# --- Comprimento ---------------------------------------------------------------------------


def test_senha_boa_e_aceita():
    result = evaluate_password(GOOD_PASSWORD, blocklist=BLOCKLIST)
    assert result.accepted
    assert result.violations == ()
    assert result.length == len(GOOD_PASSWORD)


@pytest.mark.parametrize(
    ("length", "config", "expected_short"),
    [
        (14, SINGLE_FACTOR, True),  # um a menos que o mínimo do fator único
        (15, SINGLE_FACTOR, False),  # exatamente o mínimo
        (7, MULTI_FACTOR, True),
        (8, MULTI_FACTOR, False),
    ],
)
def test_comprimento_minimo_depende_do_perfil(length, config, expected_short):
    # Palavras distintas geradas a partir de letras variadas: só o comprimento importa aqui.
    password = "kfjwqzmxnvbtlrp"[:length]
    assert (Rule.TOO_SHORT in rules(password, config=config)) is expected_short


def test_senha_longa_demais_so_reporta_o_tamanho():
    result = evaluate_password("a" * 129, blocklist=BLOCKLIST)
    assert [v.rule for v in result.violations] == [Rule.TOO_LONG]  # nem roda as outras
    assert result.length == 129


def test_maximo_padrao_aceita_pelo_menos_64():
    # O NIST pede aceitar no mínimo 64 caracteres.
    assert SINGLE_FACTOR.max_length >= 64


def test_comprimento_conta_code_points_depois_do_nfc():
    composed = "é"  # U+00E9: um code point
    decomposed = "é"  # "e" + acento agudo combinante: dois code points
    assert len(decomposed) == 2
    assert normalize_password(decomposed) == composed
    assert evaluate_password(decomposed * 15, blocklist=BLOCKLIST).length == 15


def test_emoji_conta_como_code_points_e_nao_bytes():
    thumbs_up = "👍🏽"  # polegar + modificador de tom de pele: 2 code points, 8 bytes em UTF-8
    assert len(thumbs_up.encode("utf-8")) == 8
    assert evaluate_password(thumbs_up, blocklist=BLOCKLIST).length == 2


def test_espacos_contam_e_nao_sao_removidos():
    # Verificar a senha inteira: nada de strip() escondido.
    assert evaluate_password("  ab  ", blocklist=BLOCKLIST).length == 6


def test_configuracao_invalida_e_rejeitada():
    with pytest.raises(ValueError):
        PolicyConfig(min_length=20, max_length=10)
    with pytest.raises(ValueError):
        PolicyConfig(min_length=0)


def test_configuracao_e_imutavel():
    with pytest.raises(dataclasses.FrozenInstanceError):
        SINGLE_FACTOR.min_length = 1  # type: ignore[misc]


# --- Lista de bloqueio e derivados ---------------------------------------------------------


@pytest.mark.parametrize(
    ("password", "expected"),
    [
        ("Password123!", {"password123!", "password", "passwordi2ei"}),
        ("P@ssw0rd", {"p@ssw0rd", "password"}),
        ("m0nte1r0", {"m0nte1r0", "m0nte1r", "monteir", "monteiro"}),
        ("  letmein  ", {"  letmein  ", "letmein"}),
        ("123456", {"123456", "i2eas6"}),  # o corte deixaria "", que é descartado
    ],
)
def test_blocklist_keys_remove_enfeites(password, expected):
    assert blocklist_keys(password) == expected


@pytest.mark.parametrize(
    "password",
    ["password", "PASSWORD", "Password2025!!!!", "p@$$w0rd", "!!dragon!!", "l3tm31n"],
)
def test_senha_comum_e_derivados_sao_rejeitados(password):
    assert Rule.COMMON in rules(password)


def test_senha_comum_dentro_de_frase_nao_e_rejeitada():
    # O NIST manda comparar a senha INTEIRA, não pedaços: frases com palavras comuns são boas.
    assert Rule.COMMON not in rules("dragon azul comendo pastel")


def test_lista_padrao_carrega_do_arquivo():
    words = common_passwords()
    assert len(words) == 10_001  # o arquivo "10k" da SecLists tem, de fato, 10.001 linhas
    assert {"password", "123456", "qwerty"} <= words  # "<=" entre conjuntos = subconjunto
    assert not any(w.startswith("#") for w in words)  # comentários ficaram de fora
    assert common_passwords() is words  # functools.cache: o arquivo é lido uma vez só


# --- Palavras de contexto ------------------------------------------------------------------


def test_email_context_words():
    assert email_context_words("gil.monteiro+teste@exemplo.com") == {
        "gil.monteiro+teste@exemplo.com",
        "gil.monteiro+teste",
        "gil",
        "monteiro",
        "teste",
    }


@pytest.mark.parametrize("password", ["PwnCheck", "pwncheck2025!!!!", "Monteiro1990", "m0nte1r0"])
def test_derivados_do_contexto_sao_rejeitados(password):
    context = email_context_words("gil.monteiro@exemplo.com")
    assert Rule.CONTEXT in rules(password, context_words=context)


def test_contexto_dentro_de_frase_nao_e_rejeitado():
    assert Rule.CONTEXT not in rules("o monteiro gosta de pastel", context_words={"monteiro"})


# --- Padrões previsíveis -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("aaaaaa", True),
        ("abcabcabc", True),
        ("abab", True),
        ("abcabcabd", False),
        ("ab", False),  # curto demais para ser "padrão"
        ("a\na\n", True),  # DOTALL: o "." aceita quebra de linha
    ],
)
def test_is_repetitive(text, expected):
    assert is_repetitive(text) is expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("abcdef", True),
        ("fedcba", True),  # ao contrário
        ("123456789", True),
        ("7890123", True),  # dá a volta: 9 -> 0
        ("qwerty", True),
        ("lkjhgfdsa", True),  # fileira do teclado, ao contrário
        ("abcdeg", False),
        ("ab", False),
    ],
)
def test_is_sequential(text, expected):
    assert is_sequential(text) is expected


@pytest.mark.parametrize(
    ("password", "rule"),
    [
        ("xyzxyzxyzxyzxyz", Rule.REPETITIVE),
        ("zzzzzzzzzzzzzzz!!!", Rule.REPETITIVE),  # os enfeites das pontas não salvam
        ("abcdefghijklmnopq", Rule.SEQUENTIAL),
        ("QWERTYUIOPQWERTYU", Rule.SEQUENTIAL),  # maiúsculas não mudam nada
    ],
)
def test_padroes_previsiveis_sao_rejeitados(password, rule):
    assert rule in rules(password)


# --- Vazamentos e combinação ---------------------------------------------------------------


@pytest.mark.parametrize(("count", "breached"), [(None, False), (0, False), (1, True)])
def test_contagem_de_vazamentos(count, breached):
    assert (Rule.BREACHED in rules(GOOD_PASSWORD, breach_count=count)) is breached


def test_mensagem_de_vazamento_formata_o_numero():
    result = evaluate_password(GOOD_PASSWORD, breach_count=1234567, blocklist=BLOCKLIST)
    assert "1.234.567 vezes" in result.violations[0].message


def test_reporta_todas_as_violacoes_de_uma_vez():
    # Curta, comum, sequencial e vazada: o usuário fica sabendo de tudo numa resposta só.
    assert rules("123456", blocklist=frozenset({"123456"}), breach_count=10) == {
        Rule.TOO_SHORT,
        Rule.COMMON,
        Rule.SEQUENTIAL,
        Rule.BREACHED,
    }


def test_toda_violacao_explica_o_motivo():
    result = evaluate_password("abc", breach_count=5, blocklist=frozenset({"abc"}))
    assert result.violations  # não aceita...
    assert all(len(v.message) > 20 for v in result.violations)  # ...e diz por quê


def test_rule_e_texto():
    # StrEnum: cada membro É uma str, pronta para ir num JSON.
    assert Rule.TOO_SHORT == "too_short"
    assert isinstance(Rule.BREACHED, str)


def test_format_count():
    assert format_count(0) == "0"
    assert format_count(1000) == "1.000"
    assert format_count(6421042) == "6.421.042"
