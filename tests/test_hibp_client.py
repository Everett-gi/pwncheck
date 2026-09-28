"""Testes do cliente HTTP com a API SIMULADA (httpx.MockTransport).

Nenhum teste aqui acessa a internet. O MockTransport troca a camada de rede do
httpx por uma função nossa: ela recebe a requisição que SERIA enviada e devolve
a resposta que quisermos. Isso permite testar também o que sai da máquina —
que é justamente a garantia central do projeto.
"""

import httpx
import pytest

from app.hibp_client import check_password
from app.kanonymity import sha1_hex, split_hash

PASSWORD = "minha-senha-super-secreta"
FULL_HASH = sha1_hex(PASSWORD)
PREFIX, SUFFIX = split_hash(FULL_HASH)
OTHER_SUFFIX = "011053FD0102E94D6AE2F8B83D76FAF94F6"


def fake_api(body: str, status: int = 200, sent: list[httpx.Request] | None = None) -> httpx.Client:
    """Cria um httpx.Client cuja "internet" é a função `handler` abaixo."""

    def handler(request: httpx.Request) -> httpx.Response:
        if sent is not None:
            sent.append(request)  # guarda a requisição para o teste inspecionar
        return httpx.Response(status, text=body)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_senha_vazada_retorna_a_contagem():
    client = fake_api(f"{SUFFIX}:42\r\n{OTHER_SUFFIX}:3\r\n")
    assert check_password(client, PASSWORD) == 42


def test_senha_nao_vazada_retorna_zero():
    client = fake_api(f"{OTHER_SUFFIX}:3\r\n")
    assert check_password(client, PASSWORD) == 0


def test_somente_o_prefixo_sai_da_maquina():
    """A garantia central do k-anonymity: nada além do prefixo trafega."""
    sent: list[httpx.Request] = []
    check_password(fake_api("", sent=sent), PASSWORD)

    assert len(sent) == 1  # exatamente uma consulta
    request = sent[0]
    assert request.url.path == f"/range/{PREFIX}"

    # Nada sensível em NENHUMA parte da requisição: URL, cabeçalhos ou corpo.
    everything_sent = f"{request.url} {request.headers} {request.content!r}".lower()
    for secret in (PASSWORD, FULL_HASH, SUFFIX):
        assert secret.lower() not in everything_sent


def test_envia_cabecalhos_de_padding_e_identificacao():
    sent: list[httpx.Request] = []
    check_password(fake_api("", sent=sent), PASSWORD)
    assert sent[0].headers["Add-Padding"] == "true"
    assert "PwnCheck" in sent[0].headers["User-Agent"]


def test_entrada_de_padding_nao_conta_como_vazamento():
    # Contagem 0 é enchimento falso: mesmo com o sufixo igual, não é vazamento.
    client = fake_api(f"{SUFFIX}:0\r\n")
    assert check_password(client, PASSWORD) == 0


def test_erro_da_api_vira_excecao():
    with pytest.raises(httpx.HTTPStatusError):
        check_password(fake_api("", status=503), PASSWORD)
