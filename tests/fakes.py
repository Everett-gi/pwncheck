"""Dublês de teste compartilhados: a API do HIBP simulada."""

import httpx

from app.kanonymity import sha1_hex, split_hash

# Um sufixo qualquer, que não é de nenhuma senha usada nos testes: toda faixa falsa tem ao
# menos uma linha, como as de verdade.
FILLER_SUFFIX = "011053FD0102E94D6AE2F8B83D76FAF94F6"


class FakeHIBP:
    """API do HIBP simulada (httpx.MockTransport), que conta e guarda as requisições.

    Dois modos:
        FakeHIBP(body="...")               responde sempre o mesmo corpo
        FakeHIBP(leaked={"senha": 42})     monta a faixa do prefixo pedido a partir das
                                           "senhas vazadas" — como a API de verdade faria
    `status` diferente de 200 simula a API fora do ar.
    """

    def __init__(
        self,
        body: str | None = None,
        status: int = 200,
        leaked: dict[str, int] | None = None,
    ) -> None:
        self.body = body
        self.status = status
        self.leaked = leaked or {}
        self.requests: list[httpx.Request] = []

    @property
    def calls(self) -> int:
        return len(self.requests)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.body is not None:
            return httpx.Response(self.status, text=self.body)
        prefix = request.url.path.rsplit("/", 1)[-1]
        lines = [f"{FILLER_SUFFIX}:1"]
        for password, count in self.leaked.items():
            password_prefix, suffix = split_hash(sha1_hex(password))
            if password_prefix == prefix:
                lines.append(f"{suffix}:{count}")
        return httpx.Response(self.status, text="\r\n".join(lines))

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))
