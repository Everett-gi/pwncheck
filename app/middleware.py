"""Middlewares da API (fase 4): camadas que envolvem TODAS as requisições.

Um middleware fica entre o servidor e as rotas, como as camadas de uma cebola:

    servidor ──> security_headers ──> BodySizeLimit ──> rotas
             <── (acrescenta         <── (barra corpos    <──
                  cabeçalhos)             grandes demais)

Aqui aparece `async def` / `await`: o protocolo ASGI, que liga o servidor (uvicorn) à
aplicação, é assíncrono. Por enquanto, leia `await x()` como "chame x() e espere o
resultado"; a programação assíncrona de verdade fica para o ThreatScope, o próximo projeto.
"""

from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# --- Limite de tamanho do corpo ----------------------------------------------------------------


class BodySizeLimitMiddleware:
    """Recusa (413) requisições com corpo maior que `max_bytes`.

    Nenhum endpoint precisa de mais que alguns KB. Sem limite, alguém poderia mandar
    gigabytes e ocupar a memória do servidor. O Caddy (fase 6) também limita; esta é a
    segunda camada, que vale mesmo sem ele (defesa em profundidade).

    É um middleware ASGI "puro": uma classe cujo objeto é chamado com (scope, receive, send)
    — o equivalente a registrar um callback em C que recebe o contexto e dois ponteiros de
    função, um para ler a requisição e outro para escrever a resposta.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # 1ª barreira: o cabeçalho Content-Length declara o tamanho — recusa sem ler nada.
        headers = dict(scope["headers"])
        declared = headers.get(b"content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > self.max_bytes):
            await _send_413(send)
            return

        # 2ª barreira: o corpo pode chegar em pedaços SEM Content-Length ("chunked"). Lemos
        # os pedaços aqui, contando; passou do limite, 413 e a aplicação nem é chamada.
        # (Levantar uma exceção no meio da leitura não serviria: o FastAPI a capturaria e
        # responderia 400, "erro ao interpretar o corpo". Um teste nos mostrou isso.)
        body = bytearray()
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] != "http.request":  # o cliente desconectou
                return
            body += message.get("body", b"")
            more_body = message.get("more_body", False)
            if len(body) > self.max_bytes:
                await _send_413(send)
                return

        # O corpo já foi lido: entregamos à aplicação um "receive" que o devolve de uma vez.
        delivered = False

        async def replay_receive() -> Message:
            nonlocal delivered  # "nonlocal": altera a variável da função de fora (closure)
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()  # depois do corpo, só resta esperar a desconexão

        await self.app(scope, replay_receive, send)


async def _send_413(send: Send) -> None:
    body = '{"detail":"Requisição grande demais."}'.encode()
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


# --- Cabeçalhos de segurança -------------------------------------------------------------------

# Páginas de documentação (Swagger/ReDoc) carregam scripts de uma CDN: ficam sem CSP própria.
DOCS_PATHS = ("/docs", "/redoc")
# Respostas da API (JSON/texto): não carregam nada, não podem ser embutidas em outro site.
API_CSP = "default-src 'none'; frame-ancestors 'none'"
# A página inicial e seus arquivos: só recursos do próprio site.
PAGE_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


async def security_headers(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Acrescenta cabeçalhos de segurança a toda resposta.

    O HSTS ("use sempre HTTPS") não está aqui: ele só faz sentido numa resposta HTTPS, e
    quem fala HTTPS com o navegador é o Caddy (fase 6), que o acrescenta.
    """
    response = await call_next(request)
    headers = response.headers
    headers.setdefault("X-Content-Type-Options", "nosniff")  # não "adivinhar" o tipo
    headers.setdefault("X-Frame-Options", "DENY")  # não pode ir num <iframe> (clickjacking)
    headers.setdefault("Referrer-Policy", "no-referrer")  # não vazar a URL para outros sites
    # Respostas com tokens e resultados não podem ficar guardadas em caches nem no navegador.
    headers.setdefault("Cache-Control", "no-store")
    path = request.url.path
    if not path.startswith(DOCS_PATHS):
        is_page = path == "/" or path.startswith("/static/")
        headers.setdefault("Content-Security-Policy", PAGE_CSP if is_page else API_CSP)
    return response
