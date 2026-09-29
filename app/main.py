"""PwnCheck — a API web (fase 4).

Para rodar no desenvolvimento (com o .env preenchido e o banco no ar):
    uvicorn app.main:create_app --factory --reload

    --factory   o uvicorn chama create_app() para obter a aplicação (em vez de importar um
                objeto pronto): nada acontece só por importar este módulo.
    --reload    reinicia sozinho quando você salva um arquivo.

Depois abra http://127.0.0.1:8000 (página inicial) ou http://127.0.0.1:8000/docs (a API).
"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.config import Settings
from app.database import create_db_engine, create_session_factory
from app.middleware import BodySizeLimitMiddleware, security_headers
from app.routers import auth, passwords

STATIC_DIR = Path(__file__).parent / "static"

DESCRIPTION = """
Verifica se uma senha apareceu em vazamentos **sem que ela precise sair do seu computador**
(modelo *k-anonymity* da API Pwned Passwords), e avalia a força de senhas segundo o
**NIST SP 800-63B-4**.

* `GET /range/{prefixo}` — público: mande só os 5 primeiros caracteres do SHA-1.
* `POST /check` e `POST /policy` — exigem login (`/auth/register` e `/auth/login`).
"""


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Resposta 422 SEM ecoar o que foi enviado.

    O padrão do FastAPI devolve, em cada erro, o campo "input" com o valor recebido. Se o
    erro for numa senha (grande demais, por exemplo), a senha voltaria na resposta — e
    poderia parar em logs de proxies, ferramentas de monitoramento, histórico do navegador.
    Mantemos só onde (loc), o quê (type) e a explicação (msg).
    """
    errors = [
        {"loc": list(error["loc"]), "type": error["type"], "msg": error["msg"]}
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": errors})


def create_app(settings: Settings | None = None) -> FastAPI:
    """Monta a aplicação. Recebe as configurações por parâmetro (os testes passam as suas);
    sem parâmetro, lê do ambiente / .env."""
    settings = settings or Settings()
    if not logging.getLogger().handlers:  # o uvicorn configura só os loggers dele
        logging.basicConfig(
            level=settings.log_level, format="%(asctime)s %(levelname)s [%(name)s] %(message)s"
        )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        """Roda uma vez na subida (antes do yield) e uma vez no desligamento (depois)."""
        engine = create_db_engine(settings.database_url.get_secret_value())
        app.state.session_factory = create_session_factory(engine)
        # Um cliente para a aplicação inteira: as conexões com o HIBP são reaproveitadas.
        app.state.hibp_client = httpx.Client(timeout=settings.hibp_timeout_seconds)
        yield
        app.state.hibp_client.close()
        engine.dispose()

    app = FastAPI(
        title="PwnCheck",
        version="1.0.0",
        summary="Verificação de senhas vazadas com k-anonymity.",
        description=DESCRIPTION,
        lifespan=lifespan,
    )
    app.state.settings = settings

    # A ordem importa: o ÚLTIMO adicionado fica POR FORA. Os cabeçalhos de segurança vão
    # por fora para valerem também na resposta 413 do limite de tamanho.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes)
    app.middleware("http")(security_headers)
    app.add_exception_handler(RequestValidationError, validation_error_handler)

    app.include_router(auth.router)
    app.include_router(passwords.router)

    @app.get("/health", tags=["infra"])
    def health() -> dict[str, str]:
        """Verificação simples de que a aplicação está no ar."""
        return {"status": "ok"}

    # A página inicial: verificação 100% no navegador, usando o /range (k-anonymity).
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    return app
