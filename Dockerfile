# Imagem da aplicação PwnCheck (fase 6), em dois estágios.
#
#   docker build -t pwncheck .
#
# Estágio 1 ("builder") instala as dependências num ambiente virtual; o estágio 2 copia só
# esse ambiente pronto e o código. Ferramentas de instalação e caches ficam para trás.

# ---------- Estágio 1: dependências ----------
FROM python:3.12-slim AS builder

# Sem cache do pip (a imagem não precisa dele) e sem aviso de versão nova do pip.
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv

# Só o requirements.txt primeiro: esta camada (a mais lenta) fica em cache e só é refeita
# quando as dependências mudam — não a cada alteração no código.
COPY requirements.txt .
RUN /opt/venv/bin/pip install -r requirements.txt


# ---------- Estágio 2: a imagem final ----------
FROM python:3.12-slim

# PYTHONDONTWRITEBYTECODE: não gravar .pyc (o código é só leitura para o usuário "app").
# PYTHONUNBUFFERED: logs saem na hora, sem ficar presos num buffer (importante em container).
# PATH: o Python e os comandos do ambiente virtual vêm primeiro.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Usuário de sistema, sem senha, sem shell de login e sem pasta pessoal: se alguém conseguir
# executar código na aplicação, não será root dentro do container.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
# O código pertence ao root e o usuário "app" só o LÊ: a aplicação não consegue alterar a si
# mesma. Só o que é necessário para rodar entra na imagem (testes e docs ficam de fora).
COPY pyproject.toml ./
COPY app ./app
COPY migrations ./migrations

USER app
EXPOSE 8080

# O Docker pergunta periodicamente se a aplicação responde. A imagem slim não tem curl; o
# próprio Python faz a requisição.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3)"]

# --factory: o uvicorn chama create_app(). --no-server-header: não anunciar "uvicorn".
# Os cabeçalhos de proxy (X-Forwarded-For) só são aceitos dos IPs em FORWARDED_ALLOW_IPS
# (definido no docker-compose.prod.yml).
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
