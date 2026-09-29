# Deploy do PwnCheck (Oracle Cloud Always Free, com HTTPS)

Guia para colocar o PwnCheck no ar. A infraestrutura é a mesma de todo o portfólio
([DEPLOY-GERAL](https://github.com/Everett-gi/Projetos-e-ideias/blob/main/DEPLOY-GERAL.md)):
uma VM ARM da Oracle Cloud com Docker, e o Caddy fazendo HTTPS automático.

**Tempo estimado:** 30 min (com a VM pronta) · **Custo:** R$ 0,00.

> A explicação de cada peça (Dockerfile, redes, Caddy, HSTS, proxies confiáveis) está na
> [lição da fase 6](tutorial/fase-6-deploy-https.md). Este guia é o passo a passo.

---

## 1. Antes de começar: a VM

Se você ainda não tem a VM, siga os passos 2 a 10 do
[guia de deploy do DocSage](https://github.com/Everett-gi/docsage/blob/main/docs/DEPLOY.md):
conta na Oracle, chave SSH, VM `VM.Standard.A1.Flex` (Ubuntu 24.04, ARM), portas 80/443 na
**Security List** e no **iptables** (o firewall duplo!), *hardening* com fail2ban e SSH só
por chave, swap, Docker e o domínio no DuckDNS. Tudo ali vale para o PwnCheck.

Escolha agora **um dos dois cenários**:

| Cenário | Quando | Caddy |
|---|---|---|
| **A — PwnCheck sozinho** | a VM não tem outro site nas portas 80/443 | o do próprio PwnCheck (`docker-compose.prod.yml`) |
| **B — VM compartilhada** | o DocSage (ou outro projeto) já responde nas 80/443 | o Caddy que já existe; o do PwnCheck fica desligado (`docker-compose.shared-caddy.yml`) |

Só um processo pode escutar numa porta: dois Caddys nas portas 80/443 da mesma VM não sobem.

---

## 2. O domínio

No [DuckDNS](https://www.duckdns.org), crie um subdomínio para o PwnCheck (ex.: `pwncheck-gil`)
apontando para o IP público da VM. Confira, **na VM**, antes de continuar:

```bash
dig +short pwncheck-gil.duckdns.org     # deve mostrar o IP da VM
curl -s ifconfig.me                      # o IP da VM, para comparar
```

Não avance com o DNS errado: o Let's Encrypt limita a 5 falhas por hora.

---

## 3. Clonar e criar o `.env` de produção

```bash
ssh docsage                                     # ou o apelido que você deu à VM
cd ~
git clone https://github.com/Everett-gi/pwncheck.git
cd pwncheck

# Gere os dois segredos e copie as saídas
openssl rand -base64 24 | tr -d '/+='           # senha do banco (sem / + =, que atrapalham a URL)
openssl rand -base64 48                          # JWT_SECRET

nano .env
```

Conteúdo do `.env` de produção (troque os valores marcados):

```bash
POSTGRES_DB=pwncheck
POSTGRES_USER=pwncheck
POSTGRES_PASSWORD=COLE_A_SENHA_DO_BANCO
# O host é "pwncheck-db": o nome do serviço do banco no docker-compose.prod.yml.
DATABASE_URL=postgresql+psycopg://pwncheck:COLE_A_MESMA_SENHA@pwncheck-db:5432/pwncheck

JWT_SECRET=COLE_O_SEGREDO_JWT
LOG_LEVEL=INFO

DOMAIN=pwncheck-gil.duckdns.org
ACME_EMAIL=seu-email@exemplo.com
```

Os demais valores (validade do cache, dos tokens, rate limits) têm padrões sensatos; se quiser
mudar, copie as linhas do `.env.example`.

```bash
chmod 600 .env        # só o seu usuário lê o arquivo
```

---

## 4. Subir

### Cenário A — PwnCheck sozinho

```bash
docker compose -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.prod.yml ps
```

A primeira vez leva alguns minutos (build da imagem no ARM). A ordem de subida é automática:
banco saudável → migrações (terminam com sucesso) → aplicação saudável → Caddy.

### Cenário B — VM compartilhada com o DocSage

1. Descubra o nome da rede do Caddy que já está no ar:

   ```bash
   docker inspect docsage-caddy-1 --format '{{range $net, $v := .NetworkSettings.Networks}}{{$net}} {{end}}'
   ```

   (No DocSage, o nome costuma ser `docsage_internal`.)

2. Suba o PwnCheck **sem** o Caddy dele, ligado a essa rede:

   ```bash
   export EDGE_NETWORK=docsage_internal
   docker compose -f docker-compose.prod.yml -f docker-compose.shared-caddy.yml up -d --build
   ```

   O `EDGE_NETWORK` precisa estar definido em **todo** comando `docker compose` com os dois
   arquivos (inclusive `ps`, `logs` e `down`). Para não esquecer, acrescente
   `EDGE_NETWORK=docsage_internal` ao `.env` do PwnCheck.

3. No `Caddyfile` do DocSage (`~/docsage/Caddyfile`), acrescente um bloco para o PwnCheck:

   ```
   pwncheck-gil.duckdns.org {
   	encode zstd gzip
   	request_body {
   		max_size 16KB
   	}
   	header {
   		Strict-Transport-Security "max-age=31536000; includeSubDomains"
   		-Server
   	}
   	reverse_proxy pwncheck-app:8080
   }
   ```

   E recarregue o Caddy central, sem derrubá-lo:

   ```bash
   cd ~/docsage
   docker compose -f docker-compose.prod.yml exec caddy caddy reload --config /etc/caddy/Caddyfile
   ```

   Se o Caddy não enxergar a mudança, reinicie o container dele
   (`docker compose -f docker-compose.prod.yml restart caddy`). Motivo: o `Caddyfile` entra no
   container como *bind mount* de um arquivo só, e alguns editores salvam criando um arquivo
   novo no lugar do antigo — o container continua vendo a versão anterior até reiniciar.

---

## 5. Verificar

```bash
docker compose -f docker-compose.prod.yml ps            # tudo "Up (healthy)"; o migrate "Exited (0)"
docker compose -f docker-compose.prod.yml logs -f       # Ctrl+C sai sem derrubar nada
```

No navegador:

- `https://pwncheck-gil.duckdns.org` → a página inicial, com o cadeado sem aviso.
- `https://pwncheck-gil.duckdns.org/docs` → a documentação interativa.
- `http://pwncheck-gil.duckdns.org` → deve redirecionar para `https://`.

Na sua máquina (PowerShell), confira os cabeçalhos:

```powershell
(Invoke-WebRequest https://pwncheck-gil.duckdns.org/health).Headers
```

Procure `Strict-Transport-Security`, `Content-Security-Policy` e `X-Content-Type-Options`, e
confirme que **não** há `Server`.

Crie a sua conta pela página `/docs` (`POST /auth/register`) e promova-a a administradora:

```bash
docker compose -f docker-compose.prod.yml exec pwncheck-app python -m app.manage make-admin seu-email@exemplo.com
```

---

## 6. Rotina: manutenção e backup

Crie a pasta dos backups e abra o `crontab` (o agendador do Linux):

```bash
mkdir -p ~/backups
crontab -e
```

Acrescente as duas linhas (no cenário B, inclua `-f docker-compose.shared-caddy.yml` e o
`EDGE_NETWORK` no `.env`):

```
# Todo dia às 3h: limpezas (cache expirado, contadores do rate limit, tokens vencidos)
0 3 * * * cd ~/pwncheck && docker compose -f docker-compose.prod.yml exec -T pwncheck-app python -m app.manage maintenance >> ~/backups/pwncheck-maintenance.log 2>&1
# Todo dia às 3h15: backup do banco, compactado, com a data no nome
15 3 * * * cd ~/pwncheck && docker compose -f docker-compose.prod.yml exec -T pwncheck-db sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' | gzip > ~/backups/pwncheck-$(date +\%F).sql.gz
```

(`%` tem significado especial no crontab — por isso o `\%`.) Os backups ficam na mesma VM:
protegem contra erro humano, não contra a perda da VM. O ideal é copiá-los para um storage
externo.

Para **restaurar** um backup num banco vazio:

```bash
gunzip -c ~/backups/pwncheck-2026-09-29.sql.gz | \
  docker compose -f docker-compose.prod.yml exec -T pwncheck-db sh -c 'psql -U "$POSTGRES_USER" "$POSTGRES_DB"'
```

---

## 7. Atualizar (depois de um push no GitHub)

```bash
cd ~/pwncheck
git pull
docker compose -f docker-compose.prod.yml up -d --build
```

O serviço `pwncheck-migrate` roda de novo e aplica as migrações novas **antes** de a aplicação
nova subir. Se uma migração falhar, a aplicação não sobe — confira com
`docker compose -f docker-compose.prod.yml logs pwncheck-migrate`.

---

## 8. Solução de problemas

| Sintoma | Causa provável | O que fazer |
|---|---|---|
| `pwncheck-migrate` com `Exited (1)` | banco inacessível ou senha errada | `logs pwncheck-migrate`; a senha do `POSTGRES_PASSWORD` e a do `DATABASE_URL` precisam ser iguais |
| `password authentication failed` depois de trocar a senha no `.env` | o PostgreSQL só lê `POSTGRES_PASSWORD` na **criação** do volume | troque a senha dentro do banco (`ALTER USER`) ou recrie o volume (`down -v` apaga os dados!) |
| `defina DOMAIN no .env` | variável faltando | complete o `.env` (seção 3) |
| `defina EDGE_NETWORK ...` | cenário B sem a variável | `export EDGE_NETWORK=...` ou coloque no `.env` |
| `bind: address already in use` nas portas 80/443 | outro Caddy já está no ar | você está no cenário B: use o `docker-compose.shared-caddy.yml` |
| Caddy não obtém certificado | DNS errado ou porta 80 fechada | `dig +short SEU_DOMINIO`; firewall duplo (Security List + iptables) |
| 502 Bad Gateway | a aplicação não está saudável | `ps` e `logs pwncheck-app` |
| Todos os usuários recebem 429 juntos | o IP real não está chegando à aplicação | confira o `FORWARDED_ALLOW_IPS` do `pwncheck-app` no `docker-compose.prod.yml` |
| 503 no `/range` e no `/check` | a VM não alcança o HIBP | `docker compose -f docker-compose.prod.yml exec pwncheck-app python -c "import httpx; print(httpx.get('https://api.pwnedpasswords.com/range/21BD1').status_code)"` |
| Build "Killed" | falta de memória | swap (passo 8 do guia do DocSage) |

## Checklist (do DEPLOY-GERAL)

- [ ] Repositório com Secret Scanning + Push Protection ativos
- [ ] `.env` de produção criado **na VM**, com `chmod 600`
- [ ] Subdomínio DuckDNS apontando para a VM (conferido com `dig`)
- [ ] Portas 80/443 abertas na Security List **e** no iptables
- [ ] `docker compose ... up -d --build` sem erros; `ps` com tudo saudável
- [ ] HTTPS funcionando (cadeado, sem aviso) e `http://` redirecionando
- [ ] Conta de administrador criada (`make-admin`)
- [ ] Manutenção e backup no cron
