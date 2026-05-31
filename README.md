# BotCasa

Clasificador de cedulas Davivienda-LifeMiles con panel web + bot Telegram + worker async.

## Buckets que el bot reconoce

| Bucket | Significado |
|---|---|
| `TIENE_CUENTA` | Cliente ya tiene cuenta de banca digital. La pantalla siguiente le pedira clave para mostrar oferta o no. |
| `SIN_CLAVE` | Cliente Davivienda pero sin clave de banca digital. |
| `QUEREMOS_CONOCERTE` | No es cliente Davivienda. |
| `DESCONOCIDO` | Respuesta no mapeada (queda en BD para inspeccion). |
| `ERROR` | Fallo de red/upstream. |

## Setup local

```bash
pip install -r requirements.txt
cp .env.example .env   # editar con credenciales reales
python -m src.web.cli create-user --username brayan --password TUCLAVE --admin
python -m src.main
# -> http://127.0.0.1:8000
```

## Setup Docker

```bash
docker build -t botcasa .
docker run -d --name botcasa -p 8000:8000 --env-file .env botcasa
# crear usuario admin la primera vez:
docker exec botcasa python -m src.web.cli create-user --username brayan --password TUCLAVE --admin
```

O con compose:

```bash
docker compose up -d
docker compose exec botcasa python -m src.web.cli create-user --username brayan --password TUCLAVE --admin
```

## Variables de entorno (.env)

| Var | Descripcion |
|---|---|
| `DATABASE_URL` | URL SQLAlchemy de MariaDB. Encode el `@` del usuario como `%40`. |
| `TABLE_PREFIX` | Prefijo para todas las tablas (default `bc_`). |
| `SECRET_KEY` | Para firmar cookies de sesion. Cambia en produccion. |
| `TELEGRAM_BOT_TOKEN` | Token del bot. |
| `TELEGRAM_ENABLED` | `true`/`false` para iniciar polling. |
| `MAX_CONCURRENT_WORKERS` | Workers en paralelo hacia Davivienda (default 3). |
| `ALERT_FAILURE_THRESHOLD` | Numero de fallos consecutivos antes de disparar alerta (default 5). |
| `HOST`, `PORT` | Bind del web. |

## Endpoints web

- `GET /login` ingreso
- `GET /dashboard` lista de lotes + alertas
- `POST /jobs/new` crea lote pegando cedulas
- `GET /jobs/{id}` vista con progreso en tiempo real (WebSocket)
- `GET /jobs/{id}/results.csv` descarga CSV
- `GET /jobs/{id}/results.json` JSON
- `WS /ws/jobs/{id}` stream de eventos (`snapshot`, `item_start`, `item_done`, `ping`)

## Comandos Telegram

- `/start`, `/help`
- `/classify <cedula>` clasificacion en linea
- `/batch <c1 c2 ...>` lote (max 50 desde chat)
- `/count <min> <max>` cuantas cedulas reales hay en el rango (consulta `ani.ani_fin`)
- `/range <min> <max> <n> [r]` toma N cedulas reales del rango y las encola
  (agregar `r` para muestreo aleatorio en vez de ascendente; max n=500 por chat)
- `/jobs` ultimos lotes del chat
- `/job <id>` detalle de un lote
- `/subscribe`, `/unsubscribe` recibir alertas de fallas

## Rangos desde la UI

`/jobs/new` ahora tiene dos tabs:
- **Pegar cedulas** - como siempre, una por linea o separadas por coma.
- **Por rango (ANI)** - min/max + limite + modo (ascendente o aleatorio).
  Boton "Contar cedulas en el rango" hace AJAX a `/api/ani/count` para preview.

## CLI sin web

```bash
# clasificacion directa
python src/classify.py 79672391 79667000 79667015

# desde archivo
python src/classify.py --from-file cedulas.txt
```

## Cache / anti-block

- Cada cedula usa una sesion HTTP nueva (sin pool reuse).
- `User-Agent` rotado en cada llamada (`src/web/useragents.py`).
- OTP fresco por cedula (sin reutilizar tokens).
- Concurrencia limitada por `MAX_CONCURRENT_WORKERS` para no parecer DDoS.
- Si N llamadas consecutivas fallan -> alerta a Telegram + UI.

## Pendiente

Para llegar al detalle de la oferta (cupo, producto) cuando bucket = `TIENE_CUENTA`
hay que completar el flujo Transmit Security + OAuth en `apiauth.davivienda.com`.
La pubkey de Transmit es publica (`GET /risk-collect/device/conf`) asi que es
factible en Python puro; falta capturar HAR completo hasta ver la oferta y
mapear el endpoint final.
