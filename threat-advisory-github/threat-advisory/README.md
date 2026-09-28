# Threat Advisory — servidor de equipo

Panel de incidentes de ransomware (RansomLook + ransomware.live, fusionado y
deduplicado) servido para todo el SOC, con datos en vivo. Cada analista abre
una URL; el servidor refresca los datos, no el navegador (sin CORS).

## Arranque rapido

```bash
cd rr-server
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python collector.py        # primer refresco (necesita salida a internet)
python app.py              # panel en http://localhost:8000
```

Si `collector.py` no tiene salida a las APIs, el panel arranca igual con el
`data/data.json` empaquetado (instantanea de partida).

## Que va en vivo y que no

| Seccion | Origen | En vivo |
|---|---|---|
| **Incidentes** (feed) | RansomLook `/api/recent` + ransomware.live `/v2/recentvictims` | **Si** — lo refresca `collector.py` |
| Fichas CTI, biblioteca, notas, RaaS, cripto, CVEs | curado/saneado | No — empaquetado en `data/data.json` |

Las secciones curadas están en español y saneadas (sin IDs de víctima ni
`.onion` operativos). Para automatizar alguna, ver *Extender el collector*.

## Rutas

| Ruta | Uso |
|---|---|
| `GET /` | Panel con el último `data.json` inyectado |
| `GET /api/data` | `data.json` completo (integraciones) |
| `GET /api/incidents` | Solo la lista de incidentes fusionada |
| `GET /healthz` | Estado + fecha del último refresco |
| `POST /refresh` | Fuerza un refresco |

## Refresco de datos

Tres opciones (elige una):

1. **Cron** (recomendado): `0 */6 * * *  cd /ruta/rr-server && .venv/bin/python collector.py`
2. **Scheduler embebido**: `export REFRESH_HOURS=6` antes de `python app.py` (usa APScheduler).
3. **Manual/bajo demanda**: `curl -X POST http://localhost:8000/refresh`
   (protégelo con `export REFRESH_TOKEN=xxx` → cabecera `X-Refresh-Token`).

## Producción

```bash
pip install gunicorn
gunicorn -w 2 -b 0.0.0.0:8000 app:app
```

Detrás de nginx/Caddy con TLS. En intranet cerrada, abre salida HTTPS solo a
`www.ransomlook.io` y `api.ransomware.live`. La watchlist de cada analista se
guarda en su navegador (localStorage); para una watchlist compartida del
equipo, persístela en el backend (siguiente iteración).

## Integración OpenCTI (opción 3)

- **ransomware.live**: usa su **conector oficial de OpenCTI** (external-import).
- **RansomLook + feed fusionado**: `opencti_push.py` vuelca los incidentes a
  OpenCTI como Intrusion-Set → *targets* → Identity(víctima) + Location(país),
  etiquetados `threat-advisory`.

```bash
export OPENCTI_URL=https://opencti.tu-dominio
export OPENCTI_TOKEN=xxxx
pip install pycti
python opencti_push.py http://localhost:8000/api/incidents
```

Lánzalo por cron tras cada refresco, o adáptalo como conector interno.

## Extender el collector

En `collector.build()` hay un hook comentado. Para automatizar, p. ej., los
CVE:

```python
def fetch_vulns():
    # mapea la fuente a [{"cve","product","groups":[...]}, ...]
    ...
try:    base["vulns"] = fetch_vulns()
except Exception as e:  print("vulns:", e)
```

Cada fetcher va en su propio `try/except`: si una fuente falla, se conserva la
sección que ya había. Los nombres de grupo se canonizan contra `data.groups`,
así que las fichas/CTI/CVEs siguen enlazando aunque una fuente escriba el
grupo distinto (`incransom` ↔ `inc ransom`).

## Estructura

```
rr-server/
  app.py              servidor Flask (sirve panel + API + /refresh)
  collector.py        fetch + merge + dedup -> data/data.json
  opencti_push.py     integración OpenCTI (opcional)
  templates/panel.html  el panel (una sola página; el server le inyecta datos)
  data/data.json      caché de datos (se refresca; incluye lo curado)
  requirements.txt
```

## Datos no incluidos

Este repositorio publica **la herramienta, no la base de datos de víctimas**.
`data/data.json` (feed en vivo: víctimas, mirrors `.onion`, wallets) está en
`.gitignore` y **no se versiona**. El repo trae `data/data.sample.json` vacío;
cada despliegue genera su propio `data.json` ejecutando `python collector.py`.
Si no hay `data.json`, el panel arranca con la muestra vacía.

## Uso responsable

Herramienta de CTI defensiva. Consume OSINT de RansomLook y ransomware.live;
respeta sus términos de uso y su atribución. No redistribuyas de forma masiva
sus datos ni publiques listados agregados de víctimas. Los mirrors `.onion` y
las wallets son indicadores para análisis, no para interactuar con ellos; no
los abras ni operes desde equipos corporativos. Uso bajo tu responsabilidad.

## Licencia

MIT — ver [LICENSE](LICENSE). Rellena el titular del copyright antes de publicar.

## Publicar en GitHub

```bash
cd threat-advisory
git init
git add .
git commit -m "Threat Advisory: panel CTI de víctimas de ransomware"
git branch -M main
git remote add origin git@github.com:<tu-usuario>/threat-advisory.git
git push -u origin main
```

Antes del primer push, comprueba que no se cuela el cache de datos:

```bash
git status --ignored        # data/data.json debe salir como 'ignored'
git ls-files | grep data/   # solo debe aparecer data/data.sample.json
```

## Publicar en GitHub Pages (para la comunidad)

GitHub Pages sirve el panel estático y una GitHub Action lo refresca sola.

1. Sube el repo (sección anterior).
2. **Settings → Pages → Build and deployment → Source: GitHub Actions.**
3. El workflow `.github/workflows/pages.yml` ya viene incluido: se ejecuta al
   hacer push, cada 6 h y con **Actions → Run workflow** (manual).
4. Al terminar, la URL pública sale en el job (`deploy`) y en Settings → Pages:
   `https://<usuario>.github.io/<repo>/`

La Action ejecuta `collector.py` (los runners de GitHub sí tienen salida a las
APIs) y `build_site.py`, que genera `site/index.html` + `site/data.json`.

- **Panel**: `https://<usuario>.github.io/<repo>/`
- **Feed JSON** (para consumir): `https://<usuario>.github.io/<repo>/data.json`

Build público: incluye el **feed completo** (mirrors `.onion`, wallets, cripto),
que es lo que necesitan los investigadores. Para un build saneado, pon
`PUBLIC_STRIP=1` en el workflow. Nada de datos se versiona en git: se genera en
el runner y se publica en Pages. Respeta la atribución y los términos de las
fuentes (RansomLook, ransomware.live).

### Actualizar

- **Datos**: automático cada 6 h; o **Actions → Run workflow** para forzarlo.
- **Código/panel**: `git push` a `main` → la Action redepliega.
