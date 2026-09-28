# Threat Advisory — panel CTI de víctimas de ransomware

Panel de incidentes de ransomware (RansomLook + ransomware.live, fusionado y
deduplicado) con fichas CTI por actor, CVEs, notas de rescate, RaaS, cripto y
wallets. Se publica en GitHub Pages para la comunidad y también puede
autohospedarse (Flask) para un equipo.

- **Panel público:** `https://<usuario>.github.io/<repo>/`
- **Feed JSON:** `https://<usuario>.github.io/<repo>/data.json`

## Cómo actualizar (sin terminal — todo por la web de GitHub)

Cada **Commit** relanza la Action y actualiza la web en 1–2 min. No hace falta
terminal.

### A) Datos en vivo (pestaña *Incidentes*)
Se refresca **solo cada 6 h**. Para forzarlo ahora mismo:
1. Pestaña **Actions**.
2. Columna izquierda: **"Refrescar y publicar panel"**.
3. A la derecha: **Run workflow** → rama **main** → botón verde **Run workflow**.
4. Espera al **✓ verde** y recarga el panel.

### B) Secciones curadas (fichas CTI, CVEs, notas, RaaS, cripto, wallets)
Vienen de `data/data.sample.json`. Cuando tengas una versión nueva del fichero:
1. En el repo, entra en la carpeta **`data/`**.
2. Botón **Add file ▾ → Upload files**.
3. Arrastra el nuevo **`data.sample.json`** (mismo nombre → lo reemplaza).
4. Abajo, **Commit changes**.

### C) Panel o código (nuevas funciones / diseño)
Cuando tengas un fichero nuevo (p. ej. `templates/panel.html`):
1. Entra en la carpeta del fichero (p. ej. **`templates/`**).
2. Abre el fichero → **lápiz ✏️**, o usa **Upload files** para reemplazarlo.
3. **Commit changes**.

> En tu día a día solo usarás **A** (y normalmente ni eso). **B** y **C** solo
> cuando cambien las fichas/CVEs o el panel.

## Cómo funciona

GitHub Pages es estático, así que una **GitHub Action** (`.github/workflows/pages.yml`)
hace el trabajo en cada commit y cada 6 h:
1. `collector.py` baja los incidentes en vivo de RansomLook + ransomware.live,
   los fusiona y deduplica sobre la base curada.
2. `build_site.py` inyecta los datos en el panel y genera `site/index.html` +
   `site/data.json`.
3. La Action publica `site/` en GitHub Pages.

`data/data.sample.json` es la **base curada completa** (fichas, CVEs, notas,
RaaS, cripto, wallets). `data/data.json` (el resultado con incidentes frescos)
va en `.gitignore` y no se versiona: se genera en el runner y se publica en
Pages.

## Autohospedado (opcional, para equipo)

```
pip install -r requirements.txt
python collector.py        # refresca datos (necesita salida a internet)
python app.py              # panel en http://localhost:8000
```

Rutas: `GET /` (panel), `GET /api/data`, `GET /api/incidents`,
`GET /healthz`, `POST /refresh`. En producción, `gunicorn -w 2 -b 0.0.0.0:8000 app:app`
detrás de nginx/Caddy con TLS.

## Integración OpenCTI (opcional)

- **ransomware.live**: usa su **conector oficial de OpenCTI** (external-import).
- **RansomLook + feed fusionado**: `opencti_push.py` vuelca los incidentes a
  OpenCTI como Intrusion-Set → *targets* → Identity(víctima) + Location(país),
  etiquetados `threat-advisory`.

```
export OPENCTI_URL=https://opencti.tu-dominio
export OPENCTI_TOKEN=xxxx
pip install pycti
python opencti_push.py https://<usuario>.github.io/<repo>/data.json
```

## Uso responsable

Herramienta de CTI defensiva. Consume OSINT de **RansomLook** y
**ransomware.live**; respeta sus términos de uso y su atribución. Los mirrors
`.onion` y las wallets son indicadores para análisis, no para interactuar con
ellos: no los abras ni operes desde equipos corporativos. Uso bajo tu
responsabilidad.

## Licencia

MIT — ver [LICENSE](LICENSE). Rellena el titular del copyright.
