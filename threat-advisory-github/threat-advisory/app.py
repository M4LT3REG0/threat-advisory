"""
app.py — sirve el panel Ransom Radar con datos en vivo para todo el equipo.

Rutas:
  GET  /                 panel HTML con el ultimo data.json inyectado (mismo origen)
  GET  /api/data         data.json completo (para integraciones)
  GET  /api/incidents    solo la lista de incidentes fusionada
  GET  /healthz          estado + fecha del ultimo refresco
  POST /refresh          fuerza un refresco (protegible con REFRESH_TOKEN)

El panel lee los datos incrustados en la propia pagina (mismo origen), asi que
NO hay problema de CORS: el navegador del analista no llama a ninguna API
externa; lo hace el servidor.

Variables de entorno:
  RR_HOST         (por defecto 0.0.0.0)
  RR_PORT         (por defecto 8000)
  REFRESH_HOURS   si se define y APScheduler esta instalado, refresca cada N horas
  REFRESH_TOKEN   si se define, /refresh exige cabecera  X-Refresh-Token: <token>
"""
import json, os, re
from flask import Flask, Response, jsonify, request, abort
import collector

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL = os.path.join(HERE, "templates", "panel.html")
DATA   = os.path.join(HERE, "data", "data.json")
SAMPLE = os.path.join(HERE, "data", "data.sample.json")
RL_BLOCK = re.compile(
    r'(<script type="application/json" id="rl-data">)(.*?)(</script>)', re.S)

app = Flask(__name__)


def _data_file():
    # usa el cache real si existe; si no, la muestra vacia versionada
    return DATA if os.path.exists(DATA) else SAMPLE


def _load_data_text():
    with open(_data_file(), encoding="utf-8") as f:
        return f.read()


def _render_panel():
    with open(PANEL, encoding="utf-8") as f:
        html = f.read()
    data = _load_data_text()
    return RL_BLOCK.sub(
        lambda m: m.group(1) + "\n" + data + "\n" + m.group(3), html, count=1)


@app.get("/")
def index():
    return Response(_render_panel(), mimetype="text/html")


@app.get("/api/data")
def api_data():
    return Response(_load_data_text(), mimetype="application/json")


@app.get("/api/incidents")
def api_incidents():
    data = json.loads(_load_data_text())
    return jsonify(data.get("incidents", []))


@app.get("/healthz")
def healthz():
    data = json.loads(_load_data_text())
    return jsonify(status="ok",
                   generated=data.get("generated"),
                   incidents=len(data.get("incidents", [])))


@app.post("/refresh")
def refresh():
    token = os.environ.get("REFRESH_TOKEN")
    if token and request.headers.get("X-Refresh-Token") != token:
        abort(401)
    data = collector.build()
    return jsonify(status="refreshed",
                   generated=data.get("generated"),
                   incidents=len(data.get("incidents", [])))


def _maybe_schedule():
    hours = os.environ.get("REFRESH_HOURS")
    if not hours:
        return
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
    except Exception:
        print("[app] APScheduler no instalado; refresco automatico desactivado.")
        return
    sched = BackgroundScheduler(daemon=True)
    sched.add_job(collector.build, "interval", hours=float(hours),
                  next_run_time=None)
    sched.start()
    print(f"[app] refresco automatico cada {hours} h activado.")


_maybe_schedule()

if __name__ == "__main__":
    host = os.environ.get("RR_HOST", "0.0.0.0")
    port = int(os.environ.get("RR_PORT", "8000"))
    app.run(host=host, port=port)
