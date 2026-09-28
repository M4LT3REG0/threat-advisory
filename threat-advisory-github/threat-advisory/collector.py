"""
collector.py — refresca el FEED DE INCIDENTES del panel Ransom Radar.

Fusiona en vivo:
  - RansomLook  (https://www.ransomlook.io/api/recent/N)
  - ransomware.live (https://api.ransomware.live/v2/recentvictims)

Deduplica por grupo + dominio/primer termino de la victima (mismas reglas
que el panel) y enlaza a ransomware.live las victimas presentes alli.

Las secciones curadas (analyses, library, notes, raas, crypto, vulns, groups,
default_targets) NO se tocan: se conservan tal cual vienen en data/data.json.
Para automatizar alguna de ellas, anade un fetcher y asignalo en build().

Requiere acceso saliente HTTPS a ransomlook.io y api.ransomware.live desde el
servidor donde corra (en una intranet cerrada, abre esos dos destinos).
"""
import json, os, re, unicodedata, datetime
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
DATA   = os.path.join(HERE, "data", "data.json")
SAMPLE = os.path.join(HERE, "data", "data.sample.json")
TIMEOUT = 25
UA = {"User-Agent": "ransom-radar/1.0 (CTI internal use)"}

RANSOMLOOK = "https://www.ransomlook.io/api"
RWLIVE     = "https://api.ransomware.live"

# Cuantos elementos pedir a cada fuente
RL_RECENT_N   = 150
RWL_MAX       = 250

# Historico por actor (ransomware.live groupvictims)
GV_CAP        = 200   # victimas maximas embebidas por actor
GV_MAX_GROUPS = 80    # cuantos actores del feed traer (los mas activos)


def _get(url):
    r = requests.get(url, headers=UA, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()


# ---- normalizacion / merge (identico al build del panel) -------------------
def _ascii(s):
    return "".join(c for c in unicodedata.normalize("NFD", s or "")
                   if unicodedata.category(c) != "Mn")

def _gn(g):
    return re.sub(r"[^a-z0-9]", "", _ascii(g).lower())

def _sig(victim):
    t = re.split(r"[\s/]+", _ascii(victim).lower().strip())
    t = t[0] if t else ""
    t = re.sub(r"^www\.", "", t)
    return re.sub(r"[^a-z0-9]", "", t)

def _clean_activity(a):
    a = (a or "").strip()
    return "" if a in ("Not Found", "N/A", "Other", "") else a

def _clean_desc(d):
    d = (d or "").strip()
    return "" if d in ("N/A", "Not Found") else d


# ---- fetchers del feed -----------------------------------------------------
def fetch_ransomlook(n=RL_RECENT_N):
    """RansomLook posts recientes -> incidentes (source 'rl')."""
    data = _get(f"{RANSOMLOOK}/recent/{n}")
    out = []
    for p in data:
        victim = (p.get("post_title") or p.get("title") or "").strip()
        group  = (p.get("group_name") or p.get("group") or "").strip()
        if not victim or not group:
            continue
        disc = (p.get("discovered") or p.get("published") or "")[:19].replace("T", " ")
        out.append({
            "date": disc,
            "victim": victim,
            "group": group,
            "screen": (p.get("screen") or "").strip(),
            "description": (p.get("description") or "").strip(),
        })
    return out


def fetch_rwlive(n=RWL_MAX):
    """ransomware.live victimas recientes -> dicts saneados."""
    data = _get(f"{RWLIVE}/v2/recentvictims")
    out = []
    for v in data[:n]:
        victim = (v.get("victim") or v.get("post_title") or "").strip()
        group  = (v.get("group") or v.get("group_name") or "").strip()
        if not victim or not group:
            continue
        out.append({
            "victim": victim,
            "group": group,
            "country": (v.get("country") or "").strip().upper(),
            "activity": _clean_activity(v.get("activity")),
            "discovered": (v.get("discovered") or "")[:19].replace("T", " "),
            "attackdate": (v.get("attackdate") or "").strip(),
            "description": _clean_desc(v.get("description")),
            "domain": (v.get("domain") or "").strip(),
        })
    return out


def fetch_group_victims(group, cap=GV_CAP):
    """Historico de victimas de un grupo (ransomware.live groupvictims)."""
    slug = group.strip()
    try:
        data = _get(f"{RWLIVE}/v2/groupvictims/{slug}")
    except Exception:
        data = _get(f"{RWLIVE}/v2/groupvictims/{slug.lower()}")
    out = []
    for v in data:
        victim = (v.get("victim") or v.get("post_title") or "").strip()
        if not victim:
            continue
        out.append({
            "victim": victim,
            "country": (v.get("country") or "").strip().upper(),
            "activity": _clean_activity(v.get("activity")),
            "discovered": (v.get("discovered") or "")[:19].replace("T", " "),
            "attackdate": (v.get("attackdate") or "")[:10],
            "description": _clean_desc(v.get("description")),
            "domain": (v.get("domain") or "").strip(),
        })
    out.sort(key=lambda x: x["discovered"], reverse=True)
    return out[:cap]


def _parse_ttps(raw):
    """Aplana las TTP MITRE (soporta estructura anidada tactic/techniques y plana)."""
    out = []
    for t in (raw or []):
        if not isinstance(t, dict):
            continue
        tactic = (t.get("tactic_name") or t.get("tactic") or "").strip()
        techs = t.get("techniques")
        if isinstance(techs, list):          # anidada: tactic -> [techniques]
            for te in techs:
                if isinstance(te, dict):
                    out.append({"tactic": tactic,
                                "id": (te.get("technique_id") or "").strip(),
                                "technique": (te.get("technique_name") or "").strip()})
        else:                                 # plana
            out.append({"tactic": tactic,
                        "id": (t.get("technique_id") or "").strip(),
                        "technique": (t.get("technique") or t.get("technique_name") or "").strip()})
    return [t for t in out if t["technique"] or t["id"]]


def fetch_groups():
    """Directorio completo de grupos registrados en ransomware.live (/v2/groups)."""
    data = _get(f"{RWLIVE}/v2/groups")
    out = []
    for g in data:
        name = (g.get("name") or "").strip()
        if not name:
            continue
        ttps = _parse_ttps(g.get("ttps"))
        onion = any(loc.get("available") for loc in (g.get("locations") or [])
                    if isinstance(loc, dict))
        out.append({
            "slug": _gn(name),
            "name": name,
            "description": (g.get("description") or "").strip(),
            "ttps": ttps,
            "onion": onion,
            "added": (g.get("added_date") or "")[:10],
            "url": g.get("url") or ("https://www.ransomware.live/group/" + _gn(name)),
        })
    out.sort(key=lambda x: x["name"].lower())
    return out


def merge_incidents(rl, rwl, groups):
    canon = {_gn(k): k for k in groups}          # rwlive group -> nombre canonico RansomLook
    RWL_URL = "https://www.ransomware.live/group/"
    incidents, idx = [], {}
    for it in rl:
        it = dict(it)
        it["src"] = ["rl"]
        it.setdefault("country", "")
        it.setdefault("activity", "")
        it.setdefault("rwl_url", "")
        incidents.append(it)
        idx.setdefault(_gn(it["group"]) + "|" + _sig(it["victim"]), it)
    for v in rwl:
        k   = _gn(v["group"]) + "|" + _sig(v["victim"])
        url = RWL_URL + _gn(v["group"])
        hit = idx.get(k)
        if hit:
            if "rwl" not in hit["src"]:
                hit["src"].append("rwl")
            hit["rwl_url"]  = url
            hit["country"]  = hit["country"] or v["country"]
            hit["activity"] = hit["activity"] or v["activity"]
            if not hit["description"] and v["description"]:
                hit["description"] = v["description"]
        else:
            incidents.append({
                "date": v["discovered"], "victim": v["victim"],
                "group": canon.get(_gn(v["group"]), v["group"]),
                "screen": "", "description": v["description"],
                "country": v["country"], "activity": v["activity"],
                "src": ["rwl"], "rwl_url": url,
            })
    incidents.sort(key=lambda x: x["date"], reverse=True)
    return incidents


# ---- build: refresca el feed, conserva lo curado ---------------------------
def build():
    src = DATA if os.path.exists(DATA) else SAMPLE
    with open(src, encoding="utf-8") as f:
        base = json.load(f)
    groups = base.get("groups", {})

    rwl = []
    try:
        rl  = fetch_ransomlook()
        rwl = fetch_rwlive()
        merged = merge_incidents(rl, rwl, groups)
        if merged:
            base["incidents"] = merged
            xl = sum(1 for i in merged if "rwl" in i["src"] and "rl" in i["src"])
            ro = sum(1 for i in merged if i["src"] == ["rwl"])
            print(f"[collector] incidentes: {len(merged)} (cruzados {xl}, solo rwlive {ro})")
    except Exception as e:
        print(f"[collector] fallo el refresco de incidentes, mantengo cache: {e}")

    # Historico por actor: para cada grupo que aparece en el feed de
    # ransomware.live (incluye grupos NUEVOS en cuanto publican) baja su lista
    # de victimas. Clave = nombre de grupo normalizado.
    try:
        seen, order = set(), []
        for v in rwl:
            g = (v.get("group") or "").strip()
            if g and _gn(g) not in seen:
                seen.add(_gn(g))
                order.append(g)
        av = base.get("actor_victims", {}) or {}
        got = 0
        for g in order[:GV_MAX_GROUPS]:
            try:
                vics = fetch_group_victims(g)
                if vics:
                    av[_gn(g)] = vics
                    got += 1
            except Exception as e:
                print(f"[collector] groupvictims {g}: {e}")
        if av:
            base["actor_victims"] = av
            print(f"[collector] actor_victims: {got} grupos, "
                  f"{sum(len(x) for x in av.values())} victimas")
    except Exception as e:
        print(f"[collector] fallo actor_victims, mantengo cache: {e}")

    # Directorio COMPLETO de actores registrados en ransomware.live (~127).
    try:
        dirs = fetch_groups()
        if dirs:
            base["actors_dir"] = dirs
            print(f"[collector] actors_dir: {len(dirs)} grupos registrados")
    except Exception as e:
        print(f"[collector] fallo actors_dir, mantengo cache: {e}")

    # HOOKS para automatizar mas secciones (opcional): ver README.

    base["generated"] = datetime.date.today().isoformat()
    with open(DATA, "w", encoding="utf-8") as f:
        json.dump(base, f, ensure_ascii=False, indent=0)
    return base


if __name__ == "__main__":
    build()
    print("[collector] data/data.json actualizado.")
