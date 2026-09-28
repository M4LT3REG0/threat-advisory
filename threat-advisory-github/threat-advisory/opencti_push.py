"""
opencti_push.py — integracion (opcion 3): vuelca el feed fusionado a OpenCTI.

Por cada incidente crea/actualiza en OpenCTI:
  - Intrusion-Set        el grupo de ransomware
  - Identity (Organization)  la victima
  - Relationship  intrusion-set  --targets-->  victima
  - (opcional) Location  por pais (ISO-3166 alpha-2) + relacion targets

Uso:
  export OPENCTI_URL=https://opencti.tu-dominio
  export OPENCTI_TOKEN=xxxxxxxx
  python opencti_push.py                 # lee data/data.json
  python opencti_push.py http://panel:8000/api/incidents   # lee del panel

NOTA: ransomware.live ya tiene un CONNECTOR OFICIAL de OpenCTI
(external-import). Para la parte de ransomware.live, lo recomendable es
activar ese conector. Este script aporta la parte de RansomLook y el feed
YA FUSIONADO/DEDUPLICADO, marcado con la etiqueta 'ransom-radar'.

Requiere: pip install pycti requests
"""
import json, os, sys
import requests

OPENCTI_URL   = os.environ.get("OPENCTI_URL")
OPENCTI_TOKEN = os.environ.get("OPENCTI_TOKEN")
HERE = os.path.dirname(os.path.abspath(__file__))
LABEL = "ransom-radar"


def load_incidents(src):
    if src and src.startswith("http"):
        return requests.get(src, timeout=30).json()
    path = os.path.join(HERE, "data", "data.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f).get("incidents", [])


def main(src=None):
    if not (OPENCTI_URL and OPENCTI_TOKEN):
        sys.exit("Define OPENCTI_URL y OPENCTI_TOKEN en el entorno.")
    from pycti import OpenCTIApiClient

    api = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)
    label = api.label.read_or_create_unchecked(value=LABEL, color="#d81b60")
    label_ids = [label["id"]] if label else []

    incidents = load_incidents(src)
    print(f"[opencti] {len(incidents)} incidentes a ingerir")

    seen_groups = {}
    for it in incidents:
        group  = it.get("group", "").strip()
        victim = it.get("victim", "").strip()
        if not group or not victim:
            continue

        # Intrusion-Set (grupo) — cache por nombre
        gid = seen_groups.get(group)
        if not gid:
            iset = api.intrusion_set.create(
                name=group,
                description=f"Grupo de ransomware (feed Ransom Radar).",
                objectLabel=label_ids,
            )
            gid = iset["id"]
            seen_groups[group] = gid

        # Identity (victima) como organizacion
        org = api.identity.create(
            type="Organization",
            name=victim,
            description=(it.get("description") or "")[:1000],
            objectLabel=label_ids,
        )

        # Relacion  grupo --targets--> victima
        api.stix_core_relationship.create(
            fromId=gid, toId=org["id"], relationship_type="targets",
            description=f"Publicado en DLS. Fuentes: {','.join(it.get('src', []))}."
                        + (f" ransomware.live: {it['rwl_url']}" if it.get("rwl_url") else ""),
        )

        # Location por pais (opcional)
        cc = (it.get("country") or "").strip()
        if cc:
            try:
                loc = api.location.create(type="Country", name=cc)
                api.stix_core_relationship.create(
                    fromId=gid, toId=loc["id"], relationship_type="targets")
            except Exception as e:
                print(f"[opencti] location {cc}: {e}")

    print("[opencti] ingesta completada.")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
