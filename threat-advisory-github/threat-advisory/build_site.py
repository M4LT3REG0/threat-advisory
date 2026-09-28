"""
build_site.py — genera un panel ESTATICO para GitHub Pages.

Inyecta data/data.json en templates/panel.html y escribe:
  site/index.html   -> el panel listo para servir en Pages
  site/data.json    -> el mismo feed, por si la comunidad quiere consumir el JSON

GitHub Pages es estatico (no ejecuta Flask), por eso se pre-genera el HTML.

PUBLIC_STRIP (por defecto "0"): el build publico incluye el FEED COMPLETO
(mirrors .onion, wallets, cripto) porque los investigadores lo necesitan.
Ponlo a "1" solo si quieres un build saneado (sin esos indicadores).
"""
import json, os, re

HERE   = os.path.dirname(os.path.abspath(__file__))
PANEL  = os.path.join(HERE, "templates", "panel.html")
DATA   = os.path.join(HERE, "data", "data.json")
SAMPLE = os.path.join(HERE, "data", "data.sample.json")
SITE   = os.path.join(HERE, "site")
RL_BLOCK = re.compile(
    r'(<script type="application/json" id="rl-data">)(.*?)(</script>)', re.S)


def main():
    src = DATA if os.path.exists(DATA) else SAMPLE
    with open(src, encoding="utf-8") as f:
        data = json.load(f)

    strip = os.environ.get("PUBLIC_STRIP", "0") == "1"
    if strip:
        for g in data.get("groups", {}).values():
            g["mirrors"] = []
            g["wallets"] = []
        data["crypto_recent"] = []

    text = json.dumps(data, ensure_ascii=False, indent=0)
    if strip:
        # tambien dentro del texto de CTI reports y notas
        text = re.sub(r"[a-z2-7]{16,56}\.onion", "[.onion omitido]", text)
    html = open(PANEL, encoding="utf-8").read()
    html = RL_BLOCK.sub(lambda m: m.group(1) + "\n" + text + "\n" + m.group(3),
                        html, count=1)

    os.makedirs(SITE, exist_ok=True)
    with open(os.path.join(SITE, "index.html"), "w", encoding="utf-8") as f:
        f.write(html)
    with open(os.path.join(SITE, "data.json"), "w", encoding="utf-8") as f:
        f.write(text)

    print("site/ generado | PUBLIC_STRIP=%s | incidentes: %d"
          % (os.environ.get("PUBLIC_STRIP", "0"), len(data.get("incidents", []))))


if __name__ == "__main__":
    main()
