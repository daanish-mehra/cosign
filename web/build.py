"""Build the Cosign site from real run output.

    python web/build.py --results runs/<ts>/results.json [more results files...] \
        --traces runs/<ts>/traces.jsonl --onchain logs/watch.log --out site/

Copies web/ into --out and bakes the data into the pages, so site/ opens anywhere
(double-click, or any static host). Without --results the pages fall back to sample data.
"""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
PAGES = ["index.html", "app.html", "leaderboard.html"]
ASSETS = ["cosign.css", "sample-results.json", "sample-traces.jsonl"]


def safe(obj) -> str:
    return json.dumps(obj).replace("</", "<\\/")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", nargs="*", default=[], help="one or more cosign matrix results files")
    ap.add_argument("--traces", nargs="*", default=[], help="traces.jsonl files from the same runs")
    ap.add_argument("--out", default="site")
    a = ap.parse_args()

    results = []
    for p in a.results:
        data = json.loads(Path(p).read_text())
        results += data if isinstance(data, list) else [data]
    results = [r for r in results if r.get("benign_utility", 0) > 0 or r.get("p_compromise", 0) > 0]  # drop all-error runs

    traces = []
    for p in a.traces:
        traces += [json.loads(l) for l in Path(p).read_text().splitlines() if l.strip()]

    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    for f in ASSETS:
        shutil.copy(HERE / f, out / f)
    for page in PAGES:
        html = (HERE / page).read_text()
        if results:
            html = html.replace("/*__RESULTS__*/", safe(results))
        if traces and page == "app.html":
            html = html.replace("/*__TRACES__*/", safe(traces))
        (out / page).write_text(html)
    print(f"built {out}/ with {len(results)} runs, {len(traces)} traced episodes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
