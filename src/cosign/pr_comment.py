"""Markdown PR comment for a cosign run: score, change from the base branch, attack grid, top fixes.

    python src/cosign/pr_comment.py --head head.json [--base base.json] [--out comment.md]
                                    [--base-name main] [--run N] [--github-output "$GITHUB_OUTPUT"]

Input is what `cosign test --json` prints (one row) or a `cosign matrix --out` file (a list of
rows; --run picks one, default 0). The base row is the one with the same agent and guards, if any.
Stdlib only and no package imports, so the GitHub Action can run this file straight from its own
checkout whatever version of cosign the PR's base branch has.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

MARKER = "<!-- cosign-report -->"
FULL_MUTATIONS = 8   # len(attacks.MUTATIONS), kept in sync by a test; fewer rewrites (or < 3 trials) = weak test
MIN_TRIALS = 3


def _cell(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _signed(n: float) -> str:
    return f"+{n:g}" if n > 0 else f"−{abs(n):g}" if n < 0 else "±0"


def _family(entry) -> tuple[int, int, str | None]:
    c, n, w = (list(entry) + [None, None, None])[:3]
    return int(c or 0), int(n or 0), w


def _grid_cell(entry) -> str:
    if entry is None:
        return "–"
    c, n, w = _family(entry)
    if c:
        return f"🔴 breached {c}/{n}" + (f" via `{_cell(w)}`" if w else "")
    return f"🟢 held {c}/{n}"


def headline(head: dict, base: dict | None, base_name: str = "main") -> str:
    score, limit = head["score"], head["limit"]
    line = f"**Score {score}/100**"
    if base is not None:
        d = score - base["score"]
        arrow = "▲" if d > 0 else "▼" if d < 0 else "="
        line += f" ({arrow} {_signed(d)} vs `{_cell(base_name)}`)"
    line += f" · **Spend limit {limit:g} USDC**"
    if base is not None and base["limit"] != limit:
        line += f" (was {base['limit']:g})"
    return line


def test_strength(row: dict) -> str:
    trials, muts = row.get("trials"), row.get("mutations")
    bits = [f"agent `{_cell(row.get('agent', '?'))}`",
            f"guards `{_cell(', '.join(row.get('guards') or ['none']))}`"]
    if trials is not None:
        bits.append(f"{trials} trial{'s' if trials != 1 else ''}")
    if muts is not None:
        bits.append(f"{muts}/{FULL_MUTATIONS} attacker rewrites")
    weak = trials is None or muts is None or trials < MIN_TRIALS or muts < FULL_MUTATIONS
    return " · ".join(bits) + (" · ⚠️ weak test, limit capped" if weak else "")


def attack_grid(head: dict, base: dict | None, base_name: str = "main") -> list[str]:
    fams_h = head.get("by_family") or {}
    fams_b = (base or {}).get("by_family") or {}
    names = list(fams_h) + [f for f in fams_b if f not in fams_h]
    if not names:
        return ["_No attack scenarios in this run._"]
    cols = ["Attack", "This PR"] + ([f"`{_cell(base_name)}`"] if base is not None else [])
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for f in names:
        row = [f"`{_cell(f)}`", _grid_cell(fams_h.get(f))]
        if base is not None:
            row.append(_grid_cell(fams_b.get(f)))
        lines.append("| " + " | ".join(row) + " |")
    return lines


def top_fixes(head: dict, n: int = 3) -> list[str]:
    fixes = list(head.get("fixes") or [])[:n]
    if not fixes:
        breached = any(_family(e)[0] for e in (head.get("by_family") or {}).values())
        return ["_No fixes suggested._" if breached else "_None needed: every attack held._"]
    return [f"{i}. {f}" for i, f in enumerate(fixes, 1)]


def format_comment(head: dict, base: dict | None = None, base_name: str = "main") -> str:
    parts = [MARKER, "## Cosign crash test", "", headline(head, base, base_name), "", test_strength(head)]
    if base is None:
        parts += ["", f"_No baseline from `{_cell(base_name)}`, so no comparison._"]
    parts += ["", "### Attack grid", "", *attack_grid(head, base, base_name), "", "### Top fixes", "", *top_fixes(head)]
    return "\n".join(parts) + "\n"


# --- input -------------------------------------------------------------------------------
def load_rows(path: str | Path) -> list[dict]:
    data = json.loads(Path(path).read_text())
    rows = data if isinstance(data, list) else [data]
    return [r for r in rows if isinstance(r, dict) and "score" in r]


def pick(rows: list[dict], index: int) -> dict:
    if not 0 <= index < len(rows):
        raise SystemExit(f"--run {index} out of range: {len(rows)} scored run(s)")
    return rows[index]


def match_base(head: dict, rows: list[dict], index: int) -> dict | None:
    key = (head.get("agent"), list(head.get("guards") or []))
    for r in rows:
        if (r.get("agent"), list(r.get("guards") or [])) == key:
            return r
    return rows[index] if 0 <= index < len(rows) else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pr_comment")
    ap.add_argument("--head", required=True, help="results JSON from the PR")
    ap.add_argument("--base", default=None, help="results JSON from the base branch (missing/empty: no baseline)")
    ap.add_argument("--base-name", default="main", help="label for the base branch")
    ap.add_argument("--run", type=int, default=0)
    ap.add_argument("--out", default=None)
    ap.add_argument("--github-output", default=None, help="append score/limit/score_delta to this file")
    args = ap.parse_args(argv)

    head = pick(load_rows(args.head), args.run)
    base = None
    if args.base and Path(args.base).is_file() and Path(args.base).stat().st_size:
        try:
            base = match_base(head, load_rows(args.base), args.run)
        except json.JSONDecodeError:
            print(f"warning: {args.base} is not valid JSON, no baseline", file=sys.stderr)

    text = format_comment(head, base, args.base_name or "main")
    if args.out:
        Path(args.out).write_text(text)
    else:
        sys.stdout.write(text)
    if args.github_output:
        delta = "" if base is None else str(head["score"] - base["score"])
        with open(args.github_output, "a") as f:
            f.write(f"score={head['score']}\nlimit={head['limit']}\nscore_delta={delta}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
