from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from packages.common.canonical import canonical_json_bytes, sha256_hex


def render_mission_report(report: dict[str, Any], path: Path) -> str:
    """Render a self-contained, offline-safe mission report."""
    destination = path.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    document = _document(report)
    destination.write_text(document, encoding="utf-8")
    return sha256_hex(document)


def report_json_hash(report: dict[str, Any]) -> str:
    return sha256_hex(canonical_json_bytes(report))


def _document(report: dict[str, Any]) -> str:
    outcomes = report["outcomes"]
    vocabulary = report["vocabulary"]
    cards = "".join(_outcome_card(item) for item in outcomes)
    if not cards:
        cards = (
            '<section class="empty"><strong>No qualified outcomes.</strong>'
            f'<p>{_escape(vocabulary["empty_result"])}</p></section>'
        )
    source_count = len(
        {
            str(source["source_id"])
            for outcome in outcomes
            for source in outcome["source_evidence"]
        }
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <title>{_escape(report['mission_name'])}</title>
  <style>
    :root {{ color-scheme: dark; --ink:#f4f7fb; --muted:#9aa8b7; --panel:#121a24;
      --line:#2b3a49; --accent:#5ce1c3; --hot:#ffb454; --bg:#080d13; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:var(--bg); color:var(--ink); font:15px/1.55
      ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }}
    main {{ width:min(1180px,calc(100% - 32px)); margin:0 auto; padding:48px 0 80px; }}
    header {{ border-bottom:1px solid var(--line); padding-bottom:28px; }}
    .eyebrow,.label {{ color:var(--accent); font-size:.72rem; font-weight:800;
      letter-spacing:.14em; text-transform:uppercase; }}
    h1 {{ font-size:clamp(2rem,5vw,4.6rem); line-height:.98; margin:12px 0 20px;
      max-width:900px; letter-spacing:-.04em; }}
    .objective {{ color:#cad4df; max-width:850px; font-size:1.08rem; }}
    .stats {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:1px;
      background:var(--line); border:1px solid var(--line); margin:26px 0 38px; }}
    .stat {{ background:var(--panel); padding:18px; }}
    .stat strong {{ display:block; font-size:1.45rem; }}
    .stat span {{ color:var(--muted); font-size:.78rem; }}
    .outcomes {{ display:grid; gap:18px; }}
    article,.empty {{ background:var(--panel); border:1px solid var(--line); padding:24px; }}
    .outcome-head {{ display:flex; align-items:flex-start; justify-content:space-between;
      gap:20px; }}
    h2 {{ margin:5px 0 8px; font-size:1.35rem; line-height:1.25; }}
    .score {{ min-width:82px; text-align:right; font-size:2rem; font-weight:850;
      color:var(--accent); }}
    .score small {{ display:block; color:var(--muted); font-size:.65rem;
      letter-spacing:.1em; text-transform:uppercase; }}
    .class {{ display:inline-block; color:var(--hot); font-weight:800; text-transform:uppercase;
      letter-spacing:.08em; font-size:.72rem; }}
    .why {{ color:#c4d0db; margin:10px 0 20px; }}
    .columns {{ display:grid; grid-template-columns:1fr 1fr; gap:22px; }}
    ul {{ margin:8px 0 0; padding-left:20px; }}
    li {{ margin:6px 0; }}
    .evidence {{ margin-top:22px; padding-top:18px; border-top:1px solid var(--line); }}
    .evidence a {{ color:var(--accent); text-decoration-thickness:1px; }}
    .evidence li {{ color:var(--muted); }}
    footer {{ margin-top:34px; color:var(--muted); border-top:1px solid var(--line);
      padding-top:18px; font-size:.8rem; }}
    @media (max-width:720px) {{ .stats {{ grid-template-columns:1fr 1fr; }}
      .columns {{ grid-template-columns:1fr; }} .outcome-head {{ display:block; }}
      .score {{ text-align:left; margin-top:12px; }} main {{ padding-top:28px; }} }}
  </style>
</head>
<body>
<main>
  <header>
    <div class="eyebrow">Outcome intelligence · evidence locked</div>
    <h1>{_escape(report['mission_name'])}</h1>
    <p class="objective">{_escape(report['objective'])}</p>
  </header>
  <section class="stats" aria-label="Report summary">
    <div class="stat"><strong>{len(outcomes)}</strong>
      <span>qualified {_escape(vocabulary['plural'])}</span></div>
    <div class="stat"><strong>{source_count}</strong><span>independent sources</span></div>
    <div class="stat"><strong>{_escape(report['workflow']['agent_mode'])}</strong>
      <span>review mode</span></div>
    <div class="stat">
      <strong>{'yes' if report['verification']['all_claims_cited'] else 'no'}</strong>
      <span>all claims cited</span></div>
  </section>
  <section class="outcomes" aria-label="Ranked outcomes">{cards}</section>
  <footer>Generated {_escape(report['generated_at'])} · Ranking stays in deterministic code.
    Research roles can challenge evidence; they cannot publish or change policy.</footer>
</main>
</body>
</html>
"""


def _outcome_card(outcome: dict[str, Any]) -> str:
    actions = "".join(f"<li>{_escape(item)}</li>" for item in outcome["recommended_actions"])
    unknown = "".join(f"<li>{_escape(item)}</li>" for item in outcome["unknown"])
    sources = "".join(
        (
            f'<li><a href="{_escape(source["url"])}">{_escape(source["title"])}</a>'
            f' · {_escape(source["source_type"])}</li>'
        )
        for source in outcome["source_evidence"]
    )
    return f"""<article>
  <div class="outcome-head">
    <div><span class="class">{_escape(outcome['priority_class'])} ·
      {_escape(outcome['stage'])}</span>
      <h2>{_escape(outcome['title'])}</h2></div>
    <div class="score">{float(outcome['priority_score']):.1f}<small>priority score</small></div>
  </div>
  <p class="why">{_escape(outcome['why_now'])}</p>
  <div class="columns">
    <div><span class="label">Recommended actions</span><ul>{actions}</ul></div>
    <div><span class="label">Still unknown</span><ul>{unknown}</ul></div>
  </div>
  <div class="evidence"><span class="label">Evidence</span><ul>{sources}</ul></div>
</article>"""


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def dump_report(report: dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
