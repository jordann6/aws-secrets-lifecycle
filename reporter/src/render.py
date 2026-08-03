"""Render the single-page HTML dashboard. Self-contained: inline CSS,
no external assets, no CDN."""

import html as html_mod

AGE_BUCKETS = [(0, 90, "0-90d"), (91, 180, "91-180d"), (181, 365, "181-365d"),
               (366, 100000, ">365d")]
TIER_ORDER = ["low", "medium", "high"]
TIER_COLORS = {"low": "#2e7d32", "medium": "#f9a825", "high": "#c62828"}


def bucket_ages(analyses):
    counts = {label: 0 for _, _, label in AGE_BUCKETS}
    for a in analyses:
        age = int(a.get("age_days", 0))
        for lo, hi, label in AGE_BUCKETS:
            if lo <= age <= hi:
                counts[label] += 1
                break
    return counts


def bucket_tiers(analyses):
    counts = {t: 0 for t in TIER_ORDER}
    for a in analyses:
        counts[a.get("risk_tier", "low")] = counts.get(a.get("risk_tier", "low"), 0) + 1
    return counts


def _bar_rows(counts, total, colors=None):
    rows = []
    for label, n in counts.items():
        pct = int(100 * n / total) if total else 0
        color = (colors or {}).get(label, "#1565c0")
        rows.append(
            f'<div class="row"><span class="lbl">{html_mod.escape(str(label))}</span>'
            f'<span class="bar"><span style="width:{pct}%;background:{color}"></span></span>'
            f'<span class="n">{n}</span></div>')
    return "\n".join(rows)


def _runbook_html(runbook):
    if not runbook:
        return "<p class='muted'>No runbook generated.</p>"
    steps = "".join(
        f"<li><strong>{html_mod.escape(s['action'])}</strong>"
        f"<br><em>Verify: {html_mod.escape(s['verification'])}</em></li>"
        for s in sorted(runbook.get("steps", []), key=lambda s: s.get("order", 0)))
    rollback = "".join(f"<li>{html_mod.escape(r)}</li>"
                       for r in runbook.get("rollback", []))
    return (
        f"<p>Confidence: <strong>{html_mod.escape(runbook.get('confidence', '?'))}</strong>"
        f" &middot; {html_mod.escape(runbook.get('confidence_rationale', ''))}</p>"
        f"<ol>{steps}</ol>"
        f"<p class='muted'>Rollback:</p><ul>{rollback}</ul>")


def render(scan_id, metrics, analyses):
    total = len(analyses)
    ages = bucket_ages(analyses)
    tiers = bucket_tiers(analyses)
    coverage = metrics.get("findings_by_control", {})

    top_risk = sorted(
        [a for a in analyses if a.get("kind") != "iam_access_key"],
        key=lambda a: a.get("readiness_score", 100))[:5]
    risk_cards = []
    for a in top_risk:
        consumers = a.get("consumer_map", {}).get("consumers", [])
        clist = "".join(
            f"<li><code>{html_mod.escape(str(c.get('principal_arn') or 'unidentified'))}</code>"
            f" ({c.get('access_count', 0)} reads)</li>"
            for c in consumers) or "<li class='muted'>no observed consumers</li>"
        tier = a.get("risk_tier", "low")
        risk_cards.append(f"""
      <details class="card">
        <summary>
          <span class="pill" style="background:{TIER_COLORS[tier]}">{tier}</span>
          <strong>{html_mod.escape(a.get('name', ''))}</strong>
          <span class="muted">readiness {a.get('readiness_score', '?')}/100
            &middot; {a.get('age_days', '?')}d old</span>
        </summary>
        <h4>Consumers</h4><ul>{clist}</ul>
        <h4>Rotation runbook</h4>{_runbook_html(a.get('runbook'))}
      </details>""")

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secrets Lifecycle: scan {html_mod.escape(scan_id)}</title>
<style>
  body {{ font: 15px/1.5 -apple-system, "Segoe UI", sans-serif; margin: 0;
         background: #f5f6f8; color: #1c2733; }}
  header {{ background: #101828; color: #fff; padding: 20px 28px; }}
  header h1 {{ margin: 0; font-size: 20px; }}
  header p {{ margin: 4px 0 0; color: #98a2b3; }}
  main {{ max-width: 1000px; margin: 24px auto; padding: 0 16px;
          display: grid; gap: 16px; }}
  .tiles {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 12px; }}
  .tile {{ background: #fff; border-radius: 8px; padding: 14px 16px;
           box-shadow: 0 1px 2px rgba(16,24,40,.06); }}
  .tile .v {{ font-size: 26px; font-weight: 700; }}
  .tile .k {{ color: #667085; font-size: 12px; text-transform: uppercase; }}
  section {{ background: #fff; border-radius: 8px; padding: 18px 20px;
             box-shadow: 0 1px 2px rgba(16,24,40,.06); }}
  h2 {{ font-size: 15px; margin: 0 0 12px; }}
  .row {{ display: flex; align-items: center; gap: 10px; margin: 6px 0; }}
  .lbl {{ width: 220px; font-size: 13px; color: #475467; }}
  .bar {{ flex: 1; background: #eaecf0; border-radius: 4px; height: 14px;
          overflow: hidden; display: block; }}
  .bar span {{ display: block; height: 100%; }}
  .n {{ width: 30px; text-align: right; font-variant-numeric: tabular-nums; }}
  .card {{ border: 1px solid #eaecf0; border-radius: 8px; padding: 10px 14px;
           margin: 8px 0; }}
  .card summary {{ cursor: pointer; display: flex; gap: 10px; align-items: center; }}
  .pill {{ color: #fff; border-radius: 10px; padding: 1px 10px; font-size: 12px; }}
  .muted {{ color: #98a2b3; }}
  code {{ background: #f2f4f7; padding: 1px 5px; border-radius: 4px; font-size: 12px; }}
</style></head><body>
<header>
  <h1>Secrets Lifecycle and Rotation Readiness</h1>
  <p>Scan {html_mod.escape(scan_id)}</p>
</header>
<main>
  <div class="tiles">
    <div class="tile"><div class="v">{metrics.get('total_secrets', total)}</div>
      <div class="k">secrets under management</div></div>
    <div class="tile"><div class="v">{metrics.get('mean_age_days', '?')}d</div>
      <div class="k">mean age</div></div>
    <div class="tile"><div class="v">{metrics.get('median_age_days', '?')}d</div>
      <div class="k">median age</div></div>
    <div class="tile"><div class="v">{metrics.get('pct_with_identified_consumers', '?')}%</div>
      <div class="k">identified consumer set</div></div>
    <div class="tile"><div class="v">{metrics.get('pct_with_verified_rotation_path', '?')}%</div>
      <div class="k">verified rotation path</div></div>
  </div>
  <section><h2>Secret age distribution</h2>{_bar_rows(ages, total)}</section>
  <section><h2>Rotation readiness distribution</h2>
    {_bar_rows(tiers, total, TIER_COLORS)}</section>
  <section><h2>Control findings by framework</h2>
    {_bar_rows(coverage, max(coverage.values()) if coverage else 0)}</section>
  <section><h2>Top risk secrets</h2>{''.join(risk_cards)}</section>
</main></body></html>"""
