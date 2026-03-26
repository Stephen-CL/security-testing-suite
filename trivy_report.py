#!/usr/bin/env python3
"""
trivy_report.py
---------------
Converts a Trivy `config` scan JSON report into a polished, self-contained
HTML security dashboard.

Usage:
    python trivy_report.py report.json
    python trivy_report.py report.json -o my-report.html
    python trivy_report.py report.json -o my-report.html --title "Production Helm Scan"

Requirements: Python 3.8+ standard library only (no third-party dependencies).
"""

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


# ──────────────────────────────────────────────────────────────
# Severity helpers
# ──────────────────────────────────────────────────────────────
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

SEVERITY_META = {
    "CRITICAL": {"color": "#ff2d55", "bg": "rgba(255,45,85,0.12)",  "icon": "💀", "rank": 5},
    "HIGH":     {"color": "#ff6b2b", "bg": "rgba(255,107,43,0.12)", "icon": "🔥", "rank": 4},
    "MEDIUM":   {"color": "#ffcc00", "bg": "rgba(255,204,0,0.12)",  "icon": "⚠️",  "rank": 3},
    "LOW":      {"color": "#34c759", "bg": "rgba(52,199,89,0.12)",  "icon": "ℹ️",  "rank": 2},
    "UNKNOWN":  {"color": "#8e8e93", "bg": "rgba(142,142,147,0.12)","icon": "❓", "rank": 1},
}


def sev_color(sev: str) -> str:
    return SEVERITY_META.get(sev.upper(), SEVERITY_META["UNKNOWN"])["color"]

def sev_bg(sev: str) -> str:
    return SEVERITY_META.get(sev.upper(), SEVERITY_META["UNKNOWN"])["bg"]

def sev_icon(sev: str) -> str:
    return SEVERITY_META.get(sev.upper(), SEVERITY_META["UNKNOWN"])["icon"]

def sev_rank(sev: str) -> int:
    return SEVERITY_META.get(sev.upper(), SEVERITY_META["UNKNOWN"])["rank"]


# ──────────────────────────────────────────────────────────────
# Parse Trivy JSON
# ──────────────────────────────────────────────────────────────
def parse_report(data: dict) -> dict:
    results = data.get("Results", [])
    all_misconfigs = []

    for result in results:
        target = result.get("Target", "unknown")
        resource_class = result.get("Class", "")
        resource_type = result.get("Type", "")
        misconfigs = result.get("Misconfigurations", []) or []

        for m in misconfigs:
            all_misconfigs.append({
                "target":      target,
                "class":       resource_class,
                "type":        resource_type,
                "id":          m.get("ID", ""),
                "avd_id":      m.get("AVDID", ""),
                "title":       m.get("Title", "No title"),
                "description": m.get("Description", ""),
                "message":     m.get("Message", ""),
                "severity":    m.get("Severity", "UNKNOWN").upper(),
                "status":      m.get("Status", ""),
                "resolution":  m.get("Resolution", ""),
                "references":  m.get("References", []),
            })

    # Sort: severity desc, then target, then id
    all_misconfigs.sort(key=lambda x: (-sev_rank(x["severity"]), x["target"], x["id"]))

    severity_counts = Counter(m["severity"] for m in all_misconfigs)
    target_counts   = Counter(m["target"]   for m in all_misconfigs)

    schema_version = data.get("SchemaVersion", "")
    artifact_name  = data.get("ArtifactName", "")
    artifact_type  = data.get("ArtifactType", "")
    created_at     = data.get("CreatedAt", "")

    return {
        "schema_version":  schema_version,
        "artifact_name":   artifact_name,
        "artifact_type":   artifact_type,
        "created_at":      created_at,
        "misconfigs":      all_misconfigs,
        "severity_counts": severity_counts,
        "target_counts":   target_counts,
        "total":           len(all_misconfigs),
    }


# ──────────────────────────────────────────────────────────────
# HTML builder
# ──────────────────────────────────────────────────────────────
def escape(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def build_stat_cards(parsed: dict) -> str:
    cards = []
    total = parsed["total"]

    cards.append(f"""
        <div class="stat-card stat-total">
            <div class="stat-value">{total}</div>
            <div class="stat-label">Total Findings</div>
        </div>""")

    for sev in SEVERITY_ORDER:
        count = parsed["severity_counts"].get(sev, 0)
        color = sev_color(sev)
        icon  = sev_icon(sev)
        cards.append(f"""
        <div class="stat-card" style="--sev-color:{color};">
            <div class="stat-icon">{icon}</div>
            <div class="stat-value" style="color:{color};">{count}</div>
            <div class="stat-label">{sev.title()}</div>
        </div>""")

    return "\n".join(cards)


def build_severity_bar(parsed: dict) -> str:
    total = parsed["total"]
    if total == 0:
        return '<div class="sev-bar-empty">No findings detected ✓</div>'

    segments = []
    for sev in SEVERITY_ORDER:
        count = parsed["severity_counts"].get(sev, 0)
        if count == 0:
            continue
        pct   = count / total * 100
        color = sev_color(sev)
        segments.append(
            f'<div class="sev-seg" style="width:{pct:.1f}%;background:{color};" '
            f'title="{sev}: {count}"></div>'
        )
    return f'<div class="sev-bar">{"".join(segments)}</div>'


def build_target_table(parsed: dict) -> str:
    if not parsed["target_counts"]:
        return ""

    rows = []
    for target, count in sorted(parsed["target_counts"].items(), key=lambda x: -x[1]):
        rows.append(f"""
            <tr>
                <td class="target-cell"><span class="file-icon">📄</span> {escape(target)}</td>
                <td class="count-cell">{count}</td>
            </tr>""")

    return f"""
    <section class="card targets-card">
        <h2 class="section-title">Findings by File</h2>
        <table class="target-table">
            <thead><tr><th>Target</th><th>Findings</th></tr></thead>
            <tbody>{"".join(rows)}</tbody>
        </table>
    </section>"""


def build_finding_cards(parsed: dict) -> str:
    if not parsed["misconfigs"]:
        return '<div class="no-findings">✅ No misconfigurations detected.</div>'

    cards = []
    for i, m in enumerate(parsed["misconfigs"]):
        sev      = m["severity"]
        color    = sev_color(sev)
        bg       = sev_bg(sev)
        icon     = sev_icon(sev)
        refs_html = ""

        if m["references"]:
            ref_links = " ".join(
                f'<a href="{escape(r)}" target="_blank" rel="noopener" class="ref-link">'
                f'{escape(r[:60])}{"…" if len(r) > 60 else ""}</a>'
                for r in m["references"][:3]
            )
            refs_html = f'<div class="finding-refs"><span class="refs-label">References:</span> {ref_links}</div>'

        resolution_html = ""
        if m["resolution"]:
            resolution_html = f"""
            <div class="finding-resolution">
                <span class="res-label">💡 Resolution:</span>
                <span class="res-text">{escape(m["resolution"])}</span>
            </div>"""

        avd_badge = ""
        if m["avd_id"]:
            avd_badge = f'<span class="avd-badge">{escape(m["avd_id"])}</span>'

        message_html = ""
        if m["message"] and m["message"] != m["description"]:
            message_html = f'<p class="finding-message">{escape(m["message"])}</p>'

        cards.append(f"""
        <div class="finding-card" data-severity="{sev}" style="--card-color:{color};--card-bg:{bg};">
            <div class="finding-header">
                <div class="finding-left">
                    <span class="sev-badge" style="background:{color};">{icon} {sev}</span>
                    <span class="finding-id">{escape(m["id"])}</span>
                    {avd_badge}
                </div>
                <div class="finding-target">{escape(m["target"])}</div>
            </div>
            <div class="finding-body">
                <h3 class="finding-title">{escape(m["title"])}</h3>
                <p class="finding-desc">{escape(m["description"])}</p>
                {message_html}
                {resolution_html}
                {refs_html}
            </div>
        </div>""")

    return "\n".join(cards)


def build_filter_buttons() -> str:
    buttons = ['<button class="filter-btn active" data-filter="ALL">All</button>']
    for sev in SEVERITY_ORDER:
        color = sev_color(sev)
        icon  = sev_icon(sev)
        buttons.append(
            f'<button class="filter-btn" data-filter="{sev}" '
            f'style="--btn-color:{color};">{icon} {sev.title()}</button>'
        )
    return "\n".join(buttons)


# ──────────────────────────────────────────────────────────────
# Full HTML template
# ──────────────────────────────────────────────────────────────
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>{title}</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet"/>
<style>
/* ── Reset & base ── */
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

:root {{
  --bg:         #0a0a0f;
  --bg2:        #111118;
  --bg3:        #1a1a24;
  --border:     rgba(255,255,255,0.07);
  --border2:    rgba(255,255,255,0.12);
  --text:       #e8e8f0;
  --text-muted: #6b6b80;
  --text-dim:   #9898b0;
  --accent:     #7c6aff;
  --accent2:    #a78bfa;
  --font-mono:  'JetBrains Mono', monospace;
  --font-ui:    'Syne', sans-serif;
  --radius:     12px;
  --radius-sm:  7px;
  --shadow:     0 4px 24px rgba(0,0,0,0.4);
  --shadow-lg:  0 8px 48px rgba(0,0,0,0.6);
}}

html {{ scroll-behavior: smooth; }}

body {{
  font-family: var(--font-ui);
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  line-height: 1.6;
  overflow-x: hidden;
}}

/* ── Background grid ── */
body::before {{
  content: '';
  position: fixed;
  inset: 0;
  background-image:
    linear-gradient(rgba(124,106,255,0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(124,106,255,0.03) 1px, transparent 1px);
  background-size: 40px 40px;
  pointer-events: none;
  z-index: 0;
}}

/* ── Layout ── */
.wrap {{
  position: relative;
  z-index: 1;
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 24px 80px;
}}

/* ── Header ── */
.site-header {{
  padding: 48px 0 40px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 40px;
  position: relative;
}}

.header-eyebrow {{
  font-family: var(--font-mono);
  font-size: 11px;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  color: var(--accent2);
  margin-bottom: 12px;
  display: flex;
  align-items: center;
  gap: 8px;
}}

.header-eyebrow::before {{
  content: '';
  display: inline-block;
  width: 24px;
  height: 2px;
  background: var(--accent);
}}

h1.report-title {{
  font-size: clamp(2rem, 5vw, 3.2rem);
  font-weight: 800;
  letter-spacing: -0.03em;
  line-height: 1.1;
  color: #fff;
  margin-bottom: 16px;
}}

h1.report-title span {{
  background: linear-gradient(135deg, var(--accent) 0%, var(--accent2) 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}}

.header-meta {{
  display: flex;
  flex-wrap: wrap;
  gap: 20px;
  margin-top: 20px;
}}

.meta-item {{
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--text-muted);
  display: flex;
  align-items: center;
  gap: 6px;
}}

.meta-item strong {{
  color: var(--text-dim);
}}

/* ── Stat cards ── */
.stats-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 16px;
  margin-bottom: 32px;
}}

.stat-card {{
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px 16px;
  text-align: center;
  position: relative;
  overflow: hidden;
  transition: border-color 0.2s, transform 0.2s;
  animation: fadeUp 0.5s ease both;
}}

.stat-card:hover {{
  border-color: var(--border2);
  transform: translateY(-2px);
}}

.stat-card::after {{
  content: '';
  position: absolute;
  bottom: 0; left: 0; right: 0;
  height: 2px;
  background: var(--sev-color, var(--accent));
  opacity: 0.6;
}}

.stat-total {{ --sev-color: var(--accent); }}

.stat-icon {{ font-size: 1.4rem; margin-bottom: 4px; }}

.stat-value {{
  font-size: 2rem;
  font-weight: 800;
  line-height: 1;
  margin-bottom: 6px;
  color: var(--text);
}}

.stat-label {{
  font-size: 10px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--text-muted);
  font-family: var(--font-mono);
}}

/* ── Severity bar ── */
.sev-bar-wrap {{
  margin-bottom: 40px;
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px 24px;
}}

.sev-bar-label {{
  font-family: var(--font-mono);
  font-size: 11px;
  letter-spacing: 0.15em;
  text-transform: uppercase;
  color: var(--text-muted);
  margin-bottom: 12px;
}}

.sev-bar {{
  display: flex;
  height: 10px;
  border-radius: 999px;
  overflow: hidden;
  gap: 2px;
}}

.sev-seg {{
  height: 100%;
  border-radius: 999px;
  transition: opacity 0.2s;
  cursor: default;
}}

.sev-seg:hover {{ opacity: 0.8; }}
.sev-bar-empty {{ color: var(--text-dim); font-family: var(--font-mono); font-size: 13px; }}

/* ── Card generic ── */
.card {{
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 28px;
  margin-bottom: 24px;
  box-shadow: var(--shadow);
}}

.section-title {{
  font-size: 13px;
  font-weight: 700;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--text-muted);
  font-family: var(--font-mono);
  margin-bottom: 20px;
  display: flex;
  align-items: center;
  gap: 10px;
}}

.section-title::after {{
  content: '';
  flex: 1;
  height: 1px;
  background: var(--border);
}}

/* ── Target table ── */
.target-table {{
  width: 100%;
  border-collapse: collapse;
  font-family: var(--font-mono);
  font-size: 13px;
}}

.target-table th {{
  text-align: left;
  padding: 10px 14px;
  font-size: 11px;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--text-muted);
  border-bottom: 1px solid var(--border);
}}

.target-table td {{
  padding: 11px 14px;
  border-bottom: 1px solid var(--border);
  color: var(--text-dim);
  transition: background 0.15s;
}}

.target-table tr:last-child td {{ border-bottom: none; }}
.target-table tr:hover td {{ background: rgba(255,255,255,0.03); }}
.target-cell {{ color: var(--text) !important; word-break: break-all; }}
.count-cell {{ color: var(--accent2) !important; font-weight: 700; text-align: right; }}
.file-icon {{ margin-right: 6px; opacity: 0.6; }}

/* ── Filters ── */
.filters-bar {{
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 24px;
  align-items: center;
}}

.filters-label {{
  font-family: var(--font-mono);
  font-size: 11px;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--text-muted);
  margin-right: 4px;
}}

.filter-btn {{
  font-family: var(--font-mono);
  font-size: 12px;
  font-weight: 600;
  padding: 7px 16px;
  border-radius: 999px;
  border: 1px solid var(--border2);
  background: transparent;
  color: var(--text-dim);
  cursor: pointer;
  transition: all 0.15s;
  letter-spacing: 0.05em;
}}

.filter-btn:hover {{
  background: rgba(255,255,255,0.05);
  color: var(--text);
  border-color: var(--btn-color, var(--accent));
}}

.filter-btn.active {{
  background: var(--btn-color, var(--accent));
  border-color: var(--btn-color, var(--accent));
  color: #fff;
  box-shadow: 0 0 16px -4px var(--btn-color, var(--accent));
}}

/* ── Finding cards ── */
.findings-list {{
  display: flex;
  flex-direction: column;
  gap: 14px;
}}

.finding-card {{
  background: var(--bg3);
  border: 1px solid var(--border);
  border-left: 3px solid var(--card-color);
  border-radius: var(--radius);
  overflow: hidden;
  transition: border-color 0.2s, transform 0.2s, box-shadow 0.2s;
  animation: fadeUp 0.4s ease both;
}}

.finding-card:hover {{
  border-color: var(--card-color);
  transform: translateX(3px);
  box-shadow: -4px 0 20px -8px var(--card-color);
}}

.finding-card.hidden {{ display: none; }}

.finding-header {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 10px;
  padding: 14px 18px;
  background: var(--card-bg);
  border-bottom: 1px solid var(--border);
  cursor: pointer;
  user-select: none;
}}

.finding-left {{
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}}

.sev-badge {{
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.08em;
  padding: 3px 10px;
  border-radius: 999px;
  color: #fff;
  white-space: nowrap;
}}

.finding-id {{
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--text-dim);
  font-weight: 600;
}}

.avd-badge {{
  font-family: var(--font-mono);
  font-size: 11px;
  padding: 2px 8px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border2);
  color: var(--text-muted);
}}

.finding-target {{
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-muted);
  max-width: 300px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}}

.finding-body {{
  padding: 16px 18px;
  display: none;
}}

.finding-card.expanded .finding-body {{ display: block; }}
.finding-card.expanded .finding-header {{ border-bottom-color: var(--border2); }}

.finding-title {{
  font-size: 15px;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 8px;
  line-height: 1.4;
}}

.finding-desc {{
  font-size: 13px;
  color: var(--text-dim);
  line-height: 1.7;
  margin-bottom: 12px;
}}

.finding-message {{
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--text-dim);
  background: rgba(0,0,0,0.3);
  border-left: 2px solid var(--card-color);
  padding: 10px 14px;
  border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
  margin-bottom: 12px;
  white-space: pre-wrap;
  word-break: break-word;
}}

.finding-resolution {{
  font-size: 13px;
  color: #34c759;
  margin-bottom: 12px;
  display: flex;
  gap: 8px;
  align-items: baseline;
  flex-wrap: wrap;
}}

.res-label {{ font-weight: 700; white-space: nowrap; }}
.res-text {{ color: var(--text-dim); }}

.finding-refs {{
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
  margin-top: 10px;
  padding-top: 10px;
  border-top: 1px solid var(--border);
}}

.refs-label {{
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.08em;
}}

.ref-link {{
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--accent2);
  text-decoration: none;
  padding: 2px 8px;
  border-radius: var(--radius-sm);
  border: 1px solid rgba(167,139,250,0.2);
  transition: all 0.15s;
  word-break: break-all;
}}

.ref-link:hover {{
  background: rgba(167,139,250,0.1);
  border-color: var(--accent2);
}}

/* ── Empty state ── */
.no-findings {{
  text-align: center;
  padding: 60px 24px;
  color: var(--text-muted);
  font-size: 18px;
  font-family: var(--font-mono);
  border: 1px dashed var(--border2);
  border-radius: var(--radius);
}}

/* ── Footer ── */
.site-footer {{
  text-align: center;
  padding: 32px 0;
  border-top: 1px solid var(--border);
  margin-top: 60px;
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-muted);
  letter-spacing: 0.08em;
}}

/* ── Animations ── */
@keyframes fadeUp {{
  from {{ opacity: 0; transform: translateY(16px); }}
  to   {{ opacity: 1; transform: translateY(0); }}
}}

.stats-grid .stat-card:nth-child(1) {{ animation-delay: 0.05s; }}
.stats-grid .stat-card:nth-child(2) {{ animation-delay: 0.10s; }}
.stats-grid .stat-card:nth-child(3) {{ animation-delay: 0.15s; }}
.stats-grid .stat-card:nth-child(4) {{ animation-delay: 0.20s; }}
.stats-grid .stat-card:nth-child(5) {{ animation-delay: 0.25s; }}
.stats-grid .stat-card:nth-child(6) {{ animation-delay: 0.30s; }}

/* ── Search ── */
.search-wrap {{
  position: relative;
  margin-bottom: 16px;
}}

.search-input {{
  width: 100%;
  background: var(--bg3);
  border: 1px solid var(--border2);
  border-radius: var(--radius);
  padding: 12px 16px 12px 40px;
  font-family: var(--font-mono);
  font-size: 13px;
  color: var(--text);
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
}}

.search-input::placeholder {{ color: var(--text-muted); }}
.search-input:focus {{
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(124,106,255,0.15);
}}

.search-icon {{
  position: absolute;
  left: 13px;
  top: 50%;
  transform: translateY(-50%);
  color: var(--text-muted);
  font-size: 15px;
  pointer-events: none;
}}

/* ── Responsive ── */
@media (max-width: 600px) {{
  .stats-grid {{ grid-template-columns: repeat(3, 1fr); }}
  .finding-target {{ display: none; }}
  .header-meta {{ gap: 12px; }}
}}

/* ── Expand all toggle ── */
.expand-toggle {{
  font-family: var(--font-mono);
  font-size: 11px;
  padding: 6px 14px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border2);
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
  margin-left: auto;
  transition: all 0.15s;
  letter-spacing: 0.05em;
}}

.expand-toggle:hover {{
  background: rgba(255,255,255,0.05);
  color: var(--text);
}}

.findings-toolbar {{
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 10px;
  margin-bottom: 16px;
}}
</style>
</head>
<body>
<div class="wrap">

  <!-- Header -->
  <header class="site-header">
    <div class="header-eyebrow">Trivy Security Report</div>
    <h1 class="report-title">{title_text}<br/><span>Config Scan</span></h1>
    <div class="header-meta">
      {meta_items}
    </div>
  </header>

  <!-- Stat cards -->
  <div class="stats-grid">
    {stat_cards}
  </div>

  <!-- Severity distribution bar -->
  <div class="sev-bar-wrap">
    <div class="sev-bar-label">Severity Distribution</div>
    {severity_bar}
  </div>

  <!-- Targets table -->
  {target_table}

  <!-- Findings -->
  <section>
    <h2 class="section-title" style="margin-bottom:16px;">Findings</h2>

    <!-- Filter buttons -->
    <div class="filters-bar">
      <span class="filters-label">Filter:</span>
      {filter_buttons}
    </div>

    <!-- Search + expand toggle -->
    <div class="findings-toolbar">
      <div class="search-wrap" style="flex:1;min-width:200px;margin-bottom:0;">
        <span class="search-icon">🔍</span>
        <input type="text" class="search-input" id="searchInput"
               placeholder="Search findings by title, ID, or target…"/>
      </div>
      <button class="expand-toggle" id="expandAll">Expand All</button>
    </div>

    <div class="findings-list" id="findingsList">
      {finding_cards}
    </div>
  </section>

  <footer class="site-footer">
    Generated by trivy_report.py &nbsp;·&nbsp; {generated_at}
  </footer>
</div>

<script>
// ── Expand / collapse on header click ──
document.querySelectorAll('.finding-header').forEach(header => {{
  header.addEventListener('click', () => {{
    header.closest('.finding-card').classList.toggle('expanded');
  }});
}});

// ── Expand All toggle ──
const expandAllBtn = document.getElementById('expandAll');
let allExpanded = false;
expandAllBtn.addEventListener('click', () => {{
  allExpanded = !allExpanded;
  document.querySelectorAll('.finding-card:not(.hidden)').forEach(card => {{
    card.classList.toggle('expanded', allExpanded);
  }});
  expandAllBtn.textContent = allExpanded ? 'Collapse All' : 'Expand All';
}});

// ── Severity filter ──
document.querySelectorAll('.filter-btn').forEach(btn => {{
  btn.addEventListener('click', () => {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    applyFilters();
  }});
}});

// ── Search ──
document.getElementById('searchInput').addEventListener('input', applyFilters);

function applyFilters() {{
  const activeSev   = document.querySelector('.filter-btn.active').dataset.filter;
  const searchTerm  = document.getElementById('searchInput').value.toLowerCase();

  document.querySelectorAll('.finding-card').forEach(card => {{
    const sevMatch    = activeSev === 'ALL' || card.dataset.severity === activeSev;
    const text        = card.textContent.toLowerCase();
    const searchMatch = !searchTerm || text.includes(searchTerm);
    card.classList.toggle('hidden', !(sevMatch && searchMatch));
  }});
}}
</script>
</body>
</html>
"""


# ──────────────────────────────────────────────────────────────
# Assemble & write
# ──────────────────────────────────────────────────────────────
def build_html(parsed: dict, title: str) -> str:
    # Meta row
    meta_parts = []
    if parsed["artifact_name"]:
        meta_parts.append(f'<div class="meta-item">📦 <strong>Artifact:</strong> {escape(parsed["artifact_name"])}</div>')
    if parsed["artifact_type"]:
        meta_parts.append(f'<div class="meta-item">🏷️ <strong>Type:</strong> {escape(parsed["artifact_type"])}</div>')
    if parsed["created_at"]:
        meta_parts.append(f'<div class="meta-item">🕐 <strong>Scanned:</strong> {escape(parsed["created_at"])}</div>')
    meta_parts.append(f'<div class="meta-item">🔢 <strong>Schema:</strong> v{escape(str(parsed["schema_version"]))}</div>')

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return HTML_TEMPLATE.format(
        title         = escape(title),
        title_text    = escape(title),
        meta_items    = "\n      ".join(meta_parts),
        stat_cards    = build_stat_cards(parsed),
        severity_bar  = build_severity_bar(parsed),
        target_table  = build_target_table(parsed),
        filter_buttons= build_filter_buttons(),
        finding_cards = build_finding_cards(parsed),
        generated_at  = generated_at,
    )


# ──────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Convert a Trivy config scan JSON report to an HTML dashboard."
    )
    parser.add_argument(
        "input",
        help="Path to the Trivy JSON report file (e.g. report.json)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output HTML file path (default: <input-stem>-report.html)",
    )
    parser.add_argument(
        "--title",
        default="Security Scan",
        help='Report title shown in the header (default: "Security Scan")',
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    output_path = Path(args.output) if args.output else input_path.with_name(f"{input_path.stem}-report.html")

    print(f"Reading  : {input_path}")
    try:
        with open(input_path, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse JSON — {e}", file=sys.stderr)
        sys.exit(1)

    parsed   = parse_report(data)
    html     = build_html(parsed, args.title)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Output   : {output_path}")
    print(f"Findings : {parsed['total']} total", end="")
    for sev in SEVERITY_ORDER:
        count = parsed["severity_counts"].get(sev, 0)
        if count:
            print(f"  |  {sev}: {count}", end="")
    print()


if __name__ == "__main__":
    main()
