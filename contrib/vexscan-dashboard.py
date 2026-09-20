#!/usr/bin/env python3
"""vexscan-dashboard.py -- render a vexscan JSON report as an HTML dashboard.

vexscan's text report is written for a terminal, where the reader is the person
who ran it. This is for the other audience: the one handed a link. It renders
the same report as a single self-contained HTML file -- no CDN, no fonts to
fetch, no JavaScript from anywhere else -- that opens from a file:// URL, an
artifact store or GitHub Pages.

    vexscan --image myorg/app:latest --all --triage --format json > scan.json
    contrib/vexscan-dashboard.py scan.json -o scan.html

A batch report (--images-from) renders as a directory: an index of the fleet
and one page per target.

    vexscan --images-from fleet.txt --all --triage --format json > fleet.json
    contrib/vexscan-dashboard.py fleet.json -o site/

Nothing here re-derives a verdict. Every number on the page is read out of the
JSON, and the four sections, their order, their column choices and their row
order all mirror what --format text prints, because a dashboard that disagreed
with the terminal about how many findings are AFFECTED would be worse than no
dashboard at all.

Python 3.8+, standard library only. No network access at generation time and
none when the page is viewed.
"""

import argparse
import html
import json
import os
import re
import sys
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Palette and layout
#
# Lifted from github.com/cwayne18/rke2-toolbox's scan_to_html.py (MIT, same
# author), which takes its colours from the Rancher Dashboard's Modern Light
# theme. Two deliberate departures: the font stack is the system's rather than
# a Google Fonts @import, because a dashboard that phones home to render is not
# one you can read on a disconnected network; and the severity scale keeps a
# distinct UNKNOWN, which vexscan ranks above MEDIUM rather than below LOW.
# ---------------------------------------------------------------------------

CSS = """
:root {
  --body-bg:          #FFFFFF;
  --body-text:        #141419;
  --muted:            #6C6C76;
  --border:           #DCDEE7;
  --box-bg:           #F4F5FA;
  --header-bg:        #FFFFFF;
  --link:             #1F67DB;
  --code-bg:          #F4F5FA;
  --table-header-bg:  #F4F5FA;
  --table-hover-bg:   #F4F5FA;

  --sev-critical-bg:     #B13333;
  --sev-critical-text:   #FFFFFF;
  --sev-critical-border: #7C0015;
  --sev-high-bg:         #E45C1E;
  --sev-high-text:       #FFFFFF;
  --sev-high-border:     #B03A0A;
  --sev-unknown-bg:      #6C6C76;
  --sev-unknown-text:    #FFFFFF;
  --sev-unknown-border:  #4A4A52;
  --sev-medium-bg:       #FFE47A;
  --sev-medium-text:     #473900;
  --sev-medium-border:   #E5A200;
  --sev-low-bg:          #DFE6F2;
  --sev-low-text:        #1F67DB;
  --sev-low-border:      #2673A6;
  --sev-none-bg:         #EDEFF3;
  --sev-none-text:       #6C6C76;
  --sev-none-border:     #DCDEE7;

  --ok-bg:     #27AE60;
  --ok-text:   #FFFFFF;
  --ok-border: #1A7A41;
}

*, *::before, *::after { box-sizing: border-box; }

html, body {
  margin: 0; padding: 0;
  background: var(--body-bg);
  color: var(--body-text);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
               'Helvetica Neue', Arial, sans-serif;
  font-size: 14px;
  line-height: 1.6;
}

/* ---- Header ---- */
.page-header {
  background: var(--header-bg);
  border-bottom: 1px solid var(--border);
  padding: 0 32px;
  height: 55px;
  display: flex;
  align-items: center;
  gap: 12px;
  position: sticky;
  top: 0;
  z-index: 100;
  box-shadow: 0 1px 4px rgba(0,0,0,.06);
}
.page-header .brand {
  font-weight: 600;
  font-size: 17px;
  display: flex;
  align-items: center;
  gap: 10px;
  color: var(--body-text);
  text-decoration: none;
}
.page-header .brand svg { width: 26px; height: 26px; flex-shrink: 0; }
.page-header .subtitle {
  font-size: 13px;
  color: var(--muted);
  margin-left: 4px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* ---- Layout ---- */
.page-content { max-width: 1320px; margin: 0 auto; padding: 28px 24px 64px; }

h1, h2, h3 { margin-top: 0; }
h1 {
  font-size: 22px; font-weight: 600;
  margin-bottom: 4px;
  word-break: break-all;
}
.page-sub { color: var(--muted); font-size: 13px; margin: 0 0 24px; }
h2 { font-size: 16px; font-weight: 600; margin: 32px 0 10px; }
h3 { font-size: 14px; font-weight: 600; margin: 22px 0 8px; }
.anchored { display: flex; align-items: baseline; gap: 8px; }
.anchored .anchor {
  color: var(--muted); text-decoration: none; font-size: 12px;
  opacity: 0; transition: opacity .15s ease;
}
.anchored:hover .anchor, .anchored:focus-within .anchor { opacity: 1; }
.anchored .anchor:hover { color: var(--link); }

code {
  font-family: ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas,
               'Liberation Mono', monospace;
  font-size: 12px;
  background: var(--code-bg);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 1px 5px;
}

/* ---- Verdict cards ---- */
.cards { display: flex; flex-wrap: wrap; gap: 12px; margin: 0 0 8px; }
.card {
  flex: 1 1 180px;
  border: 1px solid var(--border);
  border-left-width: 4px;
  border-radius: 6px;
  padding: 12px 14px;
  background: var(--body-bg);
  text-decoration: none;
  color: inherit;
  min-width: 160px;
}
a.card:hover { border-color: var(--link); border-left-color: var(--link); }
.card .n { font-size: 26px; font-weight: 700; line-height: 1.1; }
.card .k { font-size: 11px; font-weight: 700; letter-spacing: .06em;
           color: var(--muted); text-transform: uppercase; }
.card .note { font-size: 12px; color: var(--muted); margin-top: 4px; }
.card-affected     { border-left-color: var(--sev-critical-bg); }
.card-vexed        { border-left-color: var(--ok-border); }
.card-undetermined { border-left-color: var(--sev-medium-border); }
.card-ruled-out    { border-left-color: var(--link); }
.card-remediation  { border-left-color: var(--link); border-left-style: dashed; }
.card-remediation .k { color: var(--link); }

/* ---- Tables ---- */
.report-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.report-table thead tr { background: var(--table-header-bg); }
.report-table th {
  padding: 9px 12px;
  text-align: left;
  font-weight: 600;
  font-size: 11px;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: .05em;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
}
.report-table td {
  padding: 8px 12px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
  word-break: break-word;
}
.report-table tbody:last-child tr:last-child td { border-bottom: none; }
.report-table a { color: var(--link); text-decoration: none; }
.report-table a:hover { text-decoration: underline; }
.report-table .num { text-align: right; font-variant-numeric: tabular-nums; }
/* A findings table with every optional column earned is wider than a laptop.
   Scrolling it beats wrapping a purl across four lines. */
.table-wrap { overflow-x: auto; }
.report-table .nowrap { white-space: nowrap; }
.report-table .mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
}

.panel {
  border: 1px solid var(--border);
  border-radius: 6px;
  overflow: hidden;
  background: var(--body-bg);
  margin-bottom: 14px;
}
details.panel > summary {
  cursor: pointer;
  list-style: none;
  font-weight: 600;
  font-size: 13px;
  background: var(--table-header-bg);
  padding: 10px 14px;
  display: flex;
  align-items: center;
  gap: 8px;
}
details.panel > summary::-webkit-details-marker { display: none; }
details.panel > summary::before {
  content: "\\25be";
  display: inline-block;
  transition: transform .15s ease;
  color: var(--muted);
}
details.panel:not([open]) > summary::before { transform: rotate(-90deg); }
details.panel[open] > summary { border-bottom: 1px solid var(--border); }
summary .note { font-weight: 400; color: var(--muted); font-size: 12px; }
summary .count { color: var(--muted); font-weight: 600; }

/* ---- Finding rows ---- */
tr.f-row { cursor: pointer; }
tr.f-row:hover > td { background: var(--table-hover-bg); }
tr.f-row td.expander { color: var(--muted); width: 1em; user-select: none; }
tbody.open tr.f-row > td { background: var(--table-hover-bg); }
tr.f-detail > td {
  background: var(--box-bg);
  padding: 12px 16px 14px 34px;
  font-size: 12.5px;
}
.detail-grid {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 2px 14px;
  margin: 0;
}
.detail-grid dt { color: var(--muted); white-space: nowrap; }
.detail-grid dd {
  margin: 0;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  word-break: break-all;
}
.detail-grid dd.prose { font-family: inherit; word-break: normal; }
.evidence { margin: 10px 0 0; padding: 0; list-style: none; }
.evidence li { display: flex; gap: 8px; margin-bottom: 3px; }
.evidence .origin {
  flex: 0 0 auto;
  color: var(--muted);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 11px;
}
.evidence .blocking {
  flex: 0 0 auto;
  font-size: 10px; font-weight: 700; letter-spacing: .04em;
  text-transform: uppercase;
  color: var(--sev-high-text);
  background: var(--sev-high-bg);
  border: 1px solid var(--sev-high-border);
  border-radius: 4px;
  padding: 0 5px;
  align-self: center;
}
.vendor-block {
  margin-top: 10px;
  padding: 8px 12px;
  border-left: 3px solid var(--ok-border);
  background: var(--body-bg);
  border-radius: 0 4px 4px 0;
}
.vendor-block .who { font-weight: 600; }
.vendor-block p { margin: 4px 0 0; }

/* ---- Badges ---- */
.sev, .epss, .kev, .pill {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .04em;
  white-space: nowrap;
  border: 1px solid transparent;
}
.sev-CRITICAL { background: var(--sev-critical-bg); color: var(--sev-critical-text); border-color: var(--sev-critical-border); }
.sev-HIGH     { background: var(--sev-high-bg);     color: var(--sev-high-text);     border-color: var(--sev-high-border);     }
.sev-UNKNOWN  { background: var(--sev-unknown-bg);  color: var(--sev-unknown-text);  border-color: var(--sev-unknown-border);  }
.sev-MEDIUM   { background: var(--sev-medium-bg);   color: var(--sev-medium-text);   border-color: var(--sev-medium-border);   }
.sev-LOW      { background: var(--sev-low-bg);      color: var(--sev-low-text);      border-color: var(--sev-low-border);      }
.sev-NONE     { background: var(--sev-none-bg);     color: var(--sev-none-text);     border-color: var(--sev-none-border);     }

/* A pill, not a square: exploit likelihood is a different kind of fact from
   the impact rating sitting next to it, and should not read as one. */
.epss { border-radius: 999px; gap: 6px; font-variant-numeric: tabular-nums; }
.epss-meter {
  width: 32px; height: 5px; border-radius: 3px;
  background: rgba(0,0,0,.18); overflow: hidden; flex: 0 0 auto;
}
.epss-meter span { display: block; height: 100%; background: currentColor; opacity: .85; }
.epss-crit { background: var(--sev-critical-bg); color: var(--sev-critical-text); border-color: var(--sev-critical-border); }
.epss-high { background: var(--sev-high-bg);     color: var(--sev-high-text);     border-color: var(--sev-high-border);     }
.epss-med  { background: var(--sev-medium-bg);   color: var(--sev-medium-text);   border-color: var(--sev-medium-border);   }
.epss-low  { background: var(--sev-low-bg);      color: var(--sev-low-text);      border-color: var(--sev-low-border);      }
.epss-none { background: var(--sev-none-bg);     color: var(--sev-none-text);     border-color: var(--sev-none-border); padding: 2px 10px; }
.kev { background: var(--sev-critical-bg); color: #FFFFFF; border-color: var(--sev-critical-border); }
.pill { background: var(--box-bg); color: var(--muted); border-color: var(--border); font-weight: 600; }
.pill-vex { background: #EAF7EF; color: #1A7A41; border-color: var(--ok-border); }

.muted { color: var(--muted); }
.nofix { color: var(--muted); font-style: italic; }

/* ---- Remediation ---- */
.rem-summary {
  border: 1px solid var(--border);
  border-left: 4px solid var(--link);
  border-radius: 6px;
  background: var(--box-bg);
  padding: 12px 16px;
  margin: 4px 0 8px;
}
.rem-summary .rem-line { margin: 0 0 4px; font-weight: 600; }
.rem-summary .rem-line:last-of-type { margin-bottom: 0; }
.rem-summary p.muted { margin: 4px 0 0; font-weight: 400; }
.report-table td.num { text-align: right; font-variant-numeric: tabular-nums; }

/* ---- Banners ---- */
.banner {
  display: flex; align-items: center; gap: 10px;
  padding: 13px 16px;
  border-radius: 6px;
  font-weight: 600;
  font-size: 13px;
  margin-bottom: 14px;
}
.banner-ok   { background: #EAF7EF; border: 1px solid var(--ok-border); color: #1A7A41; }
.banner-warn { background: #FFF7E8; border: 1px solid var(--sev-medium-border); color: #7A5C00; }
.banner-bad  { background: #FDEDEC; border: 1px solid var(--sev-critical-border); color: #8E2A2A; }
.banner .icon { font-size: 17px; line-height: 1; }
.banner .sub { font-weight: 400; color: inherit; opacity: .85; }

/* ---- Filter ---- */
.filter-bar { display: flex; align-items: center; gap: 10px; margin: 18px 0 4px; }
.filter-bar input {
  flex: 1 1 auto;
  max-width: 420px;
  padding: 7px 11px;
  font: inherit;
  font-size: 13px;
  color: var(--body-text);
  background: var(--body-bg);
  border: 1px solid var(--border);
  border-radius: 6px;
}
.filter-bar input:focus { outline: 2px solid var(--link); outline-offset: -1px; }
.filter-bar .hits { font-size: 12px; color: var(--muted); }
tbody.filtered { display: none; }

/* ---- Footer ---- */
.page-footer {
  margin-top: 44px;
  padding-top: 16px;
  border-top: 1px solid var(--border);
  color: var(--muted);
  font-size: 12px;
}
.page-footer dl {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 2px 14px;
  margin: 0 0 10px;
}
.page-footer dt { color: var(--muted); }
.page-footer dd { margin: 0; }

/* ---- Dark mode ---- */
:root[data-theme="dark"] {
  --body-bg:          #16171C;
  --body-text:        #E6E6EC;
  --muted:            #9B9BA6;
  --border:           #2D2F39;
  --box-bg:           #1E1F26;
  --header-bg:        #1A1B21;
  --link:             #5B9BFF;
  --code-bg:          #22232B;
  --table-header-bg:  #22232B;
  --table-hover-bg:   #24262F;
  --sev-low-bg:       #1E2A40;
  --sev-low-text:     #8FB6FF;
  --sev-none-bg:      #2A2C35;
  --sev-none-text:    #9B9BA6;
  --sev-none-border:  #3A3C46;
}
:root[data-theme="dark"] .page-header { box-shadow: 0 1px 4px rgba(0,0,0,.4); }
:root[data-theme="dark"] .banner-ok   { background: #15291E; color: #5FCF8C; }
:root[data-theme="dark"] .banner-warn { background: #241F14; color: #E0B84D; }
:root[data-theme="dark"] .banner-bad  { background: #2A1618; color: #F08A8A; }
:root[data-theme="dark"] .pill-vex    { background: #15291E; color: #5FCF8C; }
:root[data-theme="dark"] .vendor-block { background: var(--box-bg); }

.theme-toggle {
  margin-left: auto;
  display: inline-flex; align-items: center; justify-content: center;
  width: 34px; height: 34px; padding: 0;
  font-size: 15px; line-height: 1; cursor: pointer;
  background: var(--box-bg);
  color: var(--body-text);
  border: 1px solid var(--border);
  border-radius: 8px;
  flex: 0 0 auto;
}
.theme-toggle:hover { border-color: var(--link); }
.theme-toggle .icon-dark { display: none; }
:root[data-theme="dark"] .theme-toggle .icon-light { display: none; }
:root[data-theme="dark"] .theme-toggle .icon-dark { display: inline; }

@media print {
  .page-header, .theme-toggle, .filter-bar { display: none; }
  details.panel > summary { display: none; }
  tr.f-detail { display: table-row !important; }
}
"""

# The theme is applied before first paint, from an inline script in <head>, so
# a dark-mode reader never gets a white flash. It is the only script that has
# to run early, and it touches nothing but the root element's attribute.
THEME_HEAD = """<script>
(function () {
  try {
    var stored = localStorage.getItem('vexscan-theme');
    var prefersDark = window.matchMedia &&
      window.matchMedia('(prefers-color-scheme: dark)').matches;
    if (stored === 'dark' || (!stored && prefersDark)) {
      document.documentElement.setAttribute('data-theme', 'dark');
    }
  } catch (e) {}
})();
</script>"""

THEME_TOGGLE = (
    '<button type="button" class="theme-toggle" aria-label="Toggle dark mode" '
    'title="Toggle dark mode" onclick="vexToggleTheme()">'
    '<span class="icon-light" aria-hidden="true">&#127769;</span>'
    '<span class="icon-dark" aria-hidden="true">&#9728;</span>'
    "</button>"
)

# One script for the whole page: the theme toggle, row expansion and the
# filter. Delegated from the document rather than attached per row, because a
# scan of a large image is a few thousand rows and that many listeners is the
# difference between a page that opens and one that hangs.
PAGE_SCRIPT = """<script>
function vexToggleTheme() {
  var d = document.documentElement;
  var dark = d.getAttribute('data-theme') === 'dark';
  if (dark) { d.removeAttribute('data-theme'); }
  else { d.setAttribute('data-theme', 'dark'); }
  try { localStorage.setItem('vexscan-theme', dark ? 'light' : 'dark'); } catch (e) {}
}

document.addEventListener('click', function (ev) {
  var row = ev.target.closest ? ev.target.closest('tr.f-row') : null;
  if (!row) { return; }
  if (ev.target.closest('a')) { return; }   // a CVE link is not an expand
  var body = row.parentNode;
  var open = body.classList.toggle('open');
  var detail = body.querySelector('tr.f-detail');
  if (detail) { detail.hidden = !open; }
  row.setAttribute('aria-expanded', open ? 'true' : 'false');
  var caret = row.querySelector('.expander');
  if (caret) { caret.textContent = open ? '\\u25be' : '\\u25b8'; }
});

document.addEventListener('keydown', function (ev) {
  if (ev.key !== 'Enter' && ev.key !== ' ') { return; }
  var row = ev.target.closest ? ev.target.closest('tr.f-row') : null;
  if (!row) { return; }
  ev.preventDefault();
  row.click();
});

function vexFilter(input) {
  var q = input.value.trim().toLowerCase();
  var scope = document.getElementById(input.dataset.scope);
  if (!scope) { return; }
  var bodies = scope.querySelectorAll('tbody.f-group');
  var shown = 0;
  for (var i = 0; i < bodies.length; i++) {
    var hit = !q || bodies[i].dataset.search.indexOf(q) !== -1;
    bodies[i].classList.toggle('filtered', !hit);
    if (hit) { shown++; }
  }
  var hits = document.getElementById(input.dataset.hits);
  if (hits) {
    hits.textContent = q ? shown + ' of ' + bodies.length + ' shown' : '';
  }
  // Every section opens while filtering, so a match hiding inside a collapsed
  // RULED OUT is not silently missed. Clearing the box puts each one back the
  // way the page shipped it rather than leaving the whole report unrolled.
  var panels = scope.querySelectorAll('details.panel');
  for (var j = 0; j < panels.length; j++) {
    if (panels[j].dataset.wasOpen === undefined) {
      panels[j].dataset.wasOpen = panels[j].open ? '1' : '0';
    }
    panels[j].open = q ? true : panels[j].dataset.wasOpen === '1';
  }
}
</script>"""

LOGO_SVG = (
    '<svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg" '
    'aria-hidden="true">'
    '<rect x="2" y="2" width="28" height="28" rx="7" fill="#1F67DB"/>'
    '<path d="M9 16.2l4.6 4.6L23 11.4" stroke="white" stroke-width="2.6" '
    'stroke-linecap="round" stroke-linejoin="round"/>'
    "</svg>"
)

# ---------------------------------------------------------------------------
# Verdicts
#
# These mirror summary.go's bucketOf, report.go's sortForDisplay and
# cvss.Rank. They are the one part of this script that has to agree with the
# binary exactly: a page that sorted differently would merely look odd, but one
# that bucketed differently would report a different number of AFFECTED
# findings than the scan it was generated from.
# ---------------------------------------------------------------------------

BUCKET_AFFECTED = "affected"
BUCKET_VEXED = "vexed"
BUCKET_UNDETERMINED = "undetermined"
BUCKET_RULED_OUT = "ruled-out"

SECTIONS = [
    (BUCKET_AFFECTED, "AFFECTED", "vulnerable code is present and can be loaded"),
    (BUCKET_VEXED, "ALREADY VEXED",
     "a published statement answers these; vexscan's own verdict is unchanged"),
    (BUCKET_UNDETERMINED, "UNDETERMINED", "not enough evidence to decide either way"),
    (BUCKET_RULED_OUT, "RULED OUT", "the vulnerable code is not present or cannot run"),
]

# Only an exculpatory statement moves a row. A vendor saying "affected" has
# spoken, but not in a way that lets a reader skip the row.
EXCULPATORY = ("not_affected", "fixed")


def bucket_of(f):
    status = f.get("status", "")
    if status in ("linked", "reachable"):
        vex = f.get("vex") or {}
        return BUCKET_VEXED if vex.get("status") in EXCULPATORY else BUCKET_AFFECTED
    if status in ("not_present", "not_in_execute_path"):
        return BUCKET_RULED_OUT
    return BUCKET_UNDETERMINED


# UNKNOWN sits between HIGH and MEDIUM, which is not a typo. An unrated finding
# is not a mild one -- nobody has said what it is -- and sorting it below LOW
# would bury exactly the rows that still need a human.
SEVERITY_RANK = {
    "CRITICAL": 0, "HIGH": 1, "UNKNOWN": 2, "MEDIUM": 3, "LOW": 4, "NONE": 5,
}

BAND_KEV, BAND_SCORED, BAND_UNSCORED = 0, 1, 2


def display_severity(f):
    sev = (f.get("severity") or "").strip()
    return sev if sev else "UNKNOWN"


def priority_band(f):
    p = f.get("priority")
    if not p:
        return BAND_UNSCORED
    if p.get("kev"):
        return BAND_KEV
    return BAND_SCORED if p.get("scored") else BAND_UNSCORED


def percentile_of(f):
    p = f.get("priority") or {}
    return p.get("percentile") or 0.0


CVE_SUFFIX = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")

OS_PURL_TYPES = ("deb", "rpm", "apk")


def short_advisory(f):
    """The id to print: a distro prefix is dropped only when a CVE remains."""
    ident = f.get("cve") or f.get("id") or ""
    head, sep, rest = ident.partition("-")
    if sep and CVE_SUFFIX.match(rest):
        return rest
    return ident


def purl_name(purl):
    """The binary package name out of an OS purl, or None."""
    if not purl.startswith("pkg:"):
        return None
    body = purl[4:]
    cut = min((i for i in (body.find("?"), body.find("#")) if i >= 0), default=-1)
    if cut >= 0:
        body = body[:cut]
    typ, sep, rest = body.partition("/")
    if not sep or typ.lower() not in OS_PURL_TYPES:
        return None
    at = rest.rfind("@")
    if at >= 0:
        rest = rest[:at]
    slash = rest.rfind("/")
    if slash >= 0:
        rest = rest[slash + 1:]
    try:
        from urllib.parse import unquote
        rest = unquote(rest)
    except Exception:  # pragma: no cover -- unquote does not raise in practice
        pass
    return rest or None


def component(f):
    """The installed artifact's own name -- the binary package, not the source
    package the advisory is filed against. Printing the latter makes an OS
    report appear to contradict itself."""
    return purl_name(f.get("purl") or "") or f.get("package") or ""


def sort_key(f):
    return (
        priority_band(f),
        -percentile_of(f),
        SEVERITY_RANK.get(display_severity(f), 6),
        component(f),
        short_advisory(f),
    )


# ---------------------------------------------------------------------------
# Debian version comparison
#
# A straight port of internal/debver, which is itself dpkg's verrevcmp
# (deb-version(7)). The fix plan needs it for one thing: when a package carries
# several advisories fixed in different point releases, pick the newest as the
# upgrade target, because a distro point release is cumulative and installing
# the latest clears every earlier one. Scoped to Debian/Ubuntu on purpose --
# other ecosystems order their versions differently and are left un-collapsed.
# ---------------------------------------------------------------------------


def _deb_order(c):
    """Each byte's dpkg sort weight, matching debver.order."""
    if c.isdigit():
        return 0
    if c.isalpha() and c.isascii():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _deb_verrevcmp(a, b):
    """Compare one upstream-or-revision fragment, matching debver.verrevcmp."""
    i, j = 0, 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        while (i < la and not a[i].isdigit()) or (j < lb and not b[j].isdigit()):
            ac = _deb_order(a[i]) if i < la else 0
            bc = _deb_order(b[j]) if j < lb else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        first_diff = 0
        while i < la and a[i].isdigit() and j < lb and b[j].isdigit():
            if first_diff == 0:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and a[i].isdigit():
            return 1
        if j < lb and b[j].isdigit():
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


def _deb_split(v):
    """Break a version into (epoch, upstream, revision), matching debver.split."""
    epoch = 0
    colon = v.find(":")
    if colon >= 0 and v[:colon].isdigit():
        epoch = int(v[:colon])
        v = v[colon + 1:]
    dash = v.rfind("-")
    if dash >= 0:
        return epoch, v[:dash], v[dash + 1:]
    return epoch, v, ""


def deb_compare(a, b):
    """-1 if a sorts before b, +1 if after, 0 if equal (Debian algorithm)."""
    ea, ua, ra = _deb_split(a)
    eb, ub, rb = _deb_split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = _deb_verrevcmp(ua, ub)
    if c != 0:
        return c
    return _deb_verrevcmp(ra, rb)


# ---------------------------------------------------------------------------
# Small renderers
# ---------------------------------------------------------------------------


def esc(text):
    return html.escape("" if text is None else str(text), quote=True)


def slug(text):
    s = re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-")
    return s or "section"


def plural(n, word, suffix="s"):
    return "%d %s%s" % (n, word, "" if n == 1 else suffix)


def severity_badge(sev):
    cls = sev if sev in SEVERITY_RANK else "UNKNOWN"
    title = ""
    if cls == "UNKNOWN":
        title = ' title="No severity was published for this advisory, which is not the same as a low one"'
    return '<span class="sev sev-%s"%s>%s</span>' % (esc(cls), title, esc(sev))


def epss_tier(percentile):
    """The badge's colour band, keyed to the same number it prints.

    The obvious alternative is to colour by the raw probability, which is the
    more meaningful risk figure. It is also the figure this badge does not
    show, and a red pill reading "45.0%" invites the reader to misread the
    number they can see as the one that earned the colour. The probability is
    in the tooltip and in the detail panel, both of which name it.
    """
    if percentile >= 0.99:
        return "epss-crit"
    if percentile >= 0.9:
        return "epss-high"
    if percentile >= 0.5:
        return "epss-med"
    return "epss-low"


def epss_pct(percentile):
    """The percentile exactly as displayEPSS in report.go prints it.

    The column is called EPSS in both places, so it has to be the same number
    in both places. A dashboard whose EPSS column read 94.4% next to a terminal
    whose EPSS column read 100.0% would leave the reader to work out that one
    is the probability and the other its rank, and most would not.
    """
    return "%.1f%%" % (percentile * 100)


def ordinal(n):
    suffix = "th" if 10 <= (n % 100) <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return "%d%s" % (n, suffix)


def epss_badge(f):
    p = f.get("priority") or {}
    if not p.get("scored"):
        # "Not scored" is a different fact from "scored zero", and the page has
        # to keep them apart for the same reason the JSON does.
        if not p:
            note = "Not triaged: this scan ran without --triage"
        elif not p.get("cve"):
            note = "Not scored: this advisory has no CVE id, and both feeds are keyed by CVE"
        else:
            note = "Not scored: %s is not in the EPSS feed yet" % p["cve"]
        return '<span class="epss epss-none" title="%s">&mdash;</span>' % esc(note)
    score = p.get("epss") or 0.0
    pct = p.get("percentile") or 0.0
    rank = max(0, min(100, int(round(pct * 100))))
    title = ("Ranks in the %s percentile of scored CVEs. EPSS puts the "
             "probability of exploitation in the next 30 days at %.5f "
             "(FIRST.org)" % (ordinal(rank), score))
    return (
        '<span class="epss %s" title="%s">'
        '<span class="epss-meter"><span style="width:%d%%"></span></span>'
        "<span>%s</span></span>"
        % (epss_tier(pct), esc(title), max(3, rank), esc(epss_pct(pct)))
    )


def kev_badge(f):
    kev = (f.get("priority") or {}).get("kev")
    if not kev:
        return ""
    label = "ransomware" if kev.get("ransomware") else "yes"
    bits = ["CISA Known Exploited Vulnerabilities catalog"]
    if kev.get("date_added"):
        bits.append("added %s" % kev["date_added"])
    if kev.get("due_date"):
        bits.append("federal due date %s" % kev["due_date"])
    return '<span class="kev" title="%s">%s</span>' % (esc(" · ".join(bits)), esc(label))


def advisory_url(ident):
    """Where to read about an advisory. Chosen from the id's own shape, so the
    page needs no network at generation time and no lookup table."""
    up = ident.upper()
    if up.startswith("CVE-"):
        return "https://nvd.nist.gov/vuln/detail/" + ident
    if up.startswith("GHSA-"):
        return "https://github.com/advisories/" + ident
    if up.startswith("GO-"):
        return "https://pkg.go.dev/vuln/" + ident
    if not ident:
        return ""
    return "https://osv.dev/vulnerability/" + ident


def advisory_link(ident):
    url = advisory_url(ident)
    if not url:
        return '<span class="muted">&mdash;</span>'
    return '<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>' % (esc(url), esc(ident))


def anchored(level, text, ident):
    return (
        '<h%d class="anchored" id="%s">%s'
        '<a class="anchor" href="#%s" aria-label="Link to this section">#</a></h%d>'
        % (level, esc(ident), esc(text), esc(ident), level)
    )


def table(headers, rows, classes="report-table"):
    """A plain table of already-escaped cells."""
    out = ['<div class="table-wrap"><table class="%s"><thead><tr>' % classes]
    for h in headers:
        cls = ' class="num"' if isinstance(h, tuple) else ""
        label = h[0] if isinstance(h, tuple) else h
        out.append("<th%s>%s</th>" % (cls, esc(label)))
    out.append("</tr></thead><tbody>")
    for row in rows:
        out.append("<tr>")
        for h, cell in zip(headers, row):
            cls = ' class="num"' if isinstance(h, tuple) else ""
            out.append("<td%s>%s</td>" % (cls, cell))
        out.append("</tr>")
    out.append("</tbody></table></div>")
    return "".join(out)


# ---------------------------------------------------------------------------
# Finding tables
# ---------------------------------------------------------------------------


def wants_columns(rows):
    """Which optional columns this section has earned.

    Mirrors writeSection: a column appears when the section holds something to
    put in it. A Debian image where everything affected is "linked" gets no
    VERDICT column, and an ecosystem that publishes no fixes gets no FIXED IN
    column, rather than a hundred rows of the same word.
    """
    return {
        "location": any(f.get("location") for f in rows),
        "fixed": any(f.get("fixed_version") for f in rows),
        "epss": any((f.get("priority") or {}).get("scored") for f in rows),
        "kev": any((f.get("priority") or {}).get("kev") for f in rows),
        "verdict": len({f.get("status", "") for f in rows}) > 1,
    }


def search_text(f):
    """The haystack the filter box matches against: everything a reader might
    reasonably type, including the ids they will paste from a ticket."""
    parts = [
        short_advisory(f), f.get("id", ""), f.get("cve", ""), f.get("go_id", ""),
        component(f), f.get("package", ""), f.get("version", ""),
        f.get("location", ""), f.get("binary", ""), f.get("ecosystem", ""),
        display_severity(f), f.get("status", ""), f.get("method", ""),
        f.get("justification", ""), f.get("purl", ""),
    ]
    vex = f.get("vex") or {}
    parts += [vex.get("status", ""), vex.get("justification", ""), vex.get("author", "")]
    return " ".join(p for p in parts if p).lower()


def detail_rows(f):
    """The per-finding detail panel, mirroring --details."""
    items = []

    def add(label, value, prose=False):
        if value:
            cls = ' class="prose"' if prose else ""
            items.append("<dt>%s</dt><dd%s>%s</dd>" % (esc(label), cls, value))

    ident = f.get("cve") or f.get("id") or ""
    go_id = f.get("go_id") or ""
    id_html = advisory_link(ident)
    aliases = [a for a in (go_id, f.get("id")) if a and a != ident]
    # De-duplicated in order: the Go id and the record id are usually the same
    # string, and printing it twice reads as two different aliases.
    seen_alias = []
    for a in aliases:
        if a not in seen_alias:
            seen_alias.append(a)
    if seen_alias:
        id_html += ' <span class="muted">(also %s)</span>' % ", ".join(
            advisory_link(a) for a in seen_alias)
    add("advisory", id_html)

    upstream = f.get("upstream") or []
    if upstream:
        shown = ", ".join(upstream[:5])
        if len(upstream) > 5:
            shown += " (+%d more)" % (len(upstream) - 5)
        add("fixes", esc(shown))

    add("from", esc(f.get("ecosystem", "")))

    sev, cvss = display_severity(f), f.get("cvss", "")
    if sev != "UNKNOWN" or cvss:
        line = severity_badge(sev)
        if cvss:
            line += ' <span class="muted">%s</span>' % esc(cvss)
        add("severity", line)

    if f.get("fixed_version"):
        line = esc(f["fixed_version"])
        others = [v for v in (f.get("fixed_versions") or []) if v != f["fixed_version"]]
        if others:
            # The branches not chosen are named, because an advisory that fixed
            # three maintained branches offers three upgrades and only one of
            # them is the small one.
            line += ' <span class="muted">(also fixed in %s)</span>' % esc(", ".join(others))
        add("fixed in", line)

    p = f.get("priority") or {}
    if p.get("scored"):
        line = "%.1f%% percentile (epss %.5f)" % (
            (p.get("percentile") or 0) * 100, p.get("epss") or 0)
        # The CVE the score was looked up under, when it is not the one at the
        # top of the row: GO-2025-3547 is scored as CVE-2024-7598, and naming
        # the join lets the reader check it rather than take it on faith.
        if p.get("cve") and p["cve"] != f.get("cve"):
            line += " for %s" % p["cve"]
        if (p.get("of_set") or 0) > 1:
            line += ", highest of %d" % p["of_set"]
        add("epss", "%s <span class=\"muted\">%s</span>" % (epss_badge(f), esc(line)))
    elif p:
        if not p.get("cve"):
            why = "this advisory has no CVE id, and both feeds are keyed by CVE"
        elif (p.get("of_set") or 0) > 1:
            why = "none of this advisory's %d CVEs are in the feed yet" % p["of_set"]
        else:
            why = "%s is not in the feed yet" % p["cve"]
        add("epss", '<span class="muted">not scored &mdash; %s</span>' % esc(why))
    kev = p.get("kev")
    if kev:
        line = "in CISA's known-exploited catalog since %s" % kev.get("date_added", "?")
        if kev.get("due_date"):
            line += ", federal remediation due %s" % kev["due_date"]
        if kev.get("ransomware"):
            line += "; known ransomware campaign use"
        add("kev", "%s <span class=\"muted\">%s</span>" % (kev_badge(f), esc(line)))

    if component(f) != f.get("package", "") and f.get("package"):
        add("source", esc(f["package"]))
    add("purl", esc(f.get("purl", "")))
    if f.get("binary"):
        note = " (stripped)" if f.get("stripped") else ""
        add("binary", esc(f["binary"] + note))
    if f.get("packages"):
        add("packages", esc("%s (%s)" % (", ".join(f["packages"]), f.get("granularity", ""))))

    if f.get("justification"):
        add("vex", "%s <span class=\"muted\">[%s]</span>" % (
            esc(f["justification"]), esc(f.get("method", ""))))
    elif f.get("method"):
        add("method", esc(f["method"]))
    add("reason", esc(f.get("reason", "")), prose=True)

    body = ['<dl class="detail-grid">%s</dl>' % "".join(items)] if items else []

    evidence = f.get("evidence") or []
    if evidence:
        lis = []
        for e in evidence:
            mark = '<span class="blocking">blocking</span>' if e.get("blocking") else ""
            lis.append(
                '<li><span class="origin">[%s]</span>%s<span>%s</span></li>'
                % (esc(e.get("origin", "")), mark, esc(e.get("detail", "")))
            )
        body.append('<ul class="evidence">%s</ul>' % "".join(lis))

    vex = f.get("vex")
    if vex:
        who = vex.get("author") or vex.get("hub") or "a published statement"
        head = "%s says <strong>%s</strong>" % (esc(who), esc(vex.get("status", "")))
        if vex.get("justification"):
            head += ' <span class="muted">(%s)</span>' % esc(vex["justification"])
        lines = ['<div class="who">%s</div>' % head]
        # The impact statement is the vendor's own sentence about this
        # vulnerability in this product, and is usually the most useful thing
        # on the row. The table has no room for it; this is where it goes.
        for text in (vex.get("impact_statement"), vex.get("action_statement")):
            if text:
                lines.append("<p>%s</p>" % esc(text))
        meta = []
        if vex.get("product"):
            meta.append("product <code>%s</code>" % esc(vex["product"]))
        if vex.get("timestamp"):
            meta.append("published %s" % esc(vex["timestamp"]))
        if vex.get("hub"):
            meta.append("from %s" % esc(vex["hub"]))
        if meta:
            lines.append('<p class="muted">%s</p>' % " · ".join(meta))
        if vex.get("match"):
            # The component match was deliberately loose about spelling, so the
            # disagreement it accepted is shown rather than hidden.
            lines.append('<p class="muted">matched loosely: %s</p>' % esc(vex["match"]))
        body.append('<div class="vendor-block">%s</div>' % "".join(lines))

    llm = f.get("llm")
    if llm:
        line = "exploitable=%s confidence=%s" % (
            esc(llm.get("exploitable", "")), esc(llm.get("confidence", "")))
        if llm.get("rationale"):
            line += "<p>%s</p>" % esc(llm["rationale"])
        body.append('<div class="vendor-block"><div class="who">LLM verdict</div>%s</div>' % line)

    return "".join(body)


def findings_table(rows, is_vex_section):
    cols = wants_columns(rows)
    headers = ['<th class="expander"></th>', "<th>Severity</th>", "<th>Advisory</th>",
               "<th>Package</th>", "<th>Version</th>"]
    if cols["location"]:
        headers.append("<th>Location</th>")
    if cols["fixed"]:
        headers.append("<th>Fixed in</th>")
    if cols["epss"]:
        headers.append(
            '<th title="EPSS percentile: where this CVE ranks among all scored '
            "CVEs, the same figure --format text prints. The probability itself "
            'is on each badge and in the expanded row.">EPSS</th>')
    if cols["kev"]:
        headers.append('<th title="Listed in CISA\'s Known Exploited Vulnerabilities catalog">KEV</th>')
    if cols["verdict"]:
        headers.append("<th>Verdict</th>")
    headers.append("<th>Vendor</th><th>Reason</th>" if is_vex_section else "<th>Method</th>")
    width = len(headers)

    out = ['<div class="table-wrap"><table class="report-table"><thead><tr>%s</tr></thead>'
           % "".join(headers)]
    for f in rows:
        cells = [
            '<td class="expander" aria-hidden="true">▸</td>',
            '<td class="nowrap">%s</td>' % severity_badge(display_severity(f)),
            '<td class="nowrap">%s</td>' % advisory_link(short_advisory(f)),
            '<td class="mono">%s</td>' % esc(component(f) or "(no matching component)"),
            '<td class="mono">%s</td>' % esc(f.get("version", "")),
        ]
        if cols["location"]:
            cells.append('<td class="mono">%s</td>' % esc(f.get("location", "")))
        if cols["fixed"]:
            fixed = f.get("fixed_version")
            cells.append('<td class="mono">%s</td>' % (
                esc(fixed) if fixed else '<span class="nofix">no fix</span>'))
        if cols["epss"]:
            cells.append('<td class="nowrap">%s</td>' % epss_badge(f))
        if cols["kev"]:
            cells.append('<td class="nowrap">%s</td>' % kev_badge(f))
        if cols["verdict"]:
            cells.append('<td class="nowrap"><span class="pill">%s</span></td>' % esc(f.get("status", "")))
        if is_vex_section:
            vex = f.get("vex") or {}
            reason = vex.get("justification") or vex.get("impact_statement") or ""
            cells.append('<td class="nowrap"><span class="pill pill-vex">%s</span></td>' % esc(vex.get("status", "")))
            cells.append("<td>%s</td>" % esc(reason))
        else:
            cells.append('<td class="mono">%s</td>' % esc(f.get("method", "")))

        out.append(
            '<tbody class="f-group" data-search="%s">'
            '<tr class="f-row" tabindex="0" role="button" aria-expanded="false">%s</tr>'
            '<tr class="f-detail" hidden><td colspan="%d">%s</td></tr>'
            "</tbody>" % (esc(search_text(f)), "".join(cells), width, detail_rows(f))
        )
    out.append("</table></div>")
    return "".join(out)


# ---------------------------------------------------------------------------
# Remediation view (--format fixplan, as a panel)
#
# The findings tables above answer "what is wrong with this image". This
# answers the next question, the one asked once the AFFECTED table is a hundred
# rows long: "what do I do about it". It is the same population --format fixplan
# reorganises -- affected, and not already answered by a VEX statement -- folded
# from a wall of per-CVE rows into a short list of upgrades, each annotated with
# how many advisories it clears and the worst severity among them.
#
# It is a view, not a filter. Every affected finding with no published fix is
# still listed, under its own heading, because a remediation plan that silently
# dropped the un-fixable rows would read as complete when it is not.
# ---------------------------------------------------------------------------


def dpkg_plugins(res):
    """Which ecosystem ids produced Debian-comparable versions, so an upgrade
    may fold to its newest fix. A plugin qualifies only when every OSV
    ecosystem it detected is a Debian or Ubuntu one; a mixed or unknown
    analyzer stays on the safe, un-collapsed path."""
    out = set()
    for e in res.get("ecosystems") or []:
        names = e.get("ecosystems") or []
        if not names:
            continue
        if all(is_debian_family(n) for n in names):
            out.add(e.get("id", ""))
    return out


def is_debian_family(ecosystem):
    family = ecosystem.split(":", 1)[0]
    return family.lower() in ("debian", "ubuntu")


def group_upgrades(findings, dpkg):
    """Collapse fixable findings into upgrade actions, mirroring groupUpgrades.

    For a dpkg-orderable ecosystem every advisory on a package folds into one
    row whose target is the newest fix of them all. For any other ecosystem the
    published fixed version is part of the key, so distinct targets stay
    distinct rows rather than risk naming the wrong one as newest.
    """
    index = {}
    order = []
    for f in findings:
        pkg = component(f)
        eco = f.get("ecosystem", "")
        collapse = eco in dpkg
        fixed = f.get("fixed_version") or ""
        key = "\x00".join([eco, pkg, f.get("version", "")])
        if not collapse:
            key += "\x00" + fixed
        u = index.get(key)
        if u is None:
            u = {
                "ecosystem": eco,
                "pkg": pkg,
                "current": f.get("version", ""),
                "fixed_in": fixed,
                "advisories": {},
                "top_rank": 6,
                "top_label": "UNKNOWN",
                "kev": False,
            }
            index[key] = u
            order.append(u)
        if collapse and fixed and deb_compare(fixed, u["fixed_in"]) > 0:
            u["fixed_in"] = fixed
        adv = short_advisory(f)
        u["advisories"][adv] = f
        rank = SEVERITY_RANK.get(display_severity(f), 6)
        if rank < u["top_rank"]:
            u["top_rank"] = rank
            u["top_label"] = display_severity(f)
        if priority_band(f) == BAND_KEV:
            u["kev"] = True

    # Worst first: known-exploited, then severity, then the biggest wins, then a
    # stable name order so the plan is diffable between runs.
    order.sort(key=lambda u: (
        0 if u["kev"] else 1,
        u["top_rank"],
        -len(u["advisories"]),
        u["ecosystem"],
        u["pkg"],
    ))
    return order


def fixplan_population(res):
    """Split the affected-and-unvexed findings into fixable and no-fix, and
    count what the plan declines to plan for. Mirrors writeFixSummary's
    population so the two never disagree."""
    fixable, no_fix = [], []
    vexed = undetermined = 0
    for f in res.get("findings") or []:
        b = bucket_of(f)
        if b == BUCKET_VEXED:
            vexed += 1
            continue
        if b == BUCKET_UNDETERMINED:
            undetermined += 1
            continue
        if b != BUCKET_AFFECTED:
            continue
        if f.get("fixed_version"):
            fixable.append(f)
        else:
            no_fix.append(f)
    return fixable, no_fix, vexed, undetermined


def unique_advisories(findings):
    return len({short_advisory(f) for f in findings})


def build_fixplan(res):
    """The remediation plan and its population, computed once so the summary
    card and the section below it cannot disagree."""
    fixable, no_fix, vexed, undetermined = fixplan_population(res)
    plan = group_upgrades(fixable, dpkg_plugins(res))
    return plan, fixable, no_fix, vexed, undetermined


def remediation_card(res):
    """The fifth verdict card: the one action the page can name. It links to the
    remediation panel and is omitted entirely when nothing is affected, so it
    never appears reading '0 upgrades' on a clean image."""
    plan, fixable, no_fix, _, _ = build_fixplan(res)
    if not fixable and not no_fix:
        return ""
    if plan:
        cleared = unique_advisories(fixable)
        adv = "advisory" if cleared == 1 else "advisories"
        n = len(plan)
        note = "%s to upgrade · clears %d %s" % (plural(n, "package"), cleared, adv)
    else:
        n, note = len(no_fix), "affected, no fix has shipped yet"
    return (
        '<a class="card card-remediation" href="#remediation">'
        '<div class="k">Remediation</div><div class="n">%d</div>'
        '<div class="note">%s</div></a>' % (n, esc(note))
    )


def remediation_summary(fixable, no_fix, upgrades, vexed, undetermined):
    """The plan's count of itself, mirroring writeFixSummary -- every number
    named by its unit, and what the plan omits said out loud."""
    total = len(fixable) + len(no_fix)
    cleared = unique_advisories(fixable)
    lines = []
    if total == 0:
        lines.append("No affected findings to fix.")
    else:
        lines.append("%d of %d affected findings have a fix." % (len(fixable), total))
    if upgrades:
        adv = "advisory" if cleared == 1 else "advisories"
        line = "Upgrading %s clears %d %s" % (plural(upgrades, "package"), cleared, adv)
        if no_fix:
            has = "finding has" if len(no_fix) == 1 else "findings have"
            line += "; %d %s no fix yet" % (len(no_fix), has)
        lines.append(line + ".")
    elif no_fix:
        lines.append("No published fixes yet for any of the %s affected."
                     % plural(len(no_fix), "finding"))
    asides = []
    if vexed:
        asides.append("%d already answered by a vendor VEX statement, so not planned for"
                      % vexed)
    if undetermined:
        asides.append("%d undetermined finding%s not shown; see the sections below"
                      % (undetermined, "" if undetermined == 1 else "s"))
    return lines, asides


def upgrade_detail(u):
    """The expanded row for one upgrade: every advisory it clears, worst first,
    so the CLEARS count can be checked rather than trusted."""
    advs = sorted(u["advisories"].values(), key=sort_key)
    items = []
    for f in advs:
        badges = severity_badge(display_severity(f))
        if priority_band(f) == BAND_KEV:
            badges += " " + kev_badge(f)
        items.append(
            '<li><span class="origin">%s</span>%s<span>%s</span></li>'
            % (advisory_link(short_advisory(f)), badges,
               esc(f.get("id", "") if f.get("id") != short_advisory(f) else "")))
    return (
        '<dl class="detail-grid">'
        "<dt>upgrade</dt><dd>%s <span class=\"muted\">&rarr;</span> %s</dd>"
        "<dt>package</dt><dd>%s <span class=\"muted\">(%s)</span></dd>"
        "</dl><ul class=\"evidence\">%s</ul>"
        % (esc(u["current"]), esc(u["fixed_in"]), esc(u["pkg"]), esc(u["ecosystem"]),
           "".join(items))
    )


def upgrade_table(plan):
    show_eco = len({u["ecosystem"] for u in plan}) > 1
    show_kev = any(u["kev"] for u in plan)

    headers = ['<th class="expander"></th>']
    if show_eco:
        headers.append("<th>Ecosystem</th>")
    headers += ["<th>Package</th>", "<th>Current</th>", "<th>Fixed in</th>",
                '<th class="num" title="Distinct advisories this one upgrade clears">Clears</th>',
                "<th>Severity</th>"]
    if show_kev:
        headers.append('<th title="Clears something in CISA\'s Known Exploited catalog">KEV</th>')
    width = len(headers)

    out = ['<div class="table-wrap"><table class="report-table"><thead><tr>%s</tr></thead>'
           % "".join(headers)]
    for u in plan:
        cells = ['<td class="expander" aria-hidden="true">&#9656;</td>']
        if show_eco:
            cells.append('<td class="mono">%s</td>' % esc(u["ecosystem"]))
        cells += [
            '<td class="mono">%s</td>' % esc(u["pkg"]),
            '<td class="mono">%s</td>' % esc(u["current"]),
            '<td class="mono">%s</td>' % esc(u["fixed_in"]),
            '<td class="num">%d</td>' % len(u["advisories"]),
            '<td class="nowrap">%s</td>' % severity_badge(u["top_label"]),
        ]
        if show_kev:
            cells.append('<td class="nowrap">%s</td>' % (
                '<span class="kev">yes</span>' if u["kev"] else ""))
        search = " ".join([u["pkg"], u["current"], u["fixed_in"], u["ecosystem"]]
                          + list(u["advisories"].keys())).lower()
        out.append(
            '<tbody class="f-group" data-search="%s">'
            '<tr class="f-row" tabindex="0" role="button" aria-expanded="false">%s</tr>'
            '<tr class="f-detail" hidden><td colspan="%d">%s</td></tr>'
            "</tbody>" % (esc(search), "".join(cells), width, upgrade_detail(u))
        )
    out.append("</table></div>")
    return "".join(out)


def render_remediation(res):
    plan, fixable, no_fix, vexed, undetermined = build_fixplan(res)
    if not fixable and not no_fix:
        return ""

    lines, asides = remediation_summary(fixable, no_fix, len(plan), vexed, undetermined)

    summary = "".join('<p class="rem-line">%s</p>' % esc(l) for l in lines)
    if asides:
        summary += "".join('<p class="muted">(%s.)</p>' % esc(a) for a in asides)

    body = [anchored(2, "Remediation", "remediation"),
            '<div class="rem-summary">%s</div>' % summary]

    if plan:
        body.append(anchored(3, "Upgrade — apply these to clear the fixable findings",
                             "remediation-upgrade"))
        body.append(upgrade_table(plan))
    if no_fix:
        body.append(anchored(3, "No fix yet — affected, but no patch has shipped",
                             "remediation-nofix"))
        body.append(findings_table(sorted(no_fix, key=sort_key), False))
    return "".join(body)


def render_sections(findings):
    by_bucket = {key: [] for key, _, _ in SECTIONS}
    for f in findings:
        by_bucket[bucket_of(f)].append(f)

    out = []
    for key, title, note in SECTIONS:
        rows = sorted(by_bucket[key], key=sort_key)
        if not rows:
            continue
        # AFFECTED is open because it is the part that requires action. RULED
        # OUT is closed because it is the proof of work -- worth having, and
        # usually the longest section on the page.
        is_open = " open" if key in (BUCKET_AFFECTED, BUCKET_UNDETERMINED) else ""
        out.append(
            '<details class="panel"%s id="%s"><summary>%s'
            '<span class="count">(%d)</span> <span class="note">&mdash; %s</span>'
            "</summary>%s</details>"
            % (is_open, esc(key), esc(title), len(rows), esc(note),
               findings_table(rows, key == BUCKET_VEXED))
        )
    return "".join(out), {k: len(v) for k, v in by_bucket.items()}


# ---------------------------------------------------------------------------
# Summary, coverage and footer
# ---------------------------------------------------------------------------

CARD_NOTES = {
    BUCKET_AFFECTED: "present and loadable",
    BUCKET_VEXED: "somebody has answered",
    BUCKET_UNDETERMINED: "needs a human",
    BUCKET_RULED_OUT: "not present or unreachable",
}


def render_cards(counts, link=True, extra=""):
    """The four verdict totals. `link` is off on the fleet index, which has no
    sections of its own to jump to. `extra` is appended as-is, for the single
    target page's remediation card, which is an action rather than a verdict."""
    cards = []
    for key, title, _ in SECTIONS:
        n = counts.get(key, 0)
        clickable = link and n
        tag = "a" if clickable else "div"
        attrs = ' href="#%s"' % esc(key) if clickable else ""
        cards.append(
            '<%s class="card card-%s"%s><div class="k">%s</div>'
            '<div class="n">%d</div><div class="note">%s</div></%s>'
            % (tag, esc(key), attrs, esc(title), n, esc(CARD_NOTES[key]), tag)
        )
    return '<div class="cards">%s%s</div>' % ("".join(cards), extra)


def render_headline(res, counts):
    """One sentence at the top saying whether anybody has to do anything."""
    affected = counts.get(BUCKET_AFFECTED, 0)
    failed = [e for e in (res.get("ecosystems") or []) if e.get("error")]
    if failed:
        # An incomplete scan is reported before its findings, because a clean
        # count over a hole in the inventory is the one reading of this page
        # that would be actively harmful.
        names = ", ".join(e.get("id", "?") for e in failed)
        return ('<div class="banner banner-bad"><span class="icon">&#9888;</span>'
                "<span>Scan incomplete &mdash; %s could not be inventoried."
                '<span class="sub"> Counts below are a floor, not a total.</span></span></div>'
                % esc(names))
    if affected == 0:
        by = ""
        vexed = counts.get(BUCKET_VEXED, 0)
        if vexed:
            by = ' <span class="sub">%s answered by a published statement.</span>' % esc(plural(vexed, "finding"))
        return ('<div class="banner banner-ok"><span class="icon">&#10004;</span>'
                "<span>Nothing to act on.%s</span></div>" % by)
    sev = {}
    for f in res.get("findings") or []:
        if bucket_of(f) == BUCKET_AFFECTED:
            sev[display_severity(f)] = sev.get(display_severity(f), 0) + 1
    order = sorted(sev, key=lambda s: SEVERITY_RANK.get(s, 6))
    breakdown = ", ".join("%d %s" % (sev[s], s.lower()) for s in order)
    cls = "banner-bad" if sev.get("CRITICAL") or sev.get("HIGH") else "banner-warn"
    return ('<div class="banner %s"><span class="icon">&#9888;</span>'
            '<span>%s to act on <span class="sub">&mdash; %s</span></span></div>'
            % (cls, esc(plural(affected, "finding")), esc(breakdown)))


def render_coverage(res):
    """What was looked at, and what was not.

    This section is why the counts above can be believed, so it reports the
    absences as loudly as the totals: an ecosystem that failed, a path that
    could not be read, a severity filter that hid rows, a hub that was
    unreachable.
    """
    blocks = []
    ecos = res.get("ecosystems") or []
    if ecos:
        counts = {}
        for f in res.get("findings") or []:
            eco = f.get("ecosystem", "")
            counts.setdefault(eco, {})
            b = bucket_of(f)
            counts[eco][b] = counts[eco].get(b, 0) + 1
        rows = []
        for e in ecos:
            c = counts.get(e.get("id", ""), {})
            status = '<span class="muted">ok</span>'
            if e.get("error"):
                status = '<span class="sev sev-CRITICAL">failed</span> %s' % esc(e["error"])
            rows.append([
                "<code>%s</code>" % esc(e.get("id", "")),
                esc(e.get("components", 0)),
                esc(c.get(BUCKET_AFFECTED, 0)),
                esc(c.get(BUCKET_VEXED, 0)),
                esc(c.get(BUCKET_UNDETERMINED, 0)),
                esc(c.get(BUCKET_RULED_OUT, 0)),
                status,
            ])
        blocks.append(table(
            ["Ecosystem", ("Components",), ("Affected",), ("Vexed",),
             ("Undetermined",), ("Ruled out",), "Status"], rows))

    hubs = res.get("vex_hubs") or []
    if hubs:
        rows = []
        for h in hubs:
            status = esc(h["error"]) if h.get("error") else '<span class="muted">ok</span>'
            rows.append([
                '<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>'
                % (esc(h.get("url", "")), esc(h.get("url", ""))),
                esc(h.get("author", "")), esc(h.get("products", 0)),
                esc(h.get("matched", 0)), status,
            ])
        blocks.append(anchored(3, "VEX hubs", "vex-hubs") + table(
            ["Hub", "Author", ("Indexes",), ("Matched",), "Status"], rows))

    feeds = res.get("distro_feeds") or []
    if feeds:
        rows = []
        for d in feeds:
            status = esc(d["error"]) if d.get("error") else '<span class="muted">ok</span>'
            rows.append([esc(d.get("name", "")), esc(d.get("matched", 0)),
                         esc(d.get("cleared", 0)), status])
        blocks.append(anchored(3, "Distribution feeds", "distro-feeds") + table(
            ["Feed", ("Matched",), ("Cleared",), "Status"], rows))

    notes = []
    tri = res.get("triage")
    if tri:
        bits = ["scored %d" % tri.get("scored", 0)]
        if tri.get("known_exploited") is not None:
            bits.append("%d known exploited" % tri.get("known_exploited", 0))
        if tri.get("not_in_feed"):
            bits.append("%d not in the EPSS feed" % tri["not_in_feed"])
        if tri.get("no_cve"):
            bits.append("%d with no CVE id to look up" % tri["no_cve"])
        dates = []
        if tri.get("epss_date"):
            dates.append("EPSS %s%s" % (tri["epss_date"], " (stale)" if tri.get("epss_stale") else ""))
        if tri.get("kev_date"):
            dates.append("KEV %s%s" % (tri["kev_date"], " (stale)" if tri.get("kev_stale") else ""))
        note = "Triage: %s." % ", ".join(bits)
        if dates:
            note += " Feeds as of %s." % "; ".join(dates)
        for key in ("epss_error", "kev_error"):
            if tri.get(key):
                note += " %s feed failed: %s." % (key.split("_")[0].upper(), tri[key])
        notes.append(note)

    unreadable = res.get("unreadable")
    if unreadable and unreadable.get("count"):
        paths = ", ".join(unreadable.get("paths") or [])
        notes.append("%s could not be read and were skipped%s."
                     % (plural(unreadable["count"], "path"), (": " + paths) if paths else ""))

    withheld = res.get("withheld")
    if withheld and withheld.get("count"):
        kept = ", ".join(withheld.get("severities") or [])
        hidden = withheld.get("by_severity") or {}
        detail = ", ".join("%d %s" % (hidden[s], s)
                           for s in sorted(hidden, key=lambda s: SEVERITY_RANK.get(s, 6)))
        notes.append("--severity kept %s; %s hidden from this page (%s)."
                     % (kept, plural(withheld["count"], "finding"), detail))

    corrections = res.get("corrections")
    if corrections and corrections.get("count"):
        notes.append("%s dropped: the advisory's own ranges excluded the version it "
                     "was matched against (%s)."
                     % (plural(corrections["count"], "match", "es"),
                        ", ".join((corrections.get("advisories") or [])[:6])))

    if notes:
        blocks.append("".join('<p class="muted">%s</p>' % esc(n) for n in notes))

    if not blocks:
        return ""
    return anchored(2, "Scan coverage", "coverage") + "".join(blocks)


def when(stamp):
    """An RFC 3339 timestamp as the text report prints it: minutes, in UTC.

    The JSON carries microseconds because it is a machine's copy. Nobody reads
    a report to find out which microsecond it started in.
    """
    text = str(stamp or "")
    # Go's zero time.Time marshals rather than omits, so "the scan resolved no
    # advisories at all" arrives as year 1 instead of as an absent field. It is
    # an absence, and printing it as a date would be a lie about a clean image.
    if not text or text.startswith("0001-01-01"):
        return ""
    try:
        cleaned = re.sub(r"\.\d+", "", text).replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return text  # an unparseable stamp is still worth showing verbatim


def render_footer(d, source_name):
    """d is a descriptor dict -- a result's own, or one synthesized for a fleet."""
    items = []

    def add(label, value):
        if value:
            items.append("<dt>%s</dt><dd>%s</dd>" % (esc(label), esc(value)))

    tool = " ".join(x for x in (d.get("tool"), d.get("version")) if x)
    add("scanned by", tool)
    add("started", when(d.get("started")))
    add("took", d.get("duration"))
    add("advisories from", d.get("advisory_source"))
    # A report outlives the run that made it, so the age of the advisories
    # behind it belongs on the page rather than in the reader's assumptions.
    add("advisories as of", when(d.get("advisories_as_of")))
    for note in d.get("advisory_notes") or []:
        add("note", note)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    dl = "<dl>%s</dl>" % "".join(items) if items else ""
    return ('<div class="page-footer">%s<div>Rendered from <code>%s</code> by '
            "contrib/vexscan-dashboard.py &nbsp;&middot;&nbsp; %s</div></div>"
            % (dl, esc(source_name), esc(now)))


def page(title, subtitle, body, nav_href=None):
    back = ""
    if nav_href:
        back = ('<a class="subtitle" href="%s" style="margin-left:auto">'
                "&#8592; all targets</a>" % esc(nav_href))
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>%s</title>
<style>%s</style>
%s
</head>
<body>
<header class="page-header">
  <div class="brand">%s vexscan</div>
  <span class="subtitle">%s</span>
  %s%s
</header>
<main class="page-content">
%s
</main>
%s
</body>
</html>
""" % (esc(title), CSS, THEME_HEAD, LOGO_SVG, esc(subtitle), back, THEME_TOGGLE,
       body, PAGE_SCRIPT)


# ---------------------------------------------------------------------------
# Single-target page
# ---------------------------------------------------------------------------


def render_report(res, source_name, nav_href=None):
    findings = res.get("findings") or []
    sections_html, counts = render_sections(findings)
    target = res.get("target", "(unknown target)")
    mode = res.get("mode", "")

    sub = "%s scan" % mode if mode else "scan"
    if res.get("module"):
        sub += " · module %s" % res["module"]
    sub += " · %s" % plural(len(findings), "finding")

    filter_bar = ""
    if findings:
        filter_bar = (
            '<div class="filter-bar">'
            '<input type="search" placeholder="Filter by CVE, package, binary, '
            'justification…" data-scope="sections" data-hits="hits" '
            'oninput="vexFilter(this)" aria-label="Filter findings">'
            '<span class="hits" id="hits"></span></div>'
        )

    body = [
        "<h1>%s</h1>" % esc(target),
        '<p class="page-sub">%s</p>' % esc(sub),
        render_headline(res, counts),
        render_cards(counts, extra=remediation_card(res)),
        render_remediation(res),
        filter_bar,
        '<div id="sections">%s</div>' % sections_html,
        render_coverage(res),
        render_footer(res.get("descriptor") or {}, source_name),
    ]
    return page("vexscan — %s" % target, target, "".join(body), nav_href)


# ---------------------------------------------------------------------------
# Fleet index
# ---------------------------------------------------------------------------


def target_filename(target, seen):
    """A file name per target that survives a registry path and a tag.

    Collisions are resolved by suffix rather than by hashing: two targets that
    slug the same are rare, and a reader who opens the wrong one because the
    name was a hash would have no way to tell.
    """
    base = slug(target)[:80] or "target"
    name = base
    n = 2
    while name in seen:
        name = "%s-%d" % (base, n)
        n += 1
    seen.add(name)
    return name + ".html"


def render_index(batch, source_name, pages):
    """pages is a list of (result, filename)."""
    totals = {key: 0 for key, _, _ in SECTIONS}
    rows = []
    clean = 0
    for res, filename in pages:
        counts = {key: 0 for key, _, _ in SECTIONS}
        worst = None
        for f in res.get("findings") or []:
            b = bucket_of(f)
            counts[b] += 1
            totals[b] += 1
            if b == BUCKET_AFFECTED:
                sev = display_severity(f)
                if worst is None or SEVERITY_RANK.get(sev, 6) < SEVERITY_RANK.get(worst, 6):
                    worst = sev
        if counts[BUCKET_AFFECTED] == 0:
            clean += 1
        components = sum(e.get("components", 0) for e in (res.get("ecosystems") or []))
        broken = [e for e in (res.get("ecosystems") or []) if e.get("error")]
        if worst:
            state = severity_badge(worst)
        elif broken:
            state = ""  # never "clear": nothing here establishes that
        else:
            state = '<span class="pill pill-vex">clear</span>'
        if broken:
            # Shown alongside the worst severity rather than instead of it. An
            # image with a CRITICAL and a plugin that failed has both problems,
            # and the badge that replaced the other would hide one of them.
            state += ' <span class="sev sev-CRITICAL" title="%s">incomplete</span>' % esc(
                "; ".join("%s: %s" % (e.get("id", "?"), e["error"]) for e in broken))
        rows.append((
            counts[BUCKET_AFFECTED],
            SEVERITY_RANK.get(worst, 9),
            [
                '<a href="%s">%s</a>' % (esc(filename), esc(res.get("target", ""))),
                state,
                esc(components),
                esc(counts[BUCKET_AFFECTED]),
                esc(counts[BUCKET_VEXED]),
                esc(counts[BUCKET_UNDETERMINED]),
                esc(counts[BUCKET_RULED_OUT]),
            ],
        ))
    # Worst first: the fleet's job is to tell you which image to open.
    rows.sort(key=lambda r: (r[1], -r[0]))

    # The batch header's own count, not the number of pages: a target that
    # failed to pull is still a target that was asked for, and an index that
    # quietly said "2 targets" for a run over three would be the wrong summary
    # of the wrong fleet.
    declared = batch.get("targets") or len(pages)
    sub = "%s · %s" % (plural(declared, "target"), plural(sum(totals.values()), "finding"))
    if len(pages) != declared:
        sub += " · %d scanned" % len(pages)
    body = ["<h1>Fleet scan</h1>", '<p class="page-sub">%s</p>' % esc(sub)]

    failures = batch.get("failures") or []
    if failures:
        # A target that could not be scanned is not a target with no findings,
        # and the difference has to survive onto the index page.
        items = "".join("<li><code>%s</code> &mdash; %s</li>"
                        % (esc(f.get("target", "")), esc(f.get("error", "")))
                        for f in failures)
        body.append('<div class="banner banner-bad"><span class="icon">&#9888;</span>'
                    "<span>%s could not be scanned at all</span></div>"
                    "<ul class=\"muted\">%s</ul>" % (esc(plural(len(failures), "target")), items))
    elif totals[BUCKET_AFFECTED] == 0:
        body.append('<div class="banner banner-ok"><span class="icon">&#10004;</span>'
                    "<span>Nothing to act on across the fleet.</span></div>")
    else:
        body.append('<div class="banner banner-warn"><span class="icon">&#9888;</span>'
                    "<span>%s to act on <span class=\"sub\">&mdash; %d of %s clear"
                    "</span></span></div>"
                    % (esc(plural(totals[BUCKET_AFFECTED], "finding")), clean,
                       esc(plural(len(pages), "target") + (" is" if clean == 1 else " are"))))

    body.append(render_cards(totals, link=False))
    body.append(
        '<div class="filter-bar">'
        '<input type="search" placeholder="Filter targets…" data-scope="fleet" '
        'data-hits="hits" oninput="vexFilter(this)" aria-label="Filter targets">'
        '<span class="hits" id="hits"></span></div>'
    )

    headers = ["Target", "Worst", ("Components",), ("Affected",), ("Vexed",),
               ("Undetermined",), ("Ruled out",)]
    out = ['<div id="fleet" class="table-wrap"><table class="report-table"><thead><tr>']
    for h in headers:
        cls = ' class="num"' if isinstance(h, tuple) else ""
        out.append("<th%s>%s</th>" % (cls, esc(h[0] if isinstance(h, tuple) else h)))
    out.append("</tr></thead>")
    for _, _, cells in rows:
        text = " ".join(re.sub(r"<[^>]+>", " ", c) for c in cells).lower()
        out.append('<tbody class="f-group" data-search="%s"><tr>' % esc(text))
        for h, cell in zip(headers, cells):
            cls = ' class="num"' if isinstance(h, tuple) else ""
            out.append("<td%s>%s</td>" % (cls, cell))
        out.append("</tr></tbody>")
    out.append("</table></div>")
    body.append("".join(out))

    body.append(render_footer(fleet_descriptor([r for r, _ in pages]), source_name))
    return page("vexscan — fleet", plural(len(pages), "target"), "".join(body))


def fleet_descriptor(results):
    """One descriptor for a whole batch.

    Each target carries its own -- a start, a duration, the moment its
    advisories were fetched. Borrowing the first one for the index would tell a
    reader the fleet took four seconds. So the timings that only make sense per
    target are dropped, and the two that make sense for the run are widened:
    the earliest start, and the oldest advisory fetch, which is the real answer
    to "how stale is this page".
    """
    descs = [r.get("descriptor") or {} for r in results]
    descs = [d for d in descs if d]
    if not descs:
        return {}
    # A target that resolved no advisories carries a zero time, which would
    # sort first and hand the whole fleet an advisory age of year 1.
    real = lambda v: v and not str(v).startswith("0001-01-01")
    starts = sorted(d["started"] for d in descs if real(d.get("started")))
    asof = sorted(d["advisories_as_of"] for d in descs if real(d.get("advisories_as_of")))
    out = {
        "tool": descs[0].get("tool"),
        "version": descs[0].get("version"),
        "advisory_source": descs[0].get("advisory_source"),
    }
    if starts:
        out["started"] = starts[0]
    if asof:
        out["advisories_as_of"] = asof[0]
    notes = []
    for d in descs:
        for n in d.get("advisory_notes") or []:
            if n not in notes:
                notes.append(n)
    if notes:
        out["advisory_notes"] = notes
    return out


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def load(path):
    if path == "-":
        return json.load(sys.stdin), "stdin"
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh), os.path.basename(path)


def is_batch(doc):
    return isinstance(doc.get("results"), list) and "findings" not in doc


def write(path, content):
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    except OSError as err:
        sys.exit("vexscan-dashboard: %s" % err)
    return path


def main():
    ap = argparse.ArgumentParser(
        description="Render a vexscan --format json report as an HTML dashboard.",
        epilog="A batch report (--images-from) needs -o to name a directory: it "
               "renders an index and one page per target.",
    )
    ap.add_argument("report", help="vexscan --format json output, or - for stdin")
    ap.add_argument("-o", "--out", default="-",
                    help="output file, or directory for a batch report (default: stdout)")
    args = ap.parse_args()

    try:
        doc, source_name = load(args.report)
    except OSError as err:
        sys.exit("vexscan-dashboard: %s" % err)
    except ValueError as err:
        sys.exit("vexscan-dashboard: %s is not JSON: %s" % (args.report, err))

    if not isinstance(doc, dict) or not (is_batch(doc) or "findings" in doc):
        sys.exit("vexscan-dashboard: %s is not a vexscan JSON report; "
                 "generate one with --format json" % args.report)

    if not is_batch(doc):
        html_out = render_report(doc, source_name)
        if args.out == "-":
            sys.stdout.write(html_out)
        else:
            print("vexscan-dashboard: wrote %s" % write(args.out, html_out), file=sys.stderr)
        return

    results = [r for r in doc["results"] if r]
    if args.out == "-":
        sys.exit("vexscan-dashboard: a batch report renders several pages; "
                 "pass -o DIR to say where they go")
    outdir = args.out
    try:
        os.makedirs(outdir, exist_ok=True)
    except OSError as err:
        sys.exit("vexscan-dashboard: %s" % err)

    seen = set()
    pages = [(res, target_filename(res.get("target", "target"), seen)) for res in results]
    for res, filename in pages:
        write(os.path.join(outdir, filename), render_report(res, source_name, "index.html"))
    write(os.path.join(outdir, "index.html"), render_index(doc, source_name, pages))
    print("vexscan-dashboard: wrote index.html and %s in %s"
          % (plural(len(pages), "target page"), outdir), file=sys.stderr)


if __name__ == "__main__":
    main()
