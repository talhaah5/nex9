#!/usr/bin/env python3
"""Build foundry/registry.html from registry/data/*.yaml.

Pure stdlib + PyYAML. Deterministic: running this twice against unchanged
data produces byte-identical output (no timestamps, no non-deterministic
ordering) so CI can diff the generated file.

Usage (from repo root):
    python3 scripts/build-registry.py
"""

from __future__ import annotations

import html
import pathlib
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "error: PyYAML is required. Install it with: pip install pyyaml\n"
    )
    sys.exit(1)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "registry" / "data"
OUTPUT_PATH = REPO_ROOT / "foundry" / "registry.html"

REQUIRED_FIELDS = (
    "name",
    "slug",
    "type",
    "summary",
    "description",
    "repo_url",
    "install",
    "license",
    "maintainer",
    "tags",
    "added_by",
    "added_date",
    "last_verified",
    "verified_by",
)

TYPE_LABELS = {
    "mcp-server": "MCP Servers",
    "skill": "Skills",
}

# Sections are rendered in this fixed order regardless of dict iteration
# order, so output stays stable even if new types are ever added.
TYPE_ORDER = ("mcp-server", "skill")


def escape_html(value: object) -> str:
    """Escape a YAML-sourced value for safe interpolation into HTML."""
    return html.escape(str(value), quote=True)


def load_entries(data_dir: pathlib.Path) -> list[dict]:
    entries: list[dict] = []
    for path in sorted(data_dir.glob("*.yaml")):
        with path.open("r", encoding="utf-8") as fh:
            entry = yaml.safe_load(fh)

        if not isinstance(entry, dict):
            raise ValueError(f"{path}: expected a YAML mapping at top level")

        missing = [f for f in REQUIRED_FIELDS if f not in entry or entry[f] in (None, "")]
        if missing:
            raise ValueError(f"{path}: missing required field(s): {', '.join(missing)}")

        expected_slug = path.stem
        if entry["slug"] != expected_slug:
            raise ValueError(
                f"{path}: slug '{entry['slug']}' does not match filename '{expected_slug}.yaml'"
            )

        if entry["type"] not in TYPE_LABELS:
            raise ValueError(
                f"{path}: unknown type '{entry['type']}' (expected one of {sorted(TYPE_LABELS)})"
            )

        if not isinstance(entry.get("tags"), list):
            raise ValueError(f"{path}: 'tags' must be a list")

        entries.append(entry)
    return entries


def render_badge(tag: object) -> str:
    return f'<span class="badge">{escape_html(tag)}</span>'


def render_card(entry: dict) -> str:
    name = escape_html(entry["name"])
    summary = escape_html(entry["summary"])
    repo_url = escape_html(entry["repo_url"])
    tags_html = "".join(render_badge(tag) for tag in entry["tags"])

    return f"""    <a class="tool-card" href="{repo_url}" target="_blank" rel="noopener noreferrer">
      <span class="name">{name}</span>
      <span class="desc">{summary}</span>
      <div class="tag-row">{tags_html}</div>
    </a>"""


def render_section(type_key: str, entries: list[dict]) -> str:
    label = TYPE_LABELS[type_key]
    matching = sorted(
        (e for e in entries if e["type"] == type_key),
        key=lambda e: e["name"].lower(),
    )
    if not matching:
        return ""

    cards = "\n".join(render_card(e) for e in matching)
    return f"""  <div class="category-label">{escape_html(label)} ({len(matching)})</div>
  <div class="grid">
{cards}
  </div>
"""


def render_page(entries: list[dict]) -> str:
    total = len(entries)
    sections = "\n".join(
        section for t in TYPE_ORDER if (section := render_section(t, entries))
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>The Foundry Registry — MCP Servers &amp; Agent Skills | nex9</title>
<meta name="description" content="A curated, continuously agent-maintained registry of {total} real MCP servers and AI-agent skills, with verified install commands and repo links.">
<link rel="canonical" href="https://nex9.de/foundry/registry.html">
<link rel="icon" href="data:,">
<link rel="stylesheet" href="/style.css">
<script type="application/ld+json">
{{"@context":"https://schema.org","@type":"ItemList","name":"The Foundry Registry","description":"Curated registry of MCP servers and AI-agent skills","numberOfItems":{total}}}
</script>
<script src="/consent.js" defer></script>
<style>
.tag-row {{ margin-top: 10px; display: flex; flex-wrap: wrap; gap: 6px; }}
.tool-card .desc {{ display: block; margin: 4px 0 0; }}
</style>
</head>
<body>
<header class="site">
  <div class="bar">
    <a class="brand" href="/"><span class="dot">▸</span> nex9<span style="color:var(--text-dim);font-weight:500">.de</span></a>
    <nav class="top">
      <a href="/#tools">Tools</a>
      <a href="/foundry/">The Foundry</a>
      <a href="/blog/">Blog</a>
      <a href="/about.html">About</a>
    </nav>
  </div>
</header>
<main class="wrap">
  <div class="breadcrumb"><a href="/">Home</a> / <a href="/foundry/">The Foundry</a> / Registry</div>
  <h1>The Foundry Registry</h1>
  <p class="lede">{total} verified MCP servers and agent skills, each with a real repo link and a copy-pasteable install command. Maintained by AI agents via GitHub PRs — see <a href="/foundry/">how it works</a>.</p>

{sections}
  <div class="privacy-note"><strong>Contributing:</strong> Found a stale entry or want to add a real MCP server or skill? Open a PR against <a href="https://github.com/talhaah5/nex9">talhaah5/nex9</a> — see AGENTS.md and CONTRIBUTING.md in the repo root for the schema and verification checklist.</div>
</main>
<footer class="site">
  <div class="wrap">
    <span>© <span id="y"></span> nex9.de — free developer tools</span>
    <span class="links"><a href="/about.html">About</a><a href="/privacy.html">Privacy</a><a href="/terms.html">Terms</a></span>
  </div>
</footer>
<script>document.getElementById('y').textContent = new Date().getFullYear();</script>
</body>
</html>
"""


def build() -> None:
    entries = load_entries(DATA_DIR)
    page = render_page(entries)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(page, encoding="utf-8")
    print(f"wrote {OUTPUT_PATH} ({len(entries)} entries)")


if __name__ == "__main__":
    build()
