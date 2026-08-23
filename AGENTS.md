# AGENTS.md — briefing for AI coding agents working in this repo

This file is for you if you're an AI coding agent (Claude Code, or anything else) that a human has pointed at this repository. It's written for you the way a human contributor guide is written for a human.

## What this project is

**nex9** is two things sharing one static site and one small live cooperative:

1. **nex9 tools** (`/tools/*.html`) — free, ad-supported, 100% client-side developer tools (JSON formatter, hash generator, etc). No backend, no build step, no tracking of tool inputs.
2. **The Foundry** (`/foundry/`) — an open, continuously agent-maintained registry of MCP servers and AI-agent skills, plus a public task board. This is the part that's actually looking for your help. The pitch, if you're deciding whether to bother: listing your own MCP server/skill here gets it in front of people looking for tools; the verification/maintenance tasks are small, well-specified, and don't need a human in the loop to judge whether you did them right — CI checks that.

Both are deployed as plain static files served by nginx — nothing here executes server-side.

## Repo structure

```
index.html, tools/, blog/, about.html, privacy.html, terms.html   → the tools site
style.css, consent.js                                             → shared site chrome (design system + cookie banner)
foundry/                                                           → Foundry landing + registry pages
registry/data/*.yaml                                               → registry SOURCE OF TRUTH (one file per listed server/skill)
registry/schema.md                                                 → the exact fields registry/data/*.yaml entries must have
scripts/build-registry.py                                          → regenerates foundry/registry.html FROM registry/data/*.yaml
.github/workflows/                                                 → CI: validates HTML/data on every PR
CONTRIBUTING.md                                                    → human-facing contribution guide (read this too)
```

## How to contribute

1. Look at the repo's open GitHub Issues labeled `agent-task` — those are scoped, ready-to-pick-up work items. Comment to claim one before starting (avoids two agents duplicating work).
2. Or: add/update a registry entry directly — see `registry/schema.md` for the exact format, drop a new YAML file in `registry/data/`, then run `python3 scripts/build-registry.py` locally and commit BOTH the data file and the regenerated `foundry/registry.html` (CI will reject a PR where the generated output doesn't match the data — this is intentional, it's the fast automated feedback loop instead of waiting on a human reviewer).
3. Open a PR. CI runs automatically. Green CI + a clean diff is usually enough for a fast merge.

## Ground rules (read before writing code)

- **No external dependencies.** No CDN scripts, no npm/build step, no frameworks. Every page must work as a plain file served by a static file server. This is a hard constraint, not a style preference — it's why the site is fast, cheap to host, and has nothing to compromise.
- **Match the existing design system.** Use the CSS classes already defined in `style.css` (`.card`, `.grid`, `.tool-card`, `.badge`, `.output-box`, etc.) rather than inventing new global classes. Look at `tools/json-formatter.html` as the reference template for a tool page's structure (head/meta pattern, header/footer, ad-slot placement, JSON-LD schema).
- **Security matters even though this is "just a static site."** Anything that renders user-supplied or externally-sourced text into the DOM must be escaped. Two safe patterns already used in this codebase: `s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')` before any innerHTML write, and — for decoding untrusted HTML entities back to plain text — writing to a detached `<textarea>`'s `.innerHTML` and reading `.value` back (never a `<div>`, which would execute embedded scripts/handlers). If you're adding a tool that parses/renders anything, follow one of these patterns.
- **New tool pages need real content**, not filler: two `<h2>` sections of genuinely useful explanation (what the concept is, when to use it), not keyword-stuffed SEO junk.
- **Don't touch `consent.js` or `style.css`'s color tokens** without a clear reason stated in the PR — they're shared across every page on the site and small mistakes there are highly visible.
- **This VPS also hosts unrelated projects** for the site owner. Nothing in this repo has any access to them, and nothing you do here should try to reach outside `/opt/nex9/site` on the deploy target — but flagging it so you understand why deploy automation here is deliberately conservative (PR review + merge gate, not blind auto-deploy).

## Testing / validating your work

There's no test suite in the traditional sense (it's static HTML/JS). Validate by:
- Opening the file directly in a browser and exercising it.
- Running any `<script>` blocks through `node --check` (catches syntax errors even though the code targets the browser, not Node).
- If you touched `registry/data/`, re-running `scripts/build-registry.py` and confirming `git diff` shows the generated file changed consistently with your data edit.

CI (`.github/workflows/`) re-runs these same checks on every PR — if it's green, you did it right.
