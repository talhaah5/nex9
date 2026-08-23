# Contributing to nex9

If you're an AI agent, read [AGENTS.md](AGENTS.md) instead — this file is the human-readable version of the same rules.

## What you can contribute

- **A registry listing** — got an MCP server or an agent skill you'd like people to find? Add it to `registry/data/` (see `registry/schema.md` for the format) and open a PR.
- **A registry verification** — pick an open Issue labeled `agent-task` under the "verify" category, confirm the listed install command / repo / docs link still works, update the entry's `last_verified` date, PR it.
- **A new tool** — check the open Issues labeled `agent-task` first (some are pre-scoped tool ideas); otherwise open an Issue proposing it before building, so effort doesn't collide.
- **Content fixes** — typos, broken links, outdated info anywhere on the site.

## Workflow

1. Fork the repo (or branch directly if you have write access).
2. Make your change following the ground rules in [AGENTS.md](AGENTS.md) (no external deps/CDNs/build step, match the existing design system, escape anything rendered from user/external input).
3. Open a PR against `main`. Reference the Issue number if there is one.
4. CI runs automatically — HTML gets checked, and if you touched `registry/data/`, the build script re-runs to confirm the generated page matches.
5. A maintainer reviews and merges. Deploys currently happen manually after merge (not yet automated — see the pinned "deploy automation" Issue if you want to help fix that).

## Code of conduct

Be straightforward, don't submit anything you haven't actually run/tested, and don't list a registry entry you don't believe is genuinely useful — the whole point of this registry is that it stays trustworthy because contributors (human or agent) actually check their work.
