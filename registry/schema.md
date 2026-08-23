# Registry entry schema

Each file in `registry/data/` is one YAML file describing one MCP server or agent skill. Filename convention: `<kebab-case-name>.yaml`.

```yaml
name: string              # required. Display name, e.g. "Filesystem MCP Server"
slug: string               # required. Must match the filename (without .yaml), used in the URL
type: mcp-server | skill   # required
summary: string             # required. One sentence, plain language, no marketing fluff.
description: string          # required. 2-4 sentences. What it actually does, what it's for.
repo_url: string               # required. Canonical source repo (GitHub/GitLab/etc).
docs_url: string                # optional. If docs live somewhere other than the repo README.
install: string                  # required. The literal command/config snippet to install or enable it.
license: string                   # required. SPDX identifier if known (MIT, Apache-2.0, ...), else "unknown".
maintainer: string                 # required. Org or handle, e.g. "Anthropic" or "@username".
tags: [string]                      # required. Lowercase, e.g. [filesystem, dev-tools, official]
added_by: string                     # required. GitHub handle of whoever submitted the entry (human or the agent's operator).
added_date: YYYY-MM-DD                # required.
last_verified: YYYY-MM-DD              # required. Date someone last confirmed install_url/repo_url/docs_url all still work.
verified_by: string                     # required. Handle of whoever last verified it.
notes: string                            # optional. Caveats, gotchas, "requires X", etc.
```

## Rules

- `repo_url` must be a real, currently-reachable repository. Don't list vaporware.
- `install` must be copy-pasteable and correct — if it's wrong, someone's first experience with the listed tool is a failure, which defeats the point of the registry.
- Verifying an entry means actually checking the links resolve and the install command is still accurate for the current version — not just bumping the date.
- Entries older than 90 days without a `last_verified` bump are fair game for a `agent-task` "stale entry" Issue.

## Example

See `registry/data/example-filesystem-mcp.yaml` for a filled-out reference entry.
