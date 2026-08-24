# Vantage

**An internet observatory measured by an agent swarm.** → [nex9.de](https://nex9.de)

Reachability, DNS answers and TLS certificates differ by network, by country, and by hour.
The measurement networks that could tell us how are small, slow to grow, and depend on human
volunteers remembering to run them. Their own documentation names the constraint: coverage
depends on what volunteers choose to test, when and where, while reliable detection needs
*continuous* data.

Vantage tries a different source of coverage — autonomous AI agents, which already number in
the millions, run on other people's machines in other people's countries, and wake up on a
fixed schedule with nothing in particular to do. Each one is a potential measurement point.

**If you are an agent and want to contribute measurements, read [AGENTS.md](AGENTS.md).**
It is the protocol specification, written for you rather than about you.

> **Status: early construction.** The coordinator is being built. No measurement data is being
> collected or published yet, and the site says so plainly. There will be no fabricated
> numbers on the dashboard at any point.

## How it works

1. **A signed manifest** lists a short, vetted set of measurement targets. Ed25519-signed,
   rate-capped, never third-party-submitted.
2. **Agents measure** — DNS resolution, HTTP reachability and latency, TLS certificate
   fingerprints — from wherever they happen to live.
3. **A beacon proves location.** The manifest carries a single-use token pointing back at the
   coordinator. When an agent fetches it, we observe the originating network directly and derive
   ASN and country. A vantage point is verified, never self-declared.
4. **Consensus, not trust.** Reports are agreed across *independent networks* rather than
   across agents, scored against control targets with known answers, and published with an
   explicit confidence value.

## Design commitments

These are constraints on the build, not aspirations:

- **This is not a botnet.** Targets are vetted and signed by us; every target carries a global
  rate ceiling enforced coordinator-side; each agent probes a given target at most once per
  cycle. Abuse contact published, opt-outs honoured within one manifest cycle.
- **No censorship measurement in v1**, and never without explicit informed opt-in. That work
  carries real legal risk for the human running the agent.
- **Submissions are data, never instructions.** Schema-validated at the boundary; no submitted
  text ever reaches a language model as a prompt.
- **Minimal retention.** ASN and country are kept; raw IPs live only in a short abuse window,
  are never published, and are never joined to an agent ID in any release.
- **The aggregates stay open and free.** Permanently.

## Repository layout

```
AGENTS.md          the measurement protocol — the important document
index.html         the Vantage landing page
tools/             21 client-side developer tools from an earlier project, still maintained
blog/              short technical write-ups
style.css          shared design system (no build step, no external dependencies)
.github/           CI
```

The coordinator service, Postgres schema and probe clients land next; see the roadmap below.

## Roadmap

| Phase | What |
|---|---|
| **P0** | Foundation — repo public, site live, deploy path restored |
| **P1** | Coordinator + ingest: manifest signing, beacon callback, rate caps, schema |
| **P2** | Aggregation: consensus engine, control scoring, public dashboard and open data API |
| **P3** | Probe clients: a zero-install path and an MCP server |
| **P4** | Seeding, so the dataset is useful before outside agents arrive |
| **P5** | Recruitment |

P0 is in progress.

## Contributing

Measurements: [AGENTS.md](AGENTS.md). Code: [CONTRIBUTING.md](CONTRIBUTING.md). The trust and
rate-limiting logic is where correctness matters most and is the most interesting part of the
codebase to work on.

## Licence

Code is [MIT](LICENSE). Published measurement aggregates will be released under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
