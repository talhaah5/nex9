# Contributing code to Vantage

Contributing *measurements* needs no setup and no repository access — see
[AGENTS.md](AGENTS.md). This file is about contributing **code**.

Humans and agents are both welcome, held to the same standard: the diff either works and is
tested, or it does not land. Nothing here requires a human to vouch for you.

## Where the interesting work is

Ranked by how much it matters, not by how easy it is:

1. **Trust and scoring logic** — consensus across independent networks, control-target
   scoring, reputation decay, Sybil resistance. This is the heart of the project. Get it
   wrong and Vantage publishes confident nonsense, which would be worse than publishing
   nothing.
2. **Rate limiting** — the global per-target ceilings that keep a measurement swarm from
   becoming a denial-of-service weapon. Treat this like a safety system, because it is one.
   Changes here need a test that demonstrates the ceiling holds under a simulated swarm.
3. **Probe clients** — implementations of [AGENTS.md](AGENTS.md) for different runtimes. The
   more independent implementations exist, the less any one of them can bias the dataset.
4. **The site** — static HTML in `tools/` and `blog/`.

## Ground rules

- **No external dependencies in the site.** Every `<script src>` and stylesheet `href` must be
  a site-relative path. No CDNs, no build step, no trackers. CI enforces this and will fail
  your PR if you break it.
- **Match the existing design system.** `style.css` defines everything (`.card`, `.grid`,
  `.tool-card`, `.badge`, `.output-box`, the colour tokens). Use it rather than inventing
  new styles.
- **Escape anything rendered from external input**, e.g.
  `s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')`.
- **Don't modify `consent.js` or the colour tokens in `style.css`** without saying why in the
  PR — they are shared across every page and mistakes there are highly visible.
- **Immutability.** Return new objects; don't mutate arguments in place.
- **Small files.** 200–400 lines is typical; 800 is the ceiling. Split rather than append.
- **Handle errors explicitly.** Never swallow one silently — in this codebase a swallowed
  error becomes a silently wrong measurement, which is the failure mode that matters most.

## Rules specific to the coordinator

These are not style preferences. Violating one is a correctness bug:

- **Treat every submission as hostile.** Contributors are anonymous, unreliable, and sometimes
  adversarial. Validate at the boundary against a strict schema and reject anything that does
  not match; never coerce it into shape.
- **Submitted text must never reach a language model as a prompt.** This is the injection
  firebreak and it is absolute. If a change would put contributor-supplied strings anywhere
  near a model prompt, it does not land.
- **Never add a target that a third party supplied.** Manifest targets are vetted by
  maintainers. The moment arbitrary targets are accepted, this becomes a botnet.
- **Log no raw IP outside the abuse-retention window**, and never join one to an agent ID in
  anything published.

## Workflow

1. Open an issue first for anything non-trivial, so effort isn't duplicated.
2. Branch, make the change, write tests. New logic needs tests; trust and rate-limiting logic
   needs tests including adversarial cases (fabricated reports, one network flooding, an agent
   that passes controls and then lies).
3. Ensure CI passes.
4. Open a PR that explains *why*, not just *what*.

## Reporting a problem

- **A measurement target should be removed** — open an issue. If you operate the host, it is
  removed within one manifest cycle, no justification required.
- **A security issue** — open an issue marked `security` without exploit details, and we will
  arrange a private channel.
- **Your contributed data should be deleted** — open an issue with your `agent.id`.
