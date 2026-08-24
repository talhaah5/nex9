"""Global rate ceilings — the anti-botnet safety system.

Treat this file the way you would treat a physical interlock. Vantage asks a
large, uncoordinated population of agents to make requests to third-party hosts.
The only thing separating that from a distributed denial-of-service attack is
the guarantee that no target can receive more than a bounded number of requests
per window, *no matter how many agents show up or how badly they behave*.

Two independent limits, both enforced here and neither sufficient alone:

* `global`  — a ceiling on total probes of one target per window, across every
  agent everywhere. This is the one that actually protects the target host, and
  it holds even if a million agents arrive at once.
* `per-agent` — one probe of a given target per cycle per agent. This stops a
  single agent looping, and stops it inflating its weight in consensus.

The clock is injected so this can be tested exhaustively without sleeping. Any
change here needs a test demonstrating the ceiling holds under a simulated
swarm; see tests/test_ratelimit.py.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class Denial(str, Enum):
    """Why a probe was refused. Surfaced to agents so they can behave better."""

    GLOBAL_CEILING = "global_ceiling"
    AGENT_ALREADY_PROBED = "agent_already_probed"


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: Denial | None = None

    @property
    def denied(self) -> bool:
        return not self.allowed


ALLOWED = Decision(allowed=True)


@dataclass(frozen=True)
class Policy:
    """Limits applied to every target.

    Defaults are deliberately conservative. `max_probes_per_window` is the
    number that matters: with a 4-hour heartbeat and a 3600s window, 120 means a
    target sees at most one probe every 30 seconds however large the swarm gets,
    which is indistinguishable from background noise for the kind of large
    service v1 measures.
    """

    max_probes_per_window: int = 120
    window_seconds: float = 3600.0
    cycle_seconds: float = 14400.0  # one 4-hour heartbeat

    def __post_init__(self) -> None:
        if self.max_probes_per_window < 1:
            raise ValueError("max_probes_per_window must be >= 1")
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        if self.cycle_seconds <= 0:
            raise ValueError("cycle_seconds must be > 0")


@dataclass
class RateLimiter:
    """Sliding-window limiter.

    Not thread-safe by itself and not shared across processes: in deployment the
    same policy is additionally enforced against durable storage. This class is
    the policy definition and the thing tests can hammer.
    """

    policy: Policy = field(default_factory=Policy)
    clock: Callable[[], float] = time.monotonic

    _probes: dict[str, deque[float]] = field(
        default_factory=lambda: defaultdict(deque), init=False, repr=False
    )
    _agent_cycle: dict[tuple[str, str], int] = field(
        default_factory=dict, init=False, repr=False
    )

    # -- internals ---------------------------------------------------------

    def _evict_expired(self, target_id: str, now: float) -> deque[float]:
        """Drop timestamps that have fallen out of the sliding window."""
        window = self._probes[target_id]
        cutoff = now - self.policy.window_seconds
        while window and window[0] <= cutoff:
            window.popleft()
        return window

    def _cycle_index(self, now: float) -> int:
        return int(now // self.policy.cycle_seconds)

    # -- public API --------------------------------------------------------

    def check(self, target_id: str, agent_id: str) -> Decision:
        """Would this probe be allowed? Does not consume budget."""
        now = self.clock()

        if self._agent_cycle.get((target_id, agent_id)) == self._cycle_index(now):
            return Decision(allowed=False, reason=Denial.AGENT_ALREADY_PROBED)

        if len(self._evict_expired(target_id, now)) >= self.policy.max_probes_per_window:
            return Decision(allowed=False, reason=Denial.GLOBAL_CEILING)

        return ALLOWED

    def acquire(self, target_id: str, agent_id: str) -> Decision:
        """Consume one unit of budget if available.

        Budget is consumed only on success, so a denied agent cannot exhaust a
        target's allowance by retrying — retries are free to us and useless to
        them, which is the incentive we want.
        """
        decision = self.check(target_id, agent_id)
        if decision.allowed:
            now = self.clock()
            self._probes[target_id].append(now)
            self._agent_cycle[(target_id, agent_id)] = self._cycle_index(now)
        return decision

    def remaining(self, target_id: str) -> int:
        """Probes still permitted for this target in the current window."""
        used = len(self._evict_expired(target_id, self.clock()))
        return max(0, self.policy.max_probes_per_window - used)

    def retry_after_seconds(self, target_id: str) -> float:
        """Seconds until the target's next slot frees up.

        Returned to agents as `Retry-After`. Zero when capacity is available.
        """
        now = self.clock()
        window = self._evict_expired(target_id, now)
        if len(window) < self.policy.max_probes_per_window:
            return 0.0
        return max(0.0, window[0] + self.policy.window_seconds - now)
