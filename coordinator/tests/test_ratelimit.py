"""The botnet guard, tested like a safety system.

The claim this file has to defend is narrow and absolute: **no target can
receive more than `max_probes_per_window` probes per window, regardless of how
many agents show up or how they behave.** If that claim ever fails, Vantage is
a distributed denial-of-service tool. So the swarm tests here use adversarial
populations, not happy paths.
"""

from __future__ import annotations

import pytest

from vantage.ratelimit import ALLOWED, Decision, Denial, Policy, RateLimiter


class FakeClock:
    """Monotonic clock we control, so ceilings can be tested without sleeping."""

    def __init__(self, start: float = 1_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


def limiter(clock: FakeClock, **policy_kwargs) -> RateLimiter:
    return RateLimiter(policy=Policy(**policy_kwargs), clock=clock)


# ---------------------------------------------------------------------------
# Policy validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_probes_per_window": 0},
        {"max_probes_per_window": -1},
        {"window_seconds": 0},
        {"window_seconds": -1},
        {"cycle_seconds": 0},
    ],
)
def test_rejects_policy_that_would_disable_the_ceiling(kwargs) -> None:
    """A misconfigured policy must fail loudly at construction.

    A zero or negative window silently disables the protection, which is the
    one failure mode nobody would notice until a target operator complained.
    """
    with pytest.raises(ValueError):
        Policy(**kwargs)


def test_default_policy_is_conservative() -> None:
    policy = Policy()
    probes_per_second = policy.max_probes_per_window / policy.window_seconds
    assert probes_per_second <= 1 / 30, "default must stay under 1 probe / 30s"


# ---------------------------------------------------------------------------
# The global ceiling — the load test the plan calls for
# ---------------------------------------------------------------------------


def test_global_ceiling_holds_against_a_large_swarm(clock: FakeClock) -> None:
    """10,000 distinct well-behaved agents, one target, one window.

    Each agent is unique, so the per-agent rule never fires — only the global
    ceiling stands between the target and 10,000 requests.
    """
    rl = limiter(clock, max_probes_per_window=120)

    granted = sum(
        1 for i in range(10_000) if rl.acquire("t1", f"agent-{i}").allowed
    )

    assert granted == 120
    assert rl.remaining("t1") == 0


def test_ceiling_holds_when_every_agent_retries_relentlessly(clock: FakeClock) -> None:
    """Denied agents that hammer us must not gain anything, or cost anything.

    This is the incentive check: retrying is free to the coordinator and
    useless to the agent, so a badly written client degrades to a no-op rather
    than to an attack.
    """
    rl = limiter(clock, max_probes_per_window=10)

    granted = 0
    for _attempt in range(50):
        for i in range(100):
            if rl.acquire("t1", f"agent-{i}").allowed:
                granted += 1

    assert granted == 10, "retries must never widen the ceiling"


def test_ceiling_is_per_target_not_global_across_targets(clock: FakeClock) -> None:
    """Budgets must not leak between targets, or one busy target starves the rest."""
    rl = limiter(clock, max_probes_per_window=2)

    assert rl.acquire("t1", "a").allowed
    assert rl.acquire("t1", "b").allowed
    assert rl.acquire("t1", "c").denied

    assert rl.acquire("t2", "a").allowed, "t2 has its own untouched budget"


def test_denial_reason_distinguishes_the_two_limits(clock: FakeClock) -> None:
    """Agents get told which rule they hit so they can behave better."""
    rl = limiter(clock, max_probes_per_window=1)

    assert rl.acquire("t1", "a") is ALLOWED
    assert rl.acquire("t1", "a").reason is Denial.AGENT_ALREADY_PROBED
    assert rl.acquire("t1", "b").reason is Denial.GLOBAL_CEILING


# ---------------------------------------------------------------------------
# The sliding window
# ---------------------------------------------------------------------------


def test_budget_recovers_gradually_not_in_a_burst(clock: FakeClock) -> None:
    """A sliding window must free slots one at a time, as each one ages out.

    A fixed window would let a swarm fire the full allowance at 59:59 and again
    at 60:01 — double the intended rate at exactly the worst moment.
    """
    rl = limiter(clock, max_probes_per_window=3, window_seconds=100.0)

    for agent in "abc":
        rl.acquire("t1", agent)
        clock.advance(10.0)  # probes at t=0, 10, 20; now t=30

    assert rl.remaining("t1") == 0

    clock.advance(71.0)  # t=101: only the first probe has aged out
    assert rl.remaining("t1") == 1

    clock.advance(10.0)  # t=111: the second ages out
    assert rl.remaining("t1") == 2


def test_full_window_elapsed_restores_the_whole_budget(clock: FakeClock) -> None:
    rl = limiter(clock, max_probes_per_window=5, window_seconds=100.0)

    for i in range(5):
        assert rl.acquire("t1", f"agent-{i}").allowed
    assert rl.acquire("t1", "agent-x").denied

    clock.advance(101.0)
    assert rl.remaining("t1") == 5
    assert rl.acquire("t1", "agent-x").allowed


def test_retry_after_tells_the_truth(clock: FakeClock) -> None:
    """`Retry-After` must not send agents back early — that just wastes both sides."""
    rl = limiter(clock, max_probes_per_window=1, window_seconds=100.0)

    assert rl.retry_after_seconds("t1") == 0.0, "zero while capacity remains"

    rl.acquire("t1", "a")
    clock.advance(30.0)
    assert rl.retry_after_seconds("t1") == pytest.approx(70.0)

    clock.advance(70.0)
    assert rl.retry_after_seconds("t1") == 0.0
    assert rl.acquire("t1", "b").allowed


def test_retry_after_never_goes_negative(clock: FakeClock) -> None:
    rl = limiter(clock, max_probes_per_window=1, window_seconds=10.0)
    rl.acquire("t1", "a")
    clock.advance(10_000.0)
    assert rl.retry_after_seconds("t1") == 0.0


def test_remaining_on_an_untouched_target_is_the_full_budget(clock: FakeClock) -> None:
    rl = limiter(clock, max_probes_per_window=7)
    assert rl.remaining("never-probed") == 7


# ---------------------------------------------------------------------------
# The per-agent rule — Sybil pressure and self-inflation
# ---------------------------------------------------------------------------


def test_one_agent_cannot_probe_the_same_target_twice_in_a_cycle(
    clock: FakeClock,
) -> None:
    """Repeat measurements from one agent would inflate its weight in consensus."""
    rl = limiter(clock, max_probes_per_window=100, cycle_seconds=1_000.0)

    assert rl.acquire("t1", "greedy").allowed
    for _ in range(20):
        assert rl.acquire("t1", "greedy").reason is Denial.AGENT_ALREADY_PROBED

    assert rl.remaining("t1") == 99, "denied repeats must not consume budget"


def test_an_agent_may_probe_the_same_target_again_next_cycle(clock: FakeClock) -> None:
    """Continuity is the whole product — the rule limits rate, not participation."""
    rl = limiter(
        clock, max_probes_per_window=100, window_seconds=10.0, cycle_seconds=1_000.0
    )

    assert rl.acquire("t1", "steady").allowed
    clock.advance(1_000.0)
    assert rl.acquire("t1", "steady").allowed


def test_per_agent_rule_is_scoped_to_one_target(clock: FakeClock) -> None:
    """Probing target A must not lock an agent out of target B."""
    rl = limiter(clock, max_probes_per_window=100)

    assert rl.acquire("t1", "a").allowed
    assert rl.acquire("t2", "a").allowed


def test_sybil_agents_still_cannot_exceed_the_global_ceiling(clock: FakeClock) -> None:
    """The per-agent rule is trivially defeated by minting new ids. That is fine.

    Identity is free and therefore worthless here; the global ceiling is what
    actually protects the target, and it does not care about identity at all.
    Location weighting is handled elsewhere, by the beacon callback.
    """
    rl = limiter(clock, max_probes_per_window=20)

    granted = sum(1 for i in range(5_000) if rl.acquire("t1", f"sybil-{i}").allowed)

    assert granted == 20


# ---------------------------------------------------------------------------
# check() vs acquire()
# ---------------------------------------------------------------------------


def test_check_does_not_consume_budget(clock: FakeClock) -> None:
    rl = limiter(clock, max_probes_per_window=3)

    for _ in range(100):
        assert rl.check("t1", "a").allowed

    assert rl.remaining("t1") == 3


def test_check_agrees_with_acquire(clock: FakeClock) -> None:
    """A pre-flight `check` must never promise something `acquire` then refuses."""
    rl = limiter(clock, max_probes_per_window=4)

    for i in range(10):
        agent = f"agent-{i}"
        predicted = rl.check("t1", agent)
        actual = rl.acquire("t1", agent)
        assert predicted.allowed == actual.allowed
        assert predicted.reason == actual.reason


def test_decision_denied_is_the_inverse_of_allowed() -> None:
    assert Decision(allowed=True).denied is False
    assert Decision(allowed=False, reason=Denial.GLOBAL_CEILING).denied is True


def test_denial_reasons_serialise_as_plain_strings() -> None:
    """These values go out over the wire in error bodies; they must be stable."""
    assert Denial.GLOBAL_CEILING.value == "global_ceiling"
    assert Denial.AGENT_ALREADY_PROBED.value == "agent_already_probed"
