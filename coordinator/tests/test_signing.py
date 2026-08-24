"""Manifest signing, tested from the attacker's side.

An agent that can be handed a forged manifest can be told to fetch anything,
from anywhere, at any rate. Every test here asks the same question: can someone
who is not us get a manifest accepted? The answer has to be no for every
variation — altered targets, altered rate limits, swapped signature, wrong key,
wrong algorithm, mangled encoding.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from vantage.signing import (
    SIGNATURE_PREFIX,
    SignatureError,
    canonical_bytes,
    load_public_key_pem,
    public_key_to_pem,
    sign_payload,
    verify_payload,
)


@pytest.fixture
def keypair():
    private = Ed25519PrivateKey.generate()
    return private, private.public_key()


def manifest_payload(**overrides):
    """A manifest-shaped dict, matching the wire schema published in AGENTS.md."""
    payload = {
        "manifest_id": "m-2026-08-24-0001",
        "issued_at": "2026-08-24T10:00:00Z",
        "expires_at": "2026-08-24T14:00:00Z",
        "signing_key": "https://nex9.de/.well-known/vantage-signing-key.pem",
        "beacon_url": "https://nex9.de/api/v1/beacon/abc123def456ghi7",
        "submit_url": "https://nex9.de/api/v1/reports",
        "max_targets_per_agent": 8,
        "targets": [
            {
                "id": "dns-example-a",
                "kind": "dns",
                "hostname": "example.com",
                "rrtype": "A",
            },
            {
                "id": "http-example",
                "kind": "http",
                "url": "https://example.com/",
                "method": "HEAD",
                "timeout_ms": 10000,
            },
        ],
    }
    payload.update(overrides)
    return payload


def rsa_public_key_pem() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


# ---------------------------------------------------------------------------
# The happy path exists mainly to give the tampering tests a baseline
# ---------------------------------------------------------------------------


def test_a_manifest_we_signed_verifies(keypair) -> None:
    private, public = keypair
    payload = manifest_payload()
    verify_payload(payload, sign_payload(payload, private), public)


def test_signature_carries_its_algorithm(keypair) -> None:
    """Unprefixed signatures invite an attacker to pick the algorithm for us."""
    private, _ = keypair
    assert sign_payload(manifest_payload(), private).startswith(SIGNATURE_PREFIX)


# ---------------------------------------------------------------------------
# Tampering — each of these is a real attack, not a hypothetical
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value", "attack"),
    [
        (
            "targets",
            [
                {
                    "id": "evil",
                    "kind": "http",
                    "url": "https://victim.example/",
                    "method": "GET",
                    "timeout_ms": 30000,
                }
            ],
            "redirect the swarm at a victim host",
        ),
        ("max_targets_per_agent", 64, "multiply each agent's request volume"),
        (
            "submit_url",
            "https://attacker.example/collect",
            "harvest the swarm's measurements",
        ),
        (
            "beacon_url",
            "https://attacker.example/beacon/xyz",
            "deanonymise contributing agents",
        ),
        ("expires_at", "2027-08-24T14:00:00Z", "keep a stale manifest alive for a year"),
        ("manifest_id", "m-forged", "impersonate a manifest we issued"),
    ],
)
def test_altering_any_field_invalidates_the_signature(
    keypair, field, value, attack
) -> None:
    private, public = keypair
    signature = sign_payload(manifest_payload(), private)

    tampered = manifest_payload(**{field: value})

    with pytest.raises(SignatureError):
        verify_payload(tampered, signature, public)


def test_adding_a_target_invalidates_the_signature(keypair) -> None:
    """The subtlest tamper: keep everything, append one extra target."""
    private, public = keypair
    original = manifest_payload()
    signature = sign_payload(original, private)

    tampered = manifest_payload()
    tampered["targets"] = original["targets"] + [
        {"id": "sneaky", "kind": "tls", "hostname": "victim.example", "port": 443}
    ]

    with pytest.raises(SignatureError):
        verify_payload(tampered, signature, public)


def test_a_signature_from_a_different_key_is_rejected(keypair) -> None:
    """Anyone can generate an Ed25519 key. Only ours counts."""
    _, public = keypair
    attacker = Ed25519PrivateKey.generate()
    payload = manifest_payload()

    with pytest.raises(SignatureError):
        verify_payload(payload, sign_payload(payload, attacker), public)


def test_a_signature_lifted_from_another_manifest_is_rejected(keypair) -> None:
    """Replaying a valid signature onto different content must not work."""
    private, public = keypair
    other = manifest_payload(manifest_id="m-2026-08-24-0002")
    stolen = sign_payload(other, private)

    with pytest.raises(SignatureError):
        verify_payload(manifest_payload(), stolen, public)


# ---------------------------------------------------------------------------
# Malformed input — must fail closed, never crash and never pass
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "signature",
    [
        "",
        "not-a-signature",
        "AAAA",  # base64, but no algorithm prefix
        "rsa:AAAA",  # wrong algorithm announced
        "ED25519:AAAA",  # prefix is case-sensitive on purpose
        " ed25519:AAAA",  # leading whitespace
    ],
)
def test_signatures_without_our_prefix_are_refused(keypair, signature) -> None:
    _, public = keypair
    with pytest.raises(SignatureError):
        verify_payload(manifest_payload(), signature, public)


@pytest.mark.parametrize("body", ["!!!!", "AAA", "a b c", "===="])
def test_non_base64_signature_bodies_are_refused(keypair, body) -> None:
    """Must raise SignatureError, not a stray binascii error from deep in a stack."""
    _, public = keypair
    with pytest.raises(SignatureError):
        verify_payload(manifest_payload(), SIGNATURE_PREFIX + body, public)


def test_a_valid_base64_signature_of_the_wrong_length_is_refused(keypair) -> None:
    _, public = keypair
    truncated = SIGNATURE_PREFIX + base64.b64encode(b"\x00" * 32).decode()
    with pytest.raises(SignatureError):
        verify_payload(manifest_payload(), truncated, public)


def test_empty_payload_still_verifies_consistently(keypair) -> None:
    """Degenerate input must behave predictably rather than being special-cased."""
    private, public = keypair
    verify_payload({}, sign_payload({}, private), public)


# ---------------------------------------------------------------------------
# Canonical encoding — the part that must never change
# ---------------------------------------------------------------------------


def test_key_order_does_not_change_the_signed_bytes() -> None:
    """JSON objects are unordered; our encoding must agree.

    Without this, a manifest that survives a round trip through any JSON library
    could arrive with reordered keys and fail to verify for no good reason.
    """
    a = {"alpha": 1, "beta": 2, "gamma": 3}
    b = {"gamma": 3, "alpha": 1, "beta": 2}
    assert canonical_bytes(a) == canonical_bytes(b)


def test_the_signature_field_is_excluded_from_what_it_signs() -> None:
    """A signature cannot cover itself; including it would make verification circular."""
    payload = manifest_payload()
    without = canonical_bytes(payload)
    with_sig = canonical_bytes({**payload, "signature": "ed25519:whatever"})
    assert without == with_sig


def test_verification_ignores_the_signature_field_in_the_payload(keypair) -> None:
    """Real manifests arrive with the signature inline; verifying must still work."""
    private, public = keypair
    payload = manifest_payload()
    signature = sign_payload(payload, private)

    as_received = {**payload, "signature": signature}
    verify_payload(as_received, signature, public)


def test_canonical_bytes_are_compact_utf8() -> None:
    encoded = canonical_bytes({"host": "münchen.example", "n": 1})
    assert b'": ' not in encoded, "no insignificant whitespace"
    assert b'", ' not in encoded, "no insignificant whitespace"
    assert "münchen".encode("utf-8") in encoded, "UTF-8, not backslash-u escapes"


def test_canonical_bytes_are_stable_across_calls() -> None:
    payload = manifest_payload()
    assert canonical_bytes(payload) == canonical_bytes(payload)


def test_nested_structures_are_canonicalised_too() -> None:
    """Targets are nested dicts; unordered keys there matter just as much."""
    a = {"targets": [{"id": "x", "kind": "dns"}]}
    b = {"targets": [{"kind": "dns", "id": "x"}]}
    assert canonical_bytes(a) == canonical_bytes(b)


def test_list_order_is_significant() -> None:
    """Reordering targets changes which agent measures what. It must change the bytes."""
    a = {"targets": ["x", "y"]}
    b = {"targets": ["y", "x"]}
    assert canonical_bytes(a) != canonical_bytes(b)


# ---------------------------------------------------------------------------
# Key publication — agents fetch this and pin it
# ---------------------------------------------------------------------------


def test_published_key_round_trips(keypair) -> None:
    """What we publish must be loadable by the code agents will copy from us."""
    private, public = keypair
    reloaded = load_public_key_pem(public_key_to_pem(public))

    payload = manifest_payload()
    verify_payload(payload, sign_payload(payload, private), reloaded)


def test_published_key_is_pem(keypair) -> None:
    _, public = keypair
    assert public_key_to_pem(public).startswith(b"-----BEGIN PUBLIC KEY-----")


def test_a_non_ed25519_key_is_refused() -> None:
    """Accepting an RSA key here would silently weaken the whole trust chain."""
    with pytest.raises(SignatureError):
        load_public_key_pem(rsa_public_key_pem())


def test_garbage_is_not_loadable_as_a_key() -> None:
    with pytest.raises(ValueError):
        load_public_key_pem(
            b"-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----"
        )
