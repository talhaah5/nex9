"""Ed25519 manifest signing.

Why manifests are signed at all: an agent that can be handed a forged manifest
can be told to fetch anything, from anywhere, at any rate. That is the
difference between a measurement network and a botnet, and it is not a
difference we are willing to leave to TLS alone. Signing means a contributing
agent can pin our public key once and thereafter verify for itself that a target
list really came from us — including when it is relayed, cached, or served
through infrastructure neither of us controls.

The canonical encoding must be stable forever. If it changes, every previously
published manifest becomes unverifiable and every deployed client breaks.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

SIGNATURE_PREFIX = "ed25519:"

# Excluded from the signed payload: a signature cannot cover itself.
_UNSIGNED_FIELDS = frozenset({"signature"})


class SignatureError(Exception):
    """Raised when a manifest signature is absent, malformed, or wrong."""


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Deterministic byte encoding of a manifest for signing.

    Sorted keys, no insignificant whitespace, UTF-8, no ASCII escaping. Two
    structurally equal manifests must always produce identical bytes on every
    platform and Python version, or signatures will fail unpredictably.
    """
    to_sign = {k: v for k, v in payload.items() if k not in _UNSIGNED_FIELDS}
    return json.dumps(
        to_sign,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def sign_payload(payload: dict[str, Any], private_key: Ed25519PrivateKey) -> str:
    """Return the `ed25519:<base64>` signature for a manifest payload."""
    raw = private_key.sign(canonical_bytes(payload))
    return SIGNATURE_PREFIX + base64.b64encode(raw).decode("ascii")


def verify_payload(
    payload: dict[str, Any], signature: str, public_key: Ed25519PublicKey
) -> None:
    """Verify a manifest signature, raising `SignatureError` if it does not hold.

    Deliberately raises rather than returning False. A caller that ignores a
    boolean return here would accept forged manifests, and that failure would be
    silent — exactly the class of bug this project cannot afford.
    """
    if not signature.startswith(SIGNATURE_PREFIX):
        raise SignatureError(
            f"signature must start with {SIGNATURE_PREFIX!r}; refusing to guess"
        )

    encoded = signature[len(SIGNATURE_PREFIX) :]
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise SignatureError("signature is not valid base64") from exc

    try:
        public_key.verify(raw, canonical_bytes(payload))
    except InvalidSignature as exc:
        raise SignatureError("signature does not match payload") from exc


def public_key_to_pem(public_key: Ed25519PublicKey) -> bytes:
    """Serialise the public key for publication at the well-known URL."""
    return public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def load_public_key_pem(data: bytes) -> Ed25519PublicKey:
    """Load a published public key, rejecting anything that isn't Ed25519."""
    key = load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise SignatureError(f"expected an Ed25519 public key, got {type(key).__name__}")
    return key
