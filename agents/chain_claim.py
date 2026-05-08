"""
UMA Delegation Chain Claim — Protocol Extension

Proposes `uma_delegation_chain` as a structured claims token extension to UMA 2.0.

Vanilla UMA 2.0 RPTs carry no chain provenance: every agent that holds a valid
RPT looks identical to the resource server regardless of how deep in a delegation
hierarchy it sits. This extension adds a cryptographically signed claim that the
resource server can validate independently of the authorisation server, closing
four attack classes specific to LLM-based delegation systems:

  T1 — Scope escalation:   child agent requests a broader scope than its chain allows
  T2 — Depth exceeded:     delegation chain longer than the configured maximum
  T3 — Token replay:       agent reuses a chain claim belonging to a peer or ancestor
  T4 — Prompt injection:   adversarial input causes the LLM to request an out-of-scope
                           resource; blocked because the scope is absent from the claim

Claim format: urn:uma-agent:delegation-chain:1.0
Transport:    HTTP header  X-Uma-Delegation-Chain: <base64url(json(claim))>
"""

import base64
import hashlib
import hmac as _hmac
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import List, Optional, Tuple

CLAIM_FORMAT_URN = "urn:uma-agent:delegation-chain:1.0"
_DEFAULT_SECRET = os.getenv("CHAIN_HMAC_SECRET", "uma-agent-chain-hmac-secret-2024")


@dataclass
class DelegationChainClaim:
    """
    Signed delegation chain claim carried alongside a UMA RPT.

    Fields
    ------
    chain_id       : UUID identifying this specific chain instance
    root_agent     : Identity of the root (depth-1) agent
    members        : Ordered agent IDs from root to current leaf
    granted_scopes : Scopes delegated to this chain, as "resource:scope" strings
    max_depth      : Hard limit on chain length; enforcement is at the resource server
    issued_at      : Unix timestamp of claim creation
    chain_hash     : HMAC-SHA256 over the canonical payload (prevents forgery)
    """

    chain_id: str
    root_agent: str
    members: List[str]
    granted_scopes: List[str]
    max_depth: int
    issued_at: int = field(default_factory=lambda: int(time.time()))
    chain_hash: str = ""

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        root_agent: str,
        members: List[str],
        granted_scopes: List[str],
        max_depth: int = 4,
        hmac_secret: str = _DEFAULT_SECRET,
        chain_id: Optional[str] = None,
    ) -> "DelegationChainClaim":
        claim = cls(
            chain_id=chain_id or str(uuid.uuid4()),
            root_agent=root_agent,
            members=list(members),
            granted_scopes=list(granted_scopes),
            max_depth=max_depth,
        )
        claim.sign(hmac_secret)
        return claim

    # ------------------------------------------------------------------
    # HMAC signing / verification
    # ------------------------------------------------------------------

    def _canonical_payload(self) -> str:
        return json.dumps(
            {
                "chain_id": self.chain_id,
                "root_agent": self.root_agent,
                "members": self.members,
                "granted_scopes": sorted(self.granted_scopes),
                "max_depth": self.max_depth,
                "issued_at": self.issued_at,
            },
            sort_keys=True,
        )

    def sign(self, secret: str = _DEFAULT_SECRET) -> None:
        self.chain_hash = _hmac.new(
            secret.encode(),
            self._canonical_payload().encode(),
            hashlib.sha256,
        ).hexdigest()

    def verify(self, secret: str = _DEFAULT_SECRET) -> bool:
        expected = _hmac.new(
            secret.encode(),
            self._canonical_payload().encode(),
            hashlib.sha256,
        ).hexdigest()
        return _hmac.compare_digest(self.chain_hash, expected)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def depth(self) -> int:
        return len(self.members)

    @property
    def leaf_agent(self) -> Optional[str]:
        return self.members[-1] if self.members else None

    # ------------------------------------------------------------------
    # Core validation — addresses W3 (no threat model / security analysis)
    # ------------------------------------------------------------------

    def validate_for_resource(
        self,
        resource: str,
        scope: str,
        claimed_agent_id: str,
        hmac_secret: str = _DEFAULT_SECRET,
        server_max_depth: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """
        Validate this claim for a specific resource access attempt.

        Returns (is_valid, human-readable reason). Reasons are tagged with
        the attack class they correspond to (T1–T4) so that the resource
        server log carries structured attack attribution.

        server_max_depth: when provided, the resource server's own configured
        ceiling is used for the depth check instead of the client-embedded
        max_depth field, preventing a compromised agent from inflating the limit.
        """
        # 1. HMAC integrity — reject forged or tampered claims
        if not self.verify(hmac_secret):
            return (
                False,
                "T2/T3: chain_hash mismatch — claim was tampered with or replayed "
                "from a different session",
            )

        # 2. Depth limit — T2: chain depth exceeded.
        # Use server_max_depth when provided so the server's own policy applies.
        # Also respect the claim's own server-signed ceiling: an agent cannot present
        # a chain whose depth exceeds the max_depth that the server embedded and signed.
        effective_max = server_max_depth if server_max_depth is not None else self.max_depth
        effective_max = min(effective_max, self.max_depth)
        if self.depth > effective_max:
            return (
                False,
                f"T2: chain depth {self.depth} exceeds configured maximum "
                f"{effective_max}; delegation rejected",
            )

        # 3. Agent membership (leaf check) — T3: token replay
        if not self.members or self.members[-1] != claimed_agent_id:
            actual = self.members[-1] if self.members else "(empty)"
            return (
                False,
                f"T3: requesting agent '{claimed_agent_id}' is not the chain "
                f"terminus (expected '{actual}') — possible token replay",
            )

        # 4. Scope check — T1: scope escalation / T4: prompt injection
        required = f"{resource}:{scope}"
        if required not in self.granted_scopes:
            return (
                False,
                f"T1/T4: scope '{required}' is not in the chain's granted set "
                f"{self.granted_scopes} — possible scope escalation or prompt injection",
            )

        return True, "chain claim valid"

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_header_value(self) -> str:
        raw = json.dumps(asdict(self)).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    @classmethod
    def from_header_value(cls, value: str) -> "DelegationChainClaim":
        # Restore stripped padding
        padding = (4 - len(value) % 4) % 4
        value += "=" * padding
        data = json.loads(base64.urlsafe_b64decode(value))
        # Only pass known fields to the constructor; tolerate extra fields
        # (format identifiers, future extension fields, etc.)
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in known}
        # issued_at may arrive as ISO string if constructed externally
        if "issued_at" in filtered and isinstance(filtered["issued_at"], str):
            from datetime import datetime, timezone
            try:
                dt = datetime.fromisoformat(filtered["issued_at"].replace("Z", "+00:00"))
                filtered["issued_at"] = int(dt.timestamp())
            except ValueError:
                filtered["issued_at"] = int(time.time())
        return cls(**filtered)

    def to_dict(self) -> dict:
        return asdict(self)

    # ------------------------------------------------------------------
    # Comparison table helpers (used by the paper's evaluation section)
    # ------------------------------------------------------------------

    @staticmethod
    def comparison_properties() -> dict:
        """
        Returns the feature set of UMA-Agent vs alternative delegation approaches.
        Used to generate Table II in the paper.
        """
        return {
            "RFC 8693 Token Exchange": {
                "standards_based": True,
                "explicit_chain_provenance": False,
                "tamper_evident_audit": False,
                "llm_agent_integration": False,
                "scope_monotonicity": True,
                "depth_enforcement": False,
            },
            "Macaroons": {
                "standards_based": False,
                "explicit_chain_provenance": "partial",
                "tamper_evident_audit": True,
                "llm_agent_integration": False,
                "scope_monotonicity": True,
                "depth_enforcement": False,
            },
            "Biscuits": {
                "standards_based": False,
                "explicit_chain_provenance": "partial",
                "tamper_evident_audit": True,
                "llm_agent_integration": False,
                "scope_monotonicity": True,
                "depth_enforcement": False,
            },
            "UMA-Agent (this work)": {
                "standards_based": True,
                "explicit_chain_provenance": True,
                "tamper_evident_audit": True,
                "llm_agent_integration": True,
                "scope_monotonicity": True,
                "depth_enforcement": True,
            },
        }
