"""
TIRtcp Governance & Authorization Gate.
Enforces explicit authorization flags (--authorized + valid --engagement-id) before
permitting any runtime or post-logout memory hygiene checks.
"""

from __future__ import annotations

import getpass
import re
from dataclasses import dataclass
from typing import Optional, Tuple

from analyzer.core.schema import AuthorizationContext

INVALID_ENGAGEMENT_IDS = {
    "",
    "unassigned",
    "unassigned-engagement",
    "none",
    "null",
    "test",
    "default",
    "todo",
}

ENGAGEMENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reason: str
    context: AuthorizationContext


def evaluate_authorization_gate(
    authorized_flag: bool,
    engagement_id: Optional[str],
    operator: Optional[str] = None,
) -> GateDecision:
    """
    Validate that both --authorized and a properly formatted --engagement-id
    are present before executing gated runtime modules.
    """
    resolved_operator = operator or _safe_current_user()
    clean_eng_id = (engagement_id or "").strip()

    ctx = AuthorizationContext(
        gated=True,
        authorized_flag=bool(authorized_flag),
        engagement_id=clean_eng_id or None,
        operator=resolved_operator,
    )

    if not authorized_flag:
        return GateDecision(
            allowed=False,
            reason=(
                "Runtime/memory hygiene module blocked: '--authorized' flag was not supplied. "
                "Explicit written authorization is required."
            ),
            context=ctx,
        )

    if not clean_eng_id or clean_eng_id.lower() in INVALID_ENGAGEMENT_IDS:
        return GateDecision(
            allowed=False,
            reason=(
                "Runtime/memory hygiene module blocked: a valid '--engagement-id' "
                "(e.g., ENG-2026-042) must be provided alongside '--authorized'."
            ),
            context=ctx,
        )

    if not ENGAGEMENT_ID_PATTERN.match(clean_eng_id):
        return GateDecision(
            allowed=False,
            reason=(
                f"Runtime/memory hygiene module blocked: engagement ID '{clean_eng_id}' "
                "does not match required format (3-64 alphanumeric/hyphen/underscore characters)."
            ),
            context=ctx,
        )

    return GateDecision(
        allowed=True,
        reason=f"Authorized for engagement '{clean_eng_id}' by operator '{resolved_operator}'.",
        context=ctx,
    )


def _safe_current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown-operator"