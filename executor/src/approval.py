"""Approval guardrails for the rotation executor.

The rest of this stack is read-only by design: every scanner, analyzer,
and reporter role carries an explicit deny on secret material. The
executor is the one component allowed to touch values, so it never acts
on its own judgment. It acts only when three independent controls all
agree that a specific secret was approved for rotation:

  1. The caller passed approve=true in the invoke event.
  2. The analyzer already produced a runbook for this secret whose
     confidence clears the bar (high, or medium when allow_medium is
     set). Low-confidence and fallback runbooks are refused unless the
     caller explicitly forces, because those are exactly the secrets
     whose consumers we could not identify.
  3. The secret itself carries the opt-in tag, set by an operator on the
     one secret they mean to rotate. A blanket invoke cannot rotate a
     secret nobody tagged.

Every function here is pure so the decision is unit-testable without AWS.
"""

APPROVED_TAG_KEY = "secops:rotation-approved"
APPROVED_TAG_VALUE = "true"

_ACCEPTED_CONFIDENCE = {"high"}
_ACCEPTED_CONFIDENCE_MEDIUM = {"high", "medium"}


def tags_to_dict(tag_list):
    """Normalize the Secrets Manager DescribeSecret tag list to a dict."""
    return {t.get("Key"): t.get("Value") for t in (tag_list or [])}


def opt_in_tagged(tags):
    """True when an operator tagged this specific secret for rotation."""
    return tags.get(APPROVED_TAG_KEY) == APPROVED_TAG_VALUE


def evaluate(event, analysis, tags, *, allow_medium=False, force=False):
    """Decide whether rotation may proceed.

    Returns (approved: bool, reasons: list[str]). reasons always lists
    every failed control, so an operator sees all blockers at once rather
    than fixing them one invoke at a time. force bypasses the runbook
    confidence and generator checks only; it never bypasses the explicit
    approve flag or the opt-in tag.
    """
    reasons = []

    if not event.get("approve") is True:
        reasons.append("event.approve is not true; rotation is opt-in")

    if not opt_in_tagged(tags):
        reasons.append(
            f"secret is missing the opt-in tag {APPROVED_TAG_KEY}="
            f"{APPROVED_TAG_VALUE}")

    runbook = (analysis or {}).get("runbook")
    if not analysis:
        reasons.append("no analyzer record found for this secret and scan")
    elif not runbook:
        reasons.append("analyzer produced no runbook for this secret")
    elif not force:
        accepted = _ACCEPTED_CONFIDENCE_MEDIUM if allow_medium \
            else _ACCEPTED_CONFIDENCE
        confidence = runbook.get("confidence")
        if confidence not in accepted:
            reasons.append(
                f"runbook confidence {confidence!r} is below the bar "
                f"({sorted(accepted)}); pass allow_medium or force")
        if runbook.get("generator") == "fallback":
            reasons.append(
                "runbook is a rule-based fallback, not a verified plan; "
                "pass force to rotate anyway")

    return (not reasons, reasons)
