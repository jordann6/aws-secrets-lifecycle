"""Rotation readiness scoring.

Readiness answers: how safely could this secret be rotated today?
Higher is safer. Combines rotation configuration, consumer count,
consumer identifiability, and age."""


def readiness_score(record, consumer_map):
    score = 50
    consumers = consumer_map.get("consumers", [])
    count = len(consumers)

    if record.get("rotation_enabled"):
        score += 25

    if count == 0:
        # No observed consumers: rotation carries no outage risk.
        score += 15
    elif count <= 3:
        score += 5
    else:
        score -= 10

    if count > 0:
        identified = all(c.get("principal_arn") for c in consumers)
        score += 10 if identified else -10

    age = int(record.get("age_days", 0))
    if age > 365:
        score -= 15
    elif age > 180:
        score -= 5

    return max(0, min(100, score))


def risk_tier(score):
    if score <= 55:
        return "high"
    if score < 75:
        return "medium"
    return "low"
