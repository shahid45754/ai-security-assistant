
import asyncio
from app.core.utils import sanitize_text, sanitize_for_json

from app.models.executive_summary import ExecutiveSummary
from app.models.verdict import SOCVerdict

# How long to wait for the local model before giving up and using the
# deterministic fallback instead.
AI_CALL_TIMEOUT_SECONDS = 90


def fallback_executive_summary(campaigns, stats) -> ExecutiveSummary:
    """Deterministic, code-only executive summary -- no LLM call."""
    severity_distribution = stats.get("severity_distribution", {})
    total_incidents = stats.get("total_incidents", len(campaigns))
    total_campaigns = stats.get("total_campaigns", len(campaigns))

    severity_lookup = {str(k).lower(): v for k, v in severity_distribution.items()}
    if severity_lookup.get("critical", 0) > 0:
        risk_level = "Critical"
    elif severity_lookup.get("high", 0) > 0:
        risk_level = "High"
    elif severity_lookup.get("medium", 0) > 0:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    attack_types = sorted({c.attack_type for c in campaigns})
    avg_confidence = (
        sum(c.confidence for c in campaigns) / len(campaigns) if campaigns else 0.0
    )

    all_recommendations = []
    for c in campaigns:
        for rec in c.recommendations:
            if rec not in all_recommendations:
                all_recommendations.append(rec)

    return ExecutiveSummary(
        summary=(
            f"Analysis of {total_incidents} incident(s) correlated into "
            f"{total_campaigns} campaign(s) involving {', '.join(attack_types) or 'no identified'} "
            f"attack activity. Overall severity assessed as {risk_level}."
        ),
        business_risk=(
            f"{risk_level} risk to business operations based on observed attack severity "
            f"and confidence levels across all correlated campaigns."
        ),
        priority_actions=all_recommendations[:5] or ["Review incident details manually."],
        overall_confidence=round(avg_confidence, 2),
    )


def fallback_soc_verdict(campaigns, stats) -> SOCVerdict:
    """Deterministic, code-only SOC verdict -- no LLM call."""
    severity_distribution = stats.get("severity_distribution", {})
    severity_lookup = {str(k).lower(): v for k, v in severity_distribution.items()}

    if severity_lookup.get("critical", 0) > 0:
        threat_level, priority = "Critical", "P1"
    elif severity_lookup.get("high", 0) > 0:
        threat_level, priority = "High", "P2"
    elif severity_lookup.get("medium", 0) > 0:
        threat_level, priority = "Medium", "P3"
    else:
        threat_level, priority = "Low", "P4"

    avg_confidence = (
        sum(c.confidence for c in campaigns) / len(campaigns) if campaigns else 0.0
    )
    unique_ips = sorted({c.source_ip for c in campaigns if c.source_ip})

    next_actions = ["Notify Incident Response Team", "Review historical logs"]
    if unique_ips:
        next_actions.insert(0, "Block malicious IPs")
    if threat_level in ("Critical", "High"):
        next_actions.append("Investigate affected hosts")
        next_actions.append("Enable additional monitoring")

    return SOCVerdict(
        verdict=(
            f"{len(campaigns)} correlated campaign(s) detected with overall "
            f"{threat_level.lower()} severity. Immediate triage recommended."
        ),
        threat_level=threat_level,
        priority=priority,
        confidence=round(avg_confidence, 2),
        next_action=next_actions,
    )


async def run_agent_with_fallback(coro, fallback_value, label: str):
    """Run an AI agent call with a hard timeout; on timeout or any error,
    fall back to a deterministic value instead of crashing the whole run."""
    try:
        # Sanitize the coroutine if it's an awaitable with a prompt
        if hasattr(coro, '__await__'):
            # The coroutine will be awaited, but we can't easily sanitize it here
            # The sanitization should happen in the agent itself
            pass
        
        result = await asyncio.wait_for(coro, timeout=AI_CALL_TIMEOUT_SECONDS)
        
        # Sanitize the result output if it has an 'output' attribute
        if hasattr(result, 'output') and isinstance(result.output, str):
            result.output = sanitize_text(result.output)
        
        return result, True
    except asyncio.TimeoutError:
        print(f"\n[FALLBACK] {label} did not respond within {AI_CALL_TIMEOUT_SECONDS}s -- using deterministic fallback.")
        return fallback_value, False
    except Exception as error:
        print(f"\n[FALLBACK] {label} failed ({type(error).__name__}: {error}) -- using deterministic fallback.")
        return fallback_value, False


def sanitize_prompt(prompt: str) -> str:
    """Sanitize prompt before sending to AI."""
    if not prompt:
        return prompt
    return sanitize_text(prompt)


def sanitize_output(data):
    """Sanitize output data for JSON serialization."""
    return sanitize_for_json(data)
