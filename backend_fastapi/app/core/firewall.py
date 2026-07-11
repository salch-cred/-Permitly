import re
from typing import Any

RULES = [
    {"id": "ignore_instructions", "weight": 45, "pattern": re.compile(r"ignore\s+(all\s+)?(previous|prior|system)\s+instructions?", re.I), "label": "Instruction override attempt"},
    {"id": "secret_exfiltration", "weight": 55, "pattern": re.compile(r"(reveal|print|send|expose|dump).{0,30}(api\s*key|private\s*key|password|secret|token|credential)", re.I), "label": "Credential exfiltration attempt"},
    {"id": "system_prompt", "weight": 35, "pattern": re.compile(r"(system\s+prompt|developer\s+message|hidden\s+instructions)", re.I), "label": "Hidden prompt access attempt"},
    {"id": "privilege_escalation", "weight": 50, "pattern": re.compile(r"(disable|bypass|override|remove).{0,25}(guardrail|policy|approval|permission|security)", re.I), "label": "Policy bypass attempt"},
    {"id": "data_exfiltration", "weight": 45, "pattern": re.compile(r"(upload|post|send).{0,30}(database|customer\s+data|source\s+code|environment\s+variables)", re.I), "label": "Sensitive data transfer attempt"},
    {"id": "shell_injection", "weight": 40, "pattern": re.compile(r"(;|&&|\|\|)\s*(curl|wget|bash|sh|nc)\b", re.I), "label": "Shell injection pattern"},
    {"id": "encoded_payload", "weight": 20, "pattern": re.compile(r"(base64|atob\(|fromcharcode|data:text/html)", re.I), "label": "Encoded payload pattern"},
]


def _flatten(value: Any, seen: set | None = None) -> str:
    if seen is None:
        seen = set()
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if not isinstance(value, (dict, list)) or id(value) in seen:
        return ""
    seen.add(id(value))
    if isinstance(value, list):
        return " ".join(_flatten(v, seen) for v in value)
    return " ".join(f"{k} {_flatten(v, seen)}" for k, v in value.items())


def scan_for_prompt_injection(input_value: Any) -> dict[str, Any]:
    text = _flatten(input_value)[:100_000]
    matches = []
    score = 0
    for rule in RULES:
        if rule["pattern"].search(text):
            matches.append({"id": rule["id"], "weight": rule["weight"], "label": rule["label"]})
            score += rule["weight"]
    score = min(100, score)
    if score >= 70:
        level = "critical"
        recommendation = "block"
    elif score >= 45:
        level = "high"
        recommendation = "escalate"
    elif score >= 20:
        level = "medium"
        recommendation = "review"
    else:
        level = "low"
        recommendation = "allow"
    return {
        "safe": score < 45,
        "score": score,
        "level": level,
        "matches": matches,
        "recommendation": recommendation,
    }


def get_firewall_rules() -> list[dict[str, Any]]:
    return [{"id": r["id"], "weight": r["weight"], "label": r["label"]} for r in RULES]
