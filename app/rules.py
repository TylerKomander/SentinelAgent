import yaml

from .config import CONFIG_DIR


def _load():
    f = CONFIG_DIR / "rules.yaml"
    if not f.exists():
        return []
    doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
    return doc.get("rules") or []


def match(alert):
    """First rule whose `match` string appears in the alert summary, or None.
    Matching is case-insensitive so 'C2' in the file catches 'c2 beacon'."""
    summary = (alert.summary or "").lower()
    for rule in _load():
        needle = str(rule.get("match", "")).strip().lower()
        if needle and needle in summary:
            return rule
    return None


def auto_remediate_allowed(alert):
    """(allowed, reason). A rule must exist AND opt in — silence is never consent."""
    rule = match(alert)
    if not rule:
        return False, "no matching rule in config/rules.yaml"
    if not rule.get("auto_remediate"):
        return False, f"rule '{rule.get('match')}' is suggest-only"
    return True, f"rule '{rule.get('match')}'"
