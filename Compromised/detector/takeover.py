"""Compromised-account / business-email-compromise detection.

Assesses whether an email account has already been taken over by combining:

  * analyst-observed takeover indicators (rules, sessions, recovery changes),
  * technical signals from recent mail sent by the account (reply-to abuse,
    unexpected auto-forwarding, external fan-out),
  * breach exposure (optional — from the HIBP password check).

Returns a 0–100 takeover-likelihood score with explanations and actions.
"""

from __future__ import annotations

from .engine import Finding

# indicator key -> (weight, severity, title, detail, remediation)
INDICATORS: dict[str, tuple[int, str, str, str, str]] = {
    "forwarding_rule": (
        22, "high", "Suspicious auto-forwarding rule",
        "Mail is silently copied to an external address — attackers use this to "
        "monitor replies without keeping the session open.",
        "Delete the rule, then review inbox rules for anything you did not create."),
    "unknown_session": (
        16, "high", "Unfamiliar active session",
        "A signed-in device or browser session does not belong to the user.",
        "Sign out all sessions and rotate the password from a clean device."),
    "recovery_changed": (
        18, "high", "Recovery email/phone changed",
        "The recovery options were altered — a classic lockout move after takeover.",
        "Restore the correct recovery options and review recent security changes."),
    "password_reset_external": (
        20, "high", "Password reset initiated elsewhere",
        "A reset from an unexpected location or by a third party.",
        "Reset the password again, enable MFA, and check for new app passwords."),
    "mfa_disabled": (
        18, "high", "MFA disabled or bypassed",
        "Multi-factor protection was turned off or an MFA method was removed.",
        "Re-enable MFA immediately and audit authentication methods."),
    "sent_mail_not_mine": (
        20, "high", "Sent mail the user did not write",
        "Messages appear in Sent Items that the account owner never sent.",
        "Assume the mailbox is compromised: rotate credentials and check inbox rules."),
    "unusual_reply_to": (
        15, "high", "Outbound mail with foreign Reply-To",
        "Messages sent from the account carry a Reply-To pointing elsewhere, "
        "hijacking replies to third parties.",
        "Remove malicious rules, then warn recent correspondents."),
    "unexpected_client": (
        8, "medium", "Mail client / SMTP relay the user never used",
        "Authentication events show a client or relay not previously associated "
        "with this account.",
        "Revoke the app's access token or app password."),
    "delegated_access": (
        12, "medium", "Unknown delegated mailbox access",
        "Another account was granted delegate/send-as rights.",
        "Remove delegates you do not recognise."),
    "mailbox_deleted_rules": (
        10, "medium", "Mass deletion of inbox rules",
        "Rules were deleted and recreated — often covers tracks after planting a rule.",
        "Review rule history and restore trusted rules."),
    "breach_password": (
        14, "medium", "Password found in a breach",
        "The account password appears in known breach corpora, making takeover "
        "via credential stuffing likely.",
        "Change the password everywhere it was reused."),
    "external_forward_domain": (
        15, "high", "Forwarding to a look-alike domain",
        "Auto-forward targets a domain closely resembling the organisation's.",
        "Delete the rule and investigate mail sent to that domain."),
    "client_geo_mismatch": (
        12, "medium", "Sessions from inconsistent locations",
        "Authentication logs show distant locations within a short window.",
        "Force sign-out of all sessions and review account activity."),
}

ADVICE = [
    "Rotate the mailbox password from a device you trust and sign out every session.",
    "Review inbox rules — delete anything that forwards, auto-replies or moves mail unexpectedly.",
    "Check recovery email, phone numbers and MFA methods for tampering.",
    "Review Sent Items and deleted mail for correspondence the user never wrote.",
    "Warn recent counterparties if replies may have been intercepted.",
    "Check whether the address appears in breaches on the Account Exposure tab.",
]


def assess_takeover(payload: dict) -> dict:
    """payload: {indicators: [key,...], notes: str}"""
    requested = payload.get("indicators") or []
    if isinstance(requested, str):
        requested = [p.strip() for p in requested.split(",") if p.strip()]

    findings: list[Finding] = []
    for key in requested:
        spec = INDICATORS.get(key)
        if not spec:
            continue
        weight, severity, title, detail, remediation = spec
        findings.append(Finding(
            category="takeover", severity=severity, points=weight,
            title=title, detail=f"{detail} → {remediation}"))

    score = min(100, sum(f.points for f in findings))
    if score >= 75:
        verdict = "compromised"
    elif score >= 50:
        verdict = "likely-takeover"
    elif score >= 25:
        verdict = "at-risk"
    else:
        verdict = "no-signals"

    return {
        "kind": "takeover",
        "score": score,
        "verdict": verdict,
        "findings": [vars(f) for f in findings],
        "advice": ADVICE if findings else [],
        "counts": {"indicators": len(findings)},
        "available_indicators": [
            {"key": k, "severity": v[1], "points": v[0], "title": v[2]}
            for k, v in INDICATORS.items()
        ],
    }
