"""Login & email-activity anomaly detection.

Consumes two event streams (either can be empty):

  logins : [{ts, user, ip, geo, device, success}]
  emails : [{ts, from, recipients:[...], subject}]

and returns a 0–100 anomaly score with human-readable findings. Rules cover
unusual login hours, unfamiliar devices/IPs, failed-login bursts, impossible
travel, send-volume spikes, recipient fan-out and external-heavy audiences.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime

from .engine import Finding

SEVERITY_POINTS = {"high": 15, "medium": 8, "low": 4}


def _parse_ts(value) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _score(findings: list[Finding]) -> tuple[int, str]:
    total = min(100, sum(f.points for f in findings))
    if total >= 75:
        verdict = "critical"
    elif total >= 50:
        verdict = "high"
    elif total >= 25:
        verdict = "moderate"
    else:
        verdict = "normal"
    return total, verdict


# ------------------------------- logins ------------------------------------

def analyse_logins(logins: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    if not logins:
        return findings

    events = sorted(
        ({**e, "_dt": _parse_ts(e.get("ts"))} for e in logins),
        key=lambda e: e["_dt"] or datetime.min,
    )

    known_devices = {e.get("device") for e in events if e.get("device")}
    known_ips = {e.get("ip") for e in events if e.get("ip")}

    # 1. successful logins outside working hours
    odd_hours = [e for e in events
                 if e["_dt"] and e.get("success", True) and not (6 <= e["_dt"].hour < 22)]
    if odd_hours:
        findings.append(Finding(
            "activity", "medium", 8, "Off-hours successful logins",
            f"{len(odd_hours)} successful sign-in(s) outside 06:00–22:00 "
            f"(first: {odd_hours[0]['_dt']:%Y-%m-%d %H:%M})."))

    # 2. failed-login burst
    failures = [e for e in events if not e.get("success", True)]
    if len(failures) >= 5:
        findings.append(Finding(
            "activity", "high", 18, "Failed-login burst",
            f"{len(failures)} failed attempts recorded — consistent with password "
            "spraying or a brute-force attempt against the account."))
    elif failures:
        findings.append(Finding(
            "activity", "low", 4, "Failed login attempts present",
            f"{len(failures)} failed sign-in(s) observed."))

    # 3. successful login immediately after failures
    for i, e in enumerate(events):
        if not e.get("success", True) or not e["_dt"]:
            continue
        window = [f for f in failures
                  if f["_dt"] and 0 <= (e["_dt"] - f["_dt"]).total_seconds() <= 1800]
        if window:
            findings.append(Finding(
                "activity","high", 15, "Success shortly after failed attempts",
                f"A successful sign-in at {e['_dt']:%Y-%m-%d %H:%M} followed "
                f"{len(window)} failure(s) within 30 minutes — possible credential guessing."))
            break

    # 4. first-seen device / IP (assume older events define the baseline)
    baseline = events[: max(1, len(events) // 2)]
    later = events[max(1, len(events) // 2):]
    base_devices = {e.get("device") for e in baseline if e.get("device")}
    base_ips = {e.get("ip") for e in baseline if e.get("ip")}
    new_devices = {e.get("device") for e in later
                   if e.get("device") and e.get("device") not in base_devices}
    new_ips = {e.get("ip") for e in later if e.get("ip") and e.get("ip") not in base_ips}
    if new_devices:
        findings.append(Finding(
            "activity", "medium", 9, "Unfamiliar device used to sign in",
            f"New device(s): {', '.join(sorted(new_devices)[:3])} — verify they belong to the user."))
    if new_ips:
        findings.append(Finding(
            "activity", "medium", 7, "New source IP address",
            f"Sign-in(s) from previously unseen IP(s): {', '.join(sorted(new_ips)[:3])}."))

    # 5. impossible travel — distinct countries within a short window
    geo_by_time = [(e["_dt"], e.get("geo")) for e in events if e["_dt"] and e.get("geo")]
    for i in range(1, len(geo_by_time)):
        dt0, g0 = geo_by_time[i - 1]
        dt1, g1 = geo_by_time[i]
        if g0 != g1 and abs((dt1 - dt0).total_seconds()) <= 3 * 3600:
            findings.append(Finding(
                "activity","high", 20, "Impossible travel",
                f"Sign-ins from {g0} and {g1} within 3 hours "
                f"({dt0:%H:%M} → {dt1:%H:%M}) — physically inconsistent for one person."))
            break

    # 6. single-IP dominance vs. churn (many IPs = possible botnet/session theft)
    ip_counts = Counter(e.get("ip") for e in events if e.get("ip"))
    if len(ip_counts) >= 4 and max(ip_counts.values()) <= 2:
        findings.append(Finding(
            "activity", "medium", 7, "Sign-ins spread across many addresses",
            f"{len(ip_counts)} distinct source IPs with no clear home address — "
            "often indicates session-token theft or automated access."))

    return findings


# ------------------------------- emails ------------------------------------

def analyse_email_activity(emails: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    if not emails:
        return findings

    events = sorted(
        ({**e, "_dt": _parse_ts(e.get("ts"))} for e in emails),
        key=lambda e: e["_dt"] or datetime.min,
    )

    # 1. send-volume spike (per hour buckets)
    buckets: Counter = Counter()
    for e in events:
        if e["_dt"]:
            buckets[e["_dt"].replace(minute=0, second=0, microsecond=0)] += 1
    if buckets:
        peak_hour, peak_count = buckets.most_common(1)[0]
        avg = sum(buckets.values()) / len(buckets)
        if peak_count >= 30 or peak_count >= max(5, avg * 4):
            findings.append(Finding(
                "activity","high", 20, "Abnormal sending-volume spike",
                f"{peak_count} messages in the hour starting {peak_hour:%Y-%m-%d %H:%M} "
                f"(average {avg:.1f}/hour) — a hallmark of a hijacked or auto-relaying mailbox."))

    # 2. recipient fan-out
    all_recipients: list[str] = []
    per_msg_recipients = []
    for e in events:
        rec = e.get("recipients") or []
        per_msg_recipients.append(len(rec))
        all_recipients.extend(r.lower() for r in rec)
    if per_msg_recipients and max(per_msg_recipients) >= 25:
        findings.append(Finding(
            "activity", "high", 16, "Single message fan-out",
            f"One message addressed to {max(per_msg_recipients)} recipients — "
            "typical of spam relaying through a trusted account."))

    unique_recipients = set(all_recipients)
    if len(events) >= 5 and len(unique_recipients) >= max(10, len(events) * 4):
        findings.append(Finding(
            "activity", "medium", 10, "High ratio of new recipients",
            f"{len(unique_recipients)} unique recipients across {len(events)} messages — "
            "the account is contacting people it has never emailed before."))

    # 3. external-heavy audience (naive internal-domain inference)
    senders = { (e.get("from") or "").lower().rsplit("@", 1)[-1] for e in events }
    senders.discard("")
    internal = next(iter(senders), "")
    if internal:
        external = [r for r in unique_recipients if not r.endswith("@" + internal)]
        if unique_recipients and len(external) / len(unique_recipients) >= 0.8 \
                and len(unique_recipients) >= 8:
            findings.append(Finding(
                "activity","medium", 8, "Audience is almost entirely external",
                f"{len(external)}/{len(unique_recipients)} recipients are outside "
                f"'{internal}'."))

    # 4. night-shift sending
    night = [e for e in events if e["_dt"] and not (6 <= e["_dt"].hour < 22)]
    if len(night) >= 5:
        findings.append(Finding(
            "activity", "medium", 7, "Messages sent in the small hours",
            f"{len(night)} message(s) sent outside 06:00–22:00 local time — "
            "automated exfiltration often runs overnight."))

    # 5. identical subjects (template/stager behaviour)
    subjects = Counter((e.get("subject") or "").strip().lower()
                       for e in events if (e.get("subject") or "").strip())
    if subjects:
        top_subject, count = subjects.most_common(1)[0]
        if count >= 10 and len(events) >= 10 and count / len(events) >= 0.6:
            findings.append(Finding(
                "activity","medium", 6, "Repeated template subject",
                f"'{top_subject}' appears {count}/{len(events)} times — bulk-send tooling."))

    return findings


def analyse_activity(payload: dict) -> dict:
    """Analyse combined login + email streams; returns a report dict."""
    logins = payload.get("logins") or []
    emails = payload.get("emails") or []

    findings = analyse_logins(logins) + analyse_email_activity(emails)
    if not findings:
        findings = []

    # dedup by title
    seen: set[str] = set()
    uniq: list[Finding] = []
    for f in findings:
        if f.title not in seen:
            seen.add(f.title)
            uniq.append(f)

    score, verdict = _score(uniq)
    return {
        "kind": "activity",
        "score": score,
        "verdict": verdict,
        "findings": [vars(f) for f in uniq],
        "counts": {"logins": len(logins), "emails": len(emails), "findings": len(uniq)},
    }
