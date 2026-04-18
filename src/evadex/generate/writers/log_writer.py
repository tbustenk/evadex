"""Log writer for evadex generate — application log format."""
from __future__ import annotations

import datetime
import json
import random
from evadex.generate.generator import GeneratedEntry
from evadex.core.result import PayloadCategory

_LOG_LEVELS = ["INFO", "DEBUG", "WARN", "ERROR"]
_LOG_LEVEL_WEIGHTS = [0.5, 0.2, 0.2, 0.1]

_SERVICES = [
    "payment-service", "auth-service", "kyc-service", "account-service",
    "compliance-engine", "transaction-processor", "notification-service",
    "audit-logger", "report-generator", "batch-processor",
]

_ACTIONS: dict[PayloadCategory, list[str]] = {
    PayloadCategory.CREDIT_CARD: [
        "Payment processed for card={v} amount={amt}",
        "Card validation passed: {v}",
        "Tokenisation request for card {v} — token issued",
        "Refund issued to card={v} ref={ref}",
        "3DS challenge completed for card {v}",
    ],
    PayloadCategory.SSN: [
        "Identity verified: SSN={v}",
        "Tax form generated for SSN {v}",
        "KYC check: SSN={v} status=passed",
        "Background check initiated for SSN={v}",
    ],
    PayloadCategory.SIN: [
        "Employee record updated: SIN={v}",
        "T4 slip generated for SIN {v}",
        "CRA submission: SIN={v} status=accepted",
        "Benefits enrolment: SIN={v} plan=B",
    ],
    PayloadCategory.IBAN: [
        "SEPA transfer initiated: dest_iban={v} amount={amt}",
        "Account validation: IBAN={v} status=valid",
        "Wire transfer completed to {v}",
        "Direct debit mandate registered: IBAN={v}",
    ],
    PayloadCategory.EMAIL: [
        "Notification sent to email={v}",
        "User login: email={v} ip={ip}",
        "Password reset requested for {v}",
        "Account created: {v}",
    ],
    PayloadCategory.PHONE: [
        "SMS OTP sent to phone={v}",
        "Outbound call placed to {v}",
        "Phone verification: number={v} status=verified",
    ],
}

_FALLBACK_ACTIONS = [
    "Data processed: value={v}",
    "Record updated with value={v}",
    "Validation check: {v} — passed",
    "Audit log entry: sensitive_value={v}",
]


def write_log(entries: list[GeneratedEntry], path: str) -> None:
    rng = random.Random(42)
    base_dt = datetime.datetime(2026, 4, 17, 8, 0, 0)

    lines: list[str] = []

    for i, e in enumerate(entries):
        # Advance time by 1-30 seconds per entry
        ts = base_dt + datetime.timedelta(seconds=i * rng.randint(1, 30))
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")

        level = rng.choices(_LOG_LEVELS, weights=_LOG_LEVEL_WEIGHTS, k=1)[0]
        service = rng.choice(_SERVICES)
        ref = f"TXN-{rng.randint(100000, 999999)}"
        amt = f"{rng.uniform(10, 5000):.2f}"
        ip = f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"

        actions = _ACTIONS.get(e.category, _FALLBACK_ACTIONS)
        action_tpl = rng.choice(actions)
        action = action_tpl.format(v=e.variant_value, amt=amt, ref=ref, ip=ip)

        # Alternate between log formats: plaintext, structured, JSON
        fmt_choice = rng.randint(0, 2)

        if fmt_choice == 0:
            # Plain text log
            line = f"{ts_str} {level} [{service}] {action}"
        elif fmt_choice == 1:
            # Structured log
            line = (
                f"{ts_str} {level} service={service} "
                f"action=\"{action}\" "
                f"request_id={ref} duration_ms={rng.randint(1, 500)}"
            )
        else:
            # JSON log
            log_obj = {
                "timestamp": ts_str,
                "level": level,
                "service": service,
                "message": action,
                "request_id": ref,
                "duration_ms": rng.randint(1, 500),
            }
            line = json.dumps(log_obj, ensure_ascii=False)

        if e.technique:
            line += f"  # evasion: {e.technique}"

        lines.append(line)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
