"""Generate near-duplicate documents at controlled Jaccard-similarity levels.

Siphon's LSH uses 3-word shingles. To produce a variant at a target
similarity to a base document, we replace a fraction of the words
with neutral filler. Each replaced word breaks up to ``shingle_size``
shingles, so the empirical similarity to the base is roughly
``1 - replace_rate * shingle_size``. We measure the actual Jaccard
afterwards and report it — distortion rate is the knob, similarity
is the observation.
"""
from __future__ import annotations

import random
from typing import Iterator


# Three base documents covering the kinds of text a bank actually
# stores in DLP-protected systems. Each is dense in sensitive
# values and 200+ words long so the 3-word shingle pool is rich
# enough that distortion produces stable, predictable similarity.

BASE_DOCUMENTS: dict[str, str] = {
    "loan_decision": (
        "Internal Loan Decision Memorandum. Customer John Smith holding "
        "credit card 4532015112830366 with social insurance number 046 454 286 "
        "has applied for a residential mortgage loan in the amount of four "
        "hundred fifty thousand dollars secured against the property at "
        "1428 Bayview Avenue Toronto Ontario M4G 3A9. The applicant maintains "
        "an active chequing account at branch zero zero zero one with "
        "transit number 00021 institution number 003 account ending in 7842. "
        "Risk classification is medium based on debt to income ratio of "
        "thirty eight percent and a credit bureau score of seven hundred "
        "twenty two from Equifax Canada. Underwriting recommendation is "
        "conditional approval pending verification of stated income through "
        "Canada Revenue Agency notice of assessment. Compliance officer "
        "Maria Chen has reviewed for anti money laundering exposure and "
        "identified no politically exposed person flags or sanctioned party "
        "matches. Final decision authority rests with the regional credit "
        "manager. Document classification is confidential restricted internal "
        "use only and must not be shared outside the bank without written "
        "approval from privacy and legal departments. Retention period is "
        "seven years from origination date pursuant to federal record "
        "keeping requirements under the Bank Act and Proceeds of Crime "
        "Money Laundering and Terrorist Financing Act regulations."
    ),
    "incident_report": (
        "Security Incident Response Report. On the seventeenth of April "
        "automated monitoring detected unusual outbound network traffic "
        "from workstation WS dash four four two zero one assigned to "
        "employee badge number 178293 in the wholesale payments division. "
        "The traffic originated from process notepad dot exe and "
        "transmitted approximately two megabytes to external host "
        "203 dot zero dot 113 dot 47 over port four four three using TLS. "
        "Endpoint forensic capture identified a temporary file containing "
        "what appears to be customer account data including credit card "
        "number 5425233430109903 and chequing account 7842156 belonging to "
        "an unnamed corporate client. The data loss prevention scanner "
        "Siphon flagged the egress attempt within eight hundred milliseconds "
        "and the firewall blocked the session. Affected user account has "
        "been suspended pending investigation by the insider threat team "
        "led by analyst Jennifer Park. Initial triage indicates this may be "
        "a misconfigured backup script rather than a malicious data "
        "exfiltration but full forensic analysis is in progress. "
        "Notification obligations under the Personal Information Protection "
        "and Electronic Documents Act are being assessed by the privacy "
        "office. No customer notification has been authorized at this time "
        "as the scope of any actual data exposure remains under "
        "investigation. Status updates will be issued every twelve hours "
        "to the executive risk committee until resolution."
    ),
    "compliance_finding": (
        "Compliance Audit Finding F dash 2026 dash 042. During the second "
        "quarter review of card data handling controls the compliance team "
        "identified eleven instances of unmasked primary account numbers "
        "stored in customer service ticket attachments outside of the "
        "approved cardholder data environment. Affected tickets include "
        "case 884412 referencing card 4929123412341234 and case 884655 "
        "referencing card 6011514420138473 along with nine others listed "
        "in appendix A of this finding. Each affected card has been "
        "evaluated for compromise risk and the cardholders have been "
        "notified through standard breach notification procedures. The "
        "root cause is identified as a missing data classification rule in "
        "the help desk system that allowed agents to attach screenshots "
        "containing full card numbers without triggering automatic "
        "redaction. Remediation actions include deployment of an updated "
        "Siphon ruleset to the help desk text input pipeline scheduled "
        "for the first of May and mandatory retraining for all level one "
        "support agents to be completed by the fifteenth of May. Finding "
        "severity is rated high under PCI DSS requirement three point two "
        "as primary account numbers were stored without authorized "
        "encryption or tokenization. Closure target is the end of the "
        "second quarter pending validation by external assessor reports."
    ),
}


# Filler words used to replace tokens during distortion. Drawn from
# the same banking domain so the variants stay semantically plausible
# and don't produce documents that visibly look like noise.
_FILLER_WORDS: list[str] = [
    "review", "process", "record", "system", "report", "matter", "item",
    "context", "case", "entry", "document", "section", "summary", "step",
    "phase", "stage", "task", "measure", "control", "policy", "guideline",
    "standard", "procedure", "operation", "function", "service", "branch",
    "office", "team", "group", "unit", "division", "department", "channel",
    "workflow", "session", "instance", "event", "outcome", "result",
    "observation", "remark", "footnote", "addendum", "exhibit", "schedule",
    "attachment", "reference", "supplement", "annex",
]


def shingle(text: str, k: int = 3) -> set[str]:
    """Reproduce Siphon's word-shingling exactly.

    Lowercase, split on whitespace, take all k-word windows. If the
    document has fewer than ``k`` words, fall back to character
    shingles — the same behaviour as ``crates/siphon-core/src/lsh.rs``
    so empirical Jaccard matches what the scanner sees.
    """
    lower = text.lower()
    words = lower.split()
    if len(words) < k:
        chars = list(lower)
        if not chars:
            return set()
        size = max(1, min(k, len(chars)))
        return {"".join(chars[i : i + size]) for i in range(len(chars) - size + 1)}
    return {" ".join(words[i : i + k]) for i in range(len(words) - k + 1)}


def jaccard_similarity(text_a: str, text_b: str, k: int = 3) -> float:
    """Exact Jaccard over k-word shingles. Same value Siphon's MinHash
    estimates probabilistically — this is the ground truth."""
    a = shingle(text_a, k)
    b = shingle(text_b, k)
    if not a and not b:
        return 1.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


# Words we never replace because they carry the document's sensitive
# payload. Without this guard, distortion at high rates would scrub
# the very PII / PCI values we want Siphon to recognise across
# variants — defeating the purpose of an LSH near-duplicate test.
_SENSITIVE_PATTERNS = (
    "@",          # emails
    "$",
)


def _is_sensitive_token(word: str) -> bool:
    """Heuristic: keep tokens that carry numeric identifiers, account
    or card-shaped digits, structured codes, or recognisable PII
    fragments. These are exactly the values DLP needs to track across
    near-duplicates."""
    if any(ch.isdigit() for ch in word):
        return True
    if any(p in word for p in _SENSITIVE_PATTERNS):
        return True
    # Any single-letter or all-uppercase token is structural (M4G, T1A,
    # PCI, DSS, AML) — preserve so distortion doesn't garble codes.
    stripped = word.strip(".,;:()")
    if stripped.isupper() and len(stripped) >= 2:
        return True
    return False


def distorted_variant(
    base: str,
    distortion_rate: float,
    rng: random.Random,
) -> str:
    """Produce a variant of *base* with approximately *distortion_rate*
    of its replaceable words swapped for neutral filler.

    Sensitive tokens (digits, structured codes) are always preserved
    so the variant still carries the same PII payload — the goal is
    to test LSH's ability to recognise that two documents *about the
    same record* are similar even when the prose around the record
    has been rewritten.
    """
    if not 0.0 <= distortion_rate <= 1.0:
        raise ValueError("distortion_rate must be between 0.0 and 1.0")

    words = base.split()
    out: list[str] = []
    for w in words:
        if _is_sensitive_token(w):
            out.append(w)
            continue
        if rng.random() < distortion_rate:
            out.append(rng.choice(_FILLER_WORDS))
        else:
            out.append(w)
    return " ".join(out)


def near_duplicate_set(
    base: str,
    distortion_rates: list[float],
    seed: int = 0,
) -> Iterator[tuple[float, float, str]]:
    """Yield (distortion_rate, empirical_jaccard, variant_text) for
    each requested distortion level. Empirical Jaccard is computed
    against *base* using the same shingle-3 algorithm Siphon uses,
    so the value reflects what the scanner's MinHash should
    asymptotically estimate."""
    rng = random.Random(seed)
    for rate in distortion_rates:
        variant = distorted_variant(base, rate, rng)
        sim = jaccard_similarity(base, variant)
        yield rate, sim, variant
