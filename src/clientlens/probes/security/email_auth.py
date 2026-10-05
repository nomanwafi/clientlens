"""Email authentication posture: SPF, DKIM, DMARC, MTA-STS, TLS-RPT.

All of this is public DNS, so every result is directly verifiable. DMARC
policy strength is graded on the published policy itself — we do not attempt
to send mail.
"""

from __future__ import annotations

from ...core.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    FindingKind,
    Severity,
)
from ...core.registry import ProbeContext, ProbeMode, ProbePhase, register_probe
from ..shared.dns_client import resolve_record, resolve_txt_at

# Common DKIM selectors to probe. Absence across these is reported as
# "not detected", never as "DKIM is not configured".
COMMON_DKIM_SELECTORS = (
    "default",
    "selector1",
    "selector2",
    "google",
    "k1",
    "k2",
    "dkim",
    "mail",
    "s1",
    "s2",
    "smtp",
    "mandrill",
    "everlytickey1",
    "cm",
)


@register_probe(
    id="security.email_auth",
    category=Category.SECURITY,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    title="Email authentication (SPF / DKIM / DMARC)",
    description="Public DNS records that govern whether the domain can be spoofed.",
    tags=("email", "phishing", "brand-protection"),
)
async def check_email_auth(ctx: ProbeContext) -> list[Finding]:
    """Look up SPF, DMARC and common DKIM selectors."""
    findings: list[Finding] = []
    target = ctx.target
    apex = target.apex

    # ---- SPF ---------------------------------------------------------------
    spf_records = await resolve_txt_at(apex)
    spf = [r for r in spf_records if r.lower().startswith("v=spf1")]

    if not spf:
        findings.append(
            Finding(
                id="security.email_auth.spf_missing",
                title="No SPF record published",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.dns_record(apex, "TXT", spf_records),
                reasoning=(
                    "Without an SPF record any host on the internet can send mail "
                    "claiming to be from this domain and receivers have no declared "
                    "policy to check against. This is the single largest lever for "
                    "domain spoofing and phishing that impersonates the brand."
                ),
                scope=f"TXT records on {apex}",
                remediation=(
                    f"Publish an SPF record listing exactly the hosts that send mail, e.g.\n"
                    f'  {apex}.  IN  TXT  "v=spf1 include:_spf.google.com -all"'
                ),
                tags=["email", "spf", "anti-spoofing"],
            )
        )
    elif len(spf) > 1:
        findings.append(
            Finding(
                id="security.email_auth.spf_multiple",
                title="Multiple SPF records published (RFC violation)",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.dns_record(apex, "TXT", spf),
                reasoning=(
                    "RFC 7208 permits exactly one SPF record per name. With more "
                    "than one, receivers treat the SPF check as PermError and fall "
                    "back to no SPF result at all — so the policy silently does "
                    "nothing."
                ),
                scope=f"TXT records on {apex}",
                remediation="Merge the mechanisms into a single `v=spf1 ...` record.",
                tags=["email", "spf"],
            )
        )
    else:
        policy = spf[0]
        findings.append(
            Finding(
                id="security.email_auth.spf_present",
                title="SPF record published",
                category=Category.SECURITY,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.dns_record(apex, "TXT", [policy]),
                reasoning=f"Published SPF policy: {policy[:180]}",
                scope=f"TXT records on {apex}",
                tags=["email", "spf", "strength"],
            )
        )
        if " +all" in policy or policy.strip().endswith(" +all"):
            findings.append(
                Finding(
                    id="security.email_auth.spf_plus_all",
                    title="SPF policy ends in `+all` (permits every sender)",
                    category=Category.SECURITY,
                    kind=FindingKind.MISCONFIGURATION,
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.dns_record(apex, "TXT", [policy]),
                    reasoning=(
                        "`+all` means 'any host may send as this domain', which is "
                        "equivalent to publishing no SPF policy at all for "
                        "anti-spoofing purposes."
                    ),
                    scope=f"SPF record on {apex}",
                    remediation="Change the terminator to `-all` (hard fail) or `~all` (soft fail).",
                    tags=["email", "spf"],
                )
            )

    # ---- DMARC -------------------------------------------------------------
    dmarc_records = await resolve_txt_at(f"_dmarc.{apex}")
    dmarc = [r for r in dmarc_records if r.lower().startswith("v=dmarc1")]

    if not dmarc:
        findings.append(
            Finding(
                id="security.email_auth.dmarc_missing",
                title="No DMARC record published",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.dns_record(f"_dmarc.{apex}", "TXT", dmarc_records),
                reasoning=(
                    "DMARC is the policy layer that tells receivers what to do when "
                    "SPF/DKIM fail, and gives the domain owner visibility via "
                    "aggregate reports. Without it, look-alike mail from this domain "
                    "is accepted on a best-effort basis and the brand has no way to "
                    "detect the abuse."
                ),
                scope=f"TXT records on _dmarc.{apex}",
                remediation=(
                    f"Start with monitoring, then enforce:\n"
                    f'  _dmarc.{apex}.  IN  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@{apex}"\n'
                    f"then move to p=quarantine and p=reject."
                ),
                tags=["email", "dmarc", "anti-spoofing", "brand-protection"],
            )
        )
    else:
        policy_text = dmarc[0]
        p_tag = _dmarc_tag(policy_text, "p")
        pct = _dmarc_tag(policy_text, "pct") or "100"
        rua = _dmarc_tag(policy_text, "rua")

        findings.append(
            Finding(
                id="security.email_auth.dmarc_present",
                title=f"DMARC record published (p={p_tag or 'n/a'})",
                category=Category.SECURITY,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.dns_record(f"_dmarc.{apex}", "TXT", dmarc),
                reasoning=f"Published DMARC policy: {policy_text[:200]}",
                scope=f"TXT records on _dmarc.{apex}",
                tags=["email", "dmarc", "strength"],
            )
        )

        if p_tag in {"none", ""}:
            findings.append(
                Finding(
                    id="security.email_auth.dmarc_monitoring_only",
                    title="DMARC policy is `p=none` (monitor only)",
                    category=Category.SECURITY,
                    kind=FindingKind.MISCONFIGURATION,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.dns_record(f"_dmarc.{apex}", "TXT", dmarc),
                    reasoning=(
                        "`p=none` means receivers are told to do nothing when "
                        "alignment fails. The domain is being observed but not "
                        "protected. It is a valid first step, but if it has been in "
                        "place for a long time the enforcement work has stalled."
                    ),
                    scope=f"DMARC record on _dmarc.{apex}",
                    remediation="Once reports are clean, move to `p=quarantine` then `p=reject`.",
                    tags=["email", "dmarc"],
                )
            )

        if pct and pct != "100":
            findings.append(
                Finding(
                    id="security.email_auth.dmarc_partial_pct",
                    title=f"DMARC applies to only {pct}% of messages",
                    category=Category.SECURITY,
                    kind=FindingKind.MISCONFIGURATION,
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.dns_record(f"_dmarc.{apex}", "TXT", dmarc),
                    reasoning=(
                        "With `pct` below 100 a fraction of failing mail is left "
                        "unprotected by design. This is normal during a staged "
                        "rollout but should reach 100%."
                    ),
                    scope=f"DMARC record on _dmarc.{apex}",
                    remediation="Raise `pct=100` once the policy is settled.",
                    tags=["email", "dmarc"],
                )
            )

        if not rua:
            findings.append(
                Finding(
                    id="security.email_auth.dmarc_no_reports",
                    title="DMARC record has no `rua` aggregate reporting address",
                    category=Category.SECURITY,
                    kind=FindingKind.MISCONFIGURATION,
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.dns_record(f"_dmarc.{apex}", "TXT", dmarc),
                    reasoning=(
                        "Without `rua`, nobody receives aggregate reports, so the "
                        "domain owner cannot see who is sending as the domain and "
                        "cannot validate that legitimate mail is aligned before "
                        "tightening the policy."
                    ),
                    scope=f"DMARC record on _dmarc.{apex}",
                    remediation=f"Add `rua=mailto:dmarc@{apex}` to the DMARC record.",
                    tags=["email", "dmarc", "visibility"],
                )
            )

    # ---- DKIM (bounded selector probe) -------------------------------------
    # NB: a wildcard `*._domainkey.<domain>` TXT record answers *every* selector
    # with the same value. Detect that case explicitly — otherwise we would
    # report 14 "found" selectors when in fact the domain publishes one revoked
    # key for the wildcard name.
    wildcard_ans = await resolve_record(f"*._domainkey.{apex}", "TXT")
    wildcard_vals = [v for v in wildcard_ans.values if "v=dkim1" in v.lower() or "p=" in v.lower()]
    wildcard_seen_values = {v.strip() for v in wildcard_vals}

    found_dkim: list[tuple[str, list[str]]] = []
    revoked_dkim: list[tuple[str, list[str]]] = []
    wildcard_hits = 0

    for selector in COMMON_DKIM_SELECTORS:
        name = f"{selector}._domainkey.{apex}"
        ans = await resolve_record(name, "TXT")
        vals = [v for v in ans.values if "v=dkim1" in v.lower() or "p=" in v.lower()]
        if not vals:
            continue

        # Same value as the wildcard record → it is the wildcard answering.
        if wildcard_seen_values and all(v.strip() in wildcard_seen_values for v in vals):
            wildcard_hits += 1
            continue

        public_key = _dkim_public_key(vals[0])
        if public_key:
            found_dkim.append((selector, vals))
        else:
            revoked_dkim.append((selector, vals))

    if found_dkim:
        selector_names = ", ".join(s for s, _ in found_dkim)
        findings.append(
            Finding(
                id="security.email_auth.dkim_detected",
                title=f"DKIM public keys found for {len(found_dkim)} selector(s)",
                category=Category.SECURITY,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.dns_record(
                    apex, "TXT", [f"{s}: {v[0][:120]}" for s, v in found_dkim]
                ),
                reasoning=(
                    f"Selectors observed: {selector_names}. DKIM signing lets "
                    "receivers verify mail actually originated here and enables "
                    "DMARC alignment."
                ),
                scope=f"DKIM selector lookups on *._domainkey.{apex}",
                tags=["email", "dkim", "strength"],
            )
        )
    elif wildcard_hits:
        findings.append(
            Finding(
                id="security.email_auth.dkim_wildcard_revoked",
                title="Only a wildcard DKIM record is published, with no public key",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.dns_record(
                    f"*._domainkey.{apex}", "TXT", sorted(wildcard_seen_values)
                ),
                reasoning=(
                    f"Every one of the {wildcard_hits} tested selector names resolves "
                    "to the same value, which means a wildcard record is answering. "
                    "That record contains `p=` with an empty key, which per RFC 6376 "
                    "means the selector is revoked.\n\n"
                    "A revoked wildcard key is not a working DKIM configuration: no "
                    "mail from this domain can be signed in a way receivers can "
                    "verify, so DMARC alignment depends entirely on SPF."
                ),
                scope=f"DKIM selector lookups on *._domainkey.{apex}",
                remediation=(
                    "Publish a real per-selector DKIM record (e.g. "
                    f"`<selector>._domainkey.{apex}`) with a public key, and remove "
                    "the revoked wildcard."
                ),
                tags=["email", "dkim"],
            )
        )
    elif revoked_dkim:
        findings.append(
            Finding(
                id="security.email_auth.dkim_revoked",
                title=f"{len(revoked_dkim)} DKIM selector(s) found but with revoked/empty keys",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.dns_record(
                    apex, "TXT", [f"{s}: {v[0][:120]}" for s, v in revoked_dkim]
                ),
                reasoning=(
                    "These selectors resolve but carry `p=` with an empty public key, "
                    "which RFC 6376 defines as a revoked selector. Mail signed with "
                    "them cannot be verified."
                ),
                scope=f"DKIM selector lookups on *._domainkey.{apex}",
                remediation="Rotate to a selector with a real public key, and retire the revoked ones.",
                tags=["email", "dkim"],
            )
        )
    else:
        findings.append(
            Finding(
                id="security.email_auth.dkim_not_detected",
                title="No DKIM keys found for common selectors",
                category=Category.SECURITY,
                kind=FindingKind.GAP,
                severity=Severity.INFO,
                confidence=Confidence.NEEDS_REVIEW,
                evidence=Evidence.text(
                    "Tried selectors: " + ", ".join(COMMON_DKIM_SELECTORS),
                    source=f"TXT *._domainkey.{apex}",
                ),
                reasoning=(
                    "None of the common DKIM selectors returned a public key. This "
                    "is NOT proof that DKIM is unconfigured — many senders use "
                    "non-standard selectors. Confirm against the mail provider's "
                    "documentation before concluding anything."
                ),
                scope=f"DKIM selector lookups on *._domainkey.{apex}",
                remediation="Check the mail provider's DKIM setup page for the correct selector names.",
                tags=["email", "dkim", "needs-review"],
            )
        )

    # ---- MTA-STS -----------------------------------------------------------
    sts_records = await resolve_txt_at(f"_mta-sts.{apex}")
    if any(r.lower().startswith("v=sts1") for r in sts_records):
        findings.append(
            Finding(
                id="security.email_auth.mta_sts_present",
                title="MTA-STS policy published",
                category=Category.SECURITY,
                kind=FindingKind.STRENGTH,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.dns_record(f"_mta-sts.{apex}", "TXT", sts_records),
                reasoning="Inbound mail to this domain is required to use a valid TLS certificate.",
                scope=f"TXT records on _mta-sts.{apex}",
                tags=["email", "mta-sts", "strength"],
            )
        )

    return findings


def _dmarc_record_is_present(records: list[str]) -> bool:
    return any(r.lower().startswith("v=dmarc1") for r in records)


def _dkim_public_key(txt: str) -> str:
    """Return the base64 public key body of a DKIM record, or '' if revoked/absent.

    RFC 6376 §3.6.1: ``p=`` with an empty value means the key is revoked and
    must not be used. Only a non-empty ``p=`` is a working key.
    """
    for part in txt.split(";"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        if k.strip().lower() == "p":
            return v.strip()
    return ""


def _dmarc_tag(policy: str, tag: str) -> str:
    for part in policy.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            if k.strip().lower() == tag.lower():
                return v.strip()
    return ""
