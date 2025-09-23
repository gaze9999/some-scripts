#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import urllib.parse
from datetime import datetime, timezone
from dataclasses import dataclass
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr

CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f]")
ANGLE_BRACKET_RE = re.compile(r"<([^>]+)>")
MAILTO_RE = re.compile(r"^mailto:([^?]*)(?:\?(.*))?$", re.IGNORECASE)
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
ALLOWED_SCHEMES = {"http", "https", "mailto"}
SAFE_PATH_CHARS = "/-._~"
SUSPICIOUS_TLDS = {
    "ru",
    "cn",
    "su",
    "tk",
    "pw",
    "top",
    "work",
    "zip",
    "review",
    "country",
    "kim",
    "cricket",
}
AUTH_METHODS = ("spf", "dkim", "dmarc")
AUTH_RESULT_PATTERN = re.compile(r"\b(spf|dkim|dmarc)=([a-z0-9_-]+)")
SPF_RISK_STATUSES = {"fail", "softfail", "neutral", "temperror", "permerror", "none"}
DKIM_RISK_STATUSES = {"fail", "temperror", "permerror"}
DMARC_RISK_STATUSES = {"fail", "temperror", "permerror"}
SECOND_LEVEL_SUFFIXES = {
    "co.uk",
    "com.au",
    "com.br",
    "com.cn",
    "com.hk",
    "com.sg",
    "com.tw",
    "co.jp",
    "co.kr",
}


@dataclass
class SanitizedLink:

    type: str
    value: str

    def to_dict(self) -> dict[str, str]:
        return {"type": self.type, "value": self.value}


@dataclass
class PhishingAssessment:
    suspected: bool
    warnings: list[str]
    notes: list[str]
    sender_domains: list[str]
    unsubscribe_domains: list[str]
    auth_results: dict[str, str | None]
    auth_sources: dict[str, list[str]]
    return_path_domain: str | None
    dkim_signature_present: bool


def parse_email_bytes(raw_bytes: bytes) -> Message:
    parser = BytesParser(policy=policy.default)
    return parser.parsebytes(raw_bytes)


def parse_email_file(path: str) -> Message:
    try:
        with open(path, "rb") as handle:
            raw_bytes = handle.read()
    except OSError as exc:
        raise RuntimeError(f"failed to read email file: {path}") from exc
    return parse_email_bytes(raw_bytes)


def extract_sender_domains(message: Message) -> set[str]:
    domains: set[str] = set()
    for _, address in getaddresses(message.get_all("From", [])):
        if not address or "@" not in address:
            continue
        domain = address.split("@", 1)[1].strip().lower()
        if domain:
            domains.add(domain)
    return domains


def extract_return_path_domain(message: Message) -> str | None:
    raw = message.get("Return-Path")
    if not raw:
        return None
    _, address = parseaddr(raw)
    if not address or "@" not in address:
        return None
    domain = address.split("@", 1)[1].strip().lower()
    return domain or None


def domain_from_link(link: SanitizedLink) -> str | None:
    if link.type == "url":
        hostname = urllib.parse.urlsplit(link.value).hostname
        return hostname.lower() if hostname else None
    if link.type == "mailto":
        parsed = urllib.parse.urlsplit(link.value)
        address = parsed.path
        if "@" not in address:
            return None
        domain = address.split("@", 1)[1]
        return domain.lower() if domain else None
    return None


def get_base_domain(domain: str) -> str:
    parts = [piece for piece in domain.split(".") if piece]
    if len(parts) < 2:
        return domain
    suffix = ".".join(parts[-2:])
    if suffix in SECOND_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return suffix


def is_ip_address(domain: str) -> bool:
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def extract_reply_to_domains(message: Message) -> set[str]:
    domains: set[str] = set()
    for _, address in getaddresses(message.get_all("Reply-To", [])):
        if not address or "@" not in address:
            continue
        domain = address.split("@", 1)[1].strip().lower()
        if domain:
            domains.add(domain)
    return domains


def parse_authentication_results(message: Message) -> tuple[dict[str, str | None], dict[str, list[str]], bool]:
    results: dict[str, str | None] = {method: None for method in AUTH_METHODS}
    sources: dict[str, list[str]] = {method: [] for method in AUTH_METHODS}
    headers = message.get_all("Authentication-Results", [])
    for header in headers:
        lowered = header.lower()
        for match in AUTH_RESULT_PATTERN.finditer(lowered):
            method, status = match.groups()
            sources[method].append(header.strip())
            if results[method] is None or status == "pass":
                results[method] = status

    received_spf_headers = message.get_all("Received-SPF", [])
    for header in received_spf_headers:
        status = interpret_received_spf_status(header)
        if status:
            sources["spf"].append(header.strip())
            if results["spf"] is None or results["spf"] != "pass":
                results["spf"] = status

    dkim_signature_present = bool(message.get("DKIM-Signature"))
    return results, sources, dkim_signature_present


def interpret_received_spf_status(header: str) -> str | None:
    lowered = header.lower()
    for status in ("fail", "softfail", "neutral", "none", "permerror", "temperror", "pass"):
        if status in lowered:
            return status
    return None


def analyze_phishing(message: Message, links: list[SanitizedLink]) -> PhishingAssessment:
    warnings: list[str] = []
    notes: list[str] = []
    sender_domains = extract_sender_domains(message)
    if not sender_domains:
        warnings.append("Missing From header or sender address.")

    unsubscribe_domains: set[str] = set()
    for link in links:
        domain = domain_from_link(link)
        if not domain:
            continue
        unsubscribe_domains.add(domain)
        tld = domain.rsplit(".", 1)[-1] if "." in domain else domain
        if tld in SUSPICIOUS_TLDS:
            warnings.append(f"Unsubscribe domain uses high-risk TLD: {domain}")
        if domain.startswith("xn--"):
            warnings.append(f"Unsubscribe domain uses punycode: {domain}")
        if is_ip_address(domain):
            warnings.append(f"Unsubscribe domain is an IP address: {domain}")

    sender_bases = {get_base_domain(domain) for domain in sender_domains}
    unsubscribe_bases = {get_base_domain(domain) for domain in unsubscribe_domains}
    if sender_bases and unsubscribe_bases and sender_bases.isdisjoint(unsubscribe_bases):
        warnings.append("Unsubscribe domains differ from sender domains.")

    subject = message.get("Subject", "") or ""
    lowered_subject = subject.lower()
    if any(keyword in lowered_subject for keyword in ("urgent", "suspended", "verify", "password", "account locked")):
        warnings.append("Subject contains urgent-action keywords.")

    reply_to_domains = extract_reply_to_domains(message)
    if reply_to_domains and sender_domains:
        reply_bases = {get_base_domain(domain) for domain in reply_to_domains}
        if reply_bases.isdisjoint({get_base_domain(domain) for domain in sender_domains}):
            warnings.append("Reply-To domains differ from sender domains.")

    return_path_domain = extract_return_path_domain(message)
    if return_path_domain and sender_domains:
        return_base = get_base_domain(return_path_domain)
        if return_base not in {get_base_domain(domain) for domain in sender_domains}:
            warnings.append("Return-Path domain differs from sender domains.")

    auth_results, auth_sources, dkim_signature_present = parse_authentication_results(message)

    spf_status = auth_results["spf"]
    if spf_status and spf_status in SPF_RISK_STATUSES:
        warnings.append(f"SPF result indicates {spf_status}.")
    if spf_status is None:
        notes.append("SPF result missing.")

    dkim_status = auth_results["dkim"]
    if dkim_signature_present:
        if dkim_status is None:
            warnings.append("DKIM signature present but no validation result.")
        elif dkim_status in DKIM_RISK_STATUSES:
            warnings.append(f"DKIM result indicates {dkim_status}.")

    if not dkim_signature_present and dkim_status and dkim_status in DKIM_RISK_STATUSES:
        warnings.append("DKIM validation failed without signature context.")

    dmarc_status = auth_results["dmarc"]
    if dmarc_status and dmarc_status in DMARC_RISK_STATUSES:
        warnings.append(f"DMARC result indicates {dmarc_status}.")
    if dmarc_status is None:
        notes.append("DMARC result missing.")

    def unique(items: list[str]) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []
        for item in items:
            if item not in seen:
                seen.add(item)
                ordered.append(item)
        return ordered

    unique_warnings = unique(warnings)
    unique_notes = unique(notes)

    return PhishingAssessment(
        suspected=bool(unique_warnings),
        warnings=unique_warnings,
        notes=unique_notes,
        sender_domains=sorted(sender_domains),
        unsubscribe_domains=sorted(unsubscribe_domains),
        auth_results=auth_results,
        auth_sources=auth_sources,
        return_path_domain=return_path_domain,
        dkim_signature_present=dkim_signature_present,
    )


def collect_list_unsubscribe_headers(message: Message) -> str | None:
    headers = message.get_all("List-Unsubscribe", [])
    if not headers:
        return None
    return ", ".join(str(header) for header in headers if header)


def get_candidates(header_value: str) -> list[str]:
    if not header_value:
        return []
    bracket_matches = ANGLE_BRACKET_RE.findall(header_value)
    if bracket_matches:
        return [match.strip() for match in bracket_matches if match.strip()]

    pieces = [piece.strip() for piece in header_value.split(",")]
    return [piece for piece in pieces if piece]


def sanitize_candidate(candidate: str) -> SanitizedLink | None:
    if not candidate:
        return None
    cleaned = CONTROL_CHARS_RE.sub("", candidate.strip())
    if not cleaned:
        return None

    if cleaned.startswith("<") and cleaned.endswith(">"):
        cleaned = cleaned[1:-1].strip()

    scheme = urllib.parse.urlsplit(cleaned).scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        return None

    if scheme in {"http", "https"}:
        return sanitize_http_url(cleaned)

    if scheme == "mailto":
        return sanitize_mailto(cleaned)

    return None


def sanitize_http_url(raw_url: str) -> SanitizedLink | None:
    try:
        parsed = urllib.parse.urlsplit(raw_url)
    except ValueError:
        return None

    if parsed.scheme.lower() not in {"http", "https"}:
        return None

    if parsed.username or parsed.password:
        return None

    if not parsed.hostname:
        return None

    try:
        hostname = parsed.hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    netloc = hostname
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"

    try:
        normalized_path = urllib.parse.quote(
            urllib.parse.unquote(parsed.path or "/"), safe=SAFE_PATH_CHARS
        )
    except (ValueError, UnicodeDecodeError):
        return None

    query_items = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    normalized_query = urllib.parse.urlencode(query_items)

    sanitized = urllib.parse.urlunsplit(
        (
            parsed.scheme.lower(),
            netloc,
            normalized_path,
            normalized_query,
            "",
        )
    )
    return SanitizedLink(type="url", value=sanitized)


def sanitize_mailto(raw_mailto: str) -> SanitizedLink | None:
    match = MAILTO_RE.match(raw_mailto)
    if not match:
        return None

    address_part = urllib.parse.unquote(match.group(1) or "").strip()
    if not address_part or not EMAIL_RE.match(address_part):
        return None

    query_part = match.group(2)
    sanitized_query = ""
    if query_part:
        params = urllib.parse.parse_qsl(query_part, keep_blank_values=True)
        if params:
            sanitized_query = urllib.parse.urlencode(params)

    value = f"mailto:{address_part}"
    if sanitized_query:
        value = f"{value}?{sanitized_query}"

    return SanitizedLink(type="mailto", value=value)


def extract_list_unsubscribe_links(message: Message) -> tuple[SanitizedLink | None, list[SanitizedLink]]:
    header_value = collect_list_unsubscribe_headers(message)
    if not header_value:
        return None, []

    sanitized_links = [
        sanitized
        for candidate in get_candidates(header_value)
        if (sanitized := sanitize_candidate(candidate)) is not None
    ]

    if not sanitized_links:
        return None, []

    preferred = next((link for link in sanitized_links if link.type == "url"), sanitized_links[0])
    return preferred, sanitized_links


def append_log_entry(path: str, entry: dict[str, object]) -> None:
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False))
            handle.write("\n")
    except OSError as exc:
        print(f"Failed to write log file: {path} ({exc})", file=sys.stderr)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Extract and sanitize the List-Unsubscribe links from a raw email file or pasted input."
        )
    )
    parser.add_argument(
        "email_file",
        nargs="?",
        help="Path to the raw email file to parse (omit to paste the email via stdin)",
    )
    parser.add_argument(
        "--log",
        dest="log_path",
        help="Append scan results to this log file as JSON lines",
    )
    args = parser.parse_args(argv)

    if args.email_file:
        try:
            message = parse_email_file(args.email_file)
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        source_label = args.email_file
    else:
        if sys.stdin.isatty():
            print("Paste the raw email below, then press Ctrl-D (Ctrl-Z on Windows) to finish:", file=sys.stderr)
        raw_bytes = sys.stdin.buffer.read()
        if not raw_bytes.strip():
            print("No input received from stdin.", file=sys.stderr)
            return 1
        message = parse_email_bytes(raw_bytes)
        source_label = "stdin"

    preferred, links = extract_list_unsubscribe_links(message)
    assessment = analyze_phishing(message, links)

    if assessment.suspected:
        print("Potential phishing indicators detected.", file=sys.stderr)
        for warning in assessment.warnings:
            print(f" - {warning}", file=sys.stderr)
    elif assessment.notes:
        print("No high-risk indicators detected; informational notes:", file=sys.stderr)
        for note in assessment.notes:
            print(f" - {note}", file=sys.stderr)

    if not links:
        print("List-Unsubscribe header not found or contains no valid links.", file=sys.stderr)
        return 2

    output = {
        "preferredType": preferred.type if preferred else None,
        "preferredLink": preferred.value if preferred else None,
        "links": [link.to_dict() for link in links],
        "phishingSuspected": assessment.suspected,
        "isPhishing": assessment.suspected,
        "phishingWarnings": assessment.warnings,
        "phishingNotes": assessment.notes,
        "senderDomains": assessment.sender_domains,
        "unsubscribeDomains": assessment.unsubscribe_domains,
        "returnPathDomain": assessment.return_path_domain,
        "dkimSignaturePresent": assessment.dkim_signature_present,
        "authResults": assessment.auth_results,
        "authSources": assessment.auth_sources,
        "source": source_label,
    }

    if args.log_path:
        append_log_entry(
            args.log_path,
            {
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "source": source_label,
                "phishingSuspected": assessment.suspected,
                "isPhishing": assessment.suspected,
                "warnings": assessment.warnings,
                "notes": assessment.notes,
                "senderDomains": assessment.sender_domains,
                "unsubscribeDomains": assessment.unsubscribe_domains,
                "preferredLink": output["preferredLink"],
                "authResults": assessment.auth_results,
                "returnPathDomain": assessment.return_path_domain,
            },
        )
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
