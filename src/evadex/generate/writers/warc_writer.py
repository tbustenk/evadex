"""WARC (Web ARChive) writer for evadex generate.

Each generated entry becomes one ``response`` record holding a
synthetic HTTP capture of a banking page. Sensitive payloads land
inside the captured HTML body — exactly where Siphon's
``extract_warc`` walks.

The output complies with WARC 1.1 (ISO 28500): one ``warcinfo``
record at the head, then one ``response`` record per entry. Each
record block is preceded by ``WARC/1.1`` plus headers, an empty
line, the block, and trailing ``\\r\\n\\r\\n``.
"""
from __future__ import annotations

import datetime
import hashlib
import random
import uuid

from evadex.generate.generator import GeneratedEntry


_HOSTS = [
    "internal.bank.local",
    "portal.compliance.bank",
    "ops-dashboard.bank.local",
    "audit.intranet.bank",
]

_PATHS = [
    "/customers/{i}/profile",
    "/cases/{i}",
    "/transactions/{i}/details",
    "/kyc/records/{i}",
    "/audit/findings/{i}",
]


def _http_response(idx: int, entry: GeneratedEntry) -> bytes:
    """Synthesise an HTTP/1.1 response with the entry's value embedded
    in an HTML body. Returned bytes are status + headers + blank line
    + body, ready to live inside a WARC ``response`` block."""
    body = (
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head><title>Internal Banking Record</title></head>\n"
        "<body>\n"
        f"  <h1>Record #{idx}</h1>\n"
        f"  <p>Category: {entry.category.value}</p>\n"
        f"  <p class=\"sensitive\">{entry.variant_value}</p>\n"
        f"  <p class=\"context\">{entry.embedded_text}</p>\n"
        "  <footer>CONFIDENTIAL — Internal use only.</footer>\n"
        "</body>\n"
        "</html>\n"
    ).encode("utf-8")

    headers = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        b"Server: bank-internal-portal/2.4\r\n"
        b"X-Internal-Classification: confidential\r\n"
        b"\r\n"
    )
    return headers + body


def _record(
    idx: int,
    base_dt: datetime.datetime,
    rng: random.Random,
    entry: GeneratedEntry,
) -> bytes:
    host = rng.choice(_HOSTS)
    path = rng.choice(_PATHS).format(i=idx)
    url = f"https://{host}{path}"

    block = _http_response(idx, entry)
    block_sha = hashlib.sha1(block).hexdigest()

    record_id = f"<urn:uuid:{uuid.uuid4()}>"
    when = (base_dt + datetime.timedelta(seconds=idx * 11)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    headers = (
        f"WARC/1.1\r\n"
        f"WARC-Type: response\r\n"
        f"WARC-Record-ID: {record_id}\r\n"
        f"WARC-Date: {when}\r\n"
        f"WARC-Target-URI: {url}\r\n"
        f"Content-Type: application/http; msgtype=response\r\n"
        f"WARC-Block-Digest: sha1:{block_sha}\r\n"
        f"Content-Length: {len(block)}\r\n"
        f"\r\n"
    ).encode("utf-8")

    return headers + block + b"\r\n\r\n"


def _warcinfo(base_dt: datetime.datetime) -> bytes:
    info = (
        b"software: evadex DLP test suite\r\n"
        b"format: WARC/1.1\r\n"
        b"description: Synthetic web-archive fixture for DLP testing\r\n"
    )
    record_id = f"<urn:uuid:{uuid.uuid4()}>"
    when = base_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    headers = (
        f"WARC/1.1\r\n"
        f"WARC-Type: warcinfo\r\n"
        f"WARC-Record-ID: {record_id}\r\n"
        f"WARC-Date: {when}\r\n"
        f"WARC-Filename: evadex.warc\r\n"
        f"Content-Type: application/warc-fields\r\n"
        f"Content-Length: {len(info)}\r\n"
        f"\r\n"
    ).encode("utf-8")
    return headers + info + b"\r\n\r\n"


def write_warc(entries: list[GeneratedEntry], path: str) -> None:
    rng = random.Random(42)
    base_dt = datetime.datetime(2026, 4, 17, 12, 0, 0,
                                tzinfo=datetime.timezone.utc)

    with open(path, "wb") as fh:
        fh.write(_warcinfo(base_dt))
        for i, e in enumerate(entries):
            fh.write(_record(i, base_dt, rng, e))
