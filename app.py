"""checktls — check whether a domain's mail server (MX) root CA is accepted by Mimecast.

Flow:
  1. Resolve the domain's MX records (all of them).
  2. For each MX host, open an SMTP/TLS connection and capture the certificate chain.
  3. Identify the root CA at the top of the chain (falling back to deriving it from
     the leaf/intermediate issuer if the server does not send the root).
  4. Compare that root against Mimecast's "Supported SSL Certificates" list using
     normalized matching with a family-level fallback.

Run:  py app.py   ->  http://localhost:5000
"""

import base64
import datetime as dt_module
import os
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

import dns.resolver
import requests
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.x509.oid import NameOID
from flask import Flask, jsonify, render_template, request

def _resource_dir() -> str:
    """Directory that holds bundled resources (templates).

    Works both when running from source and when frozen with PyInstaller, where
    onefile mode extracts data files to a temp dir exposed via ``sys._MEIPASS``.
    """
    if getattr(sys, "frozen", False):
        return sys._MEIPASS  # type: ignore[attr-defined]
    return os.path.dirname(os.path.abspath(__file__))


app = Flask(__name__, template_folder=os.path.join(_resource_dir(), "templates"))

MIMECAST_URL = (
    "https://mimecastsupport.zendesk.com/hc/en-us/articles/"
    "34000788572563-Administration-Secure-Socket-Layer-SSL-Certificates"
)

# Browser-like headers so Cloudflare does not serve the JS challenge page.
HTTP_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

CACHE_TTL_SECONDS = 6 * 3600  # keep the parsed CA list for ~6 hours


# --------------------------------------------------------------------------- #
# Mimecast supported-CA list (fetched live, cached in memory)                 #
# --------------------------------------------------------------------------- #
class MimecastList:
    """Holds the set of certificate/CA names Mimecast supports."""

    def __init__(self):
        self._names: list[str] = []
        self._normalized: list[str] = []
        self._families: set[str] = set()
        self._loaded_at: float = 0.0
        self._source: str = "empty"

    @property
    def count(self) -> int:
        return len(self._names)

    @property
    def source(self) -> str:
        return self._source

    @property
    def brand_tokens(self) -> set[str]:
        """Meaningful CA-brand tokens derived from the Mimecast list (for partial matching)."""
        toks = set()
        for n in self._normalized:
            t = _brand_token(n)
            if t and len(t) >= 5:
                toks.add(t)
        return toks

    def refresh_if_stale(self, force: bool = False) -> None:
        now = time.time()
        if not force and self._names and (now - self._loaded_at) < CACHE_TTL_SECONDS:
            return
        try:
            names = _fetch_mimecast_names(MIMECAST_URL)
            if names:
                self._build(names)
                self._source = "live"
                self._loaded_at = now
        except Exception as exc:  # keep last good cache on failure
            if not self._names:
                raise RuntimeError(f"Could not load Mimecast CA list: {exc}") from exc

    def _build(self, names: list[str]) -> None:
        self._names = [n for n in (x.strip() for x in names) if n]
        self._normalized = [_normalize(n) for n in self._names]
        # Family tokens: the leading word(s) that identify a CA brand, e.g. "digicert".
        self._families = set()
        for norm in self._normalized:
            token = _family_token(norm)
            if token and len(token) >= 4:
                self._families.add(token)

    def match(self, name: str) -> tuple[bool, Optional[str]]:
        """Return (matched, matched_entry)."""
        norm = _normalize(name)
        # 1. Exact normalized match.
        for raw, n in zip(self._names, self._normalized):
            if n and n == norm:
                return True, raw
        # 2. Substring either direction (one contains the other).
        for raw, n in zip(self._names, self._normalized):
            if not n or len(n) < 6:
                continue
            if n in norm or norm in n:
                return True, raw
        # 3. Family-level fallback: same leading brand token.
        fam = _family_token(norm)
        if fam and fam in self._families:
            for raw, n in zip(self._names, self._normalized):
                if _family_token(n) == fam:
                    return True, raw
        return False, None

    def match_partial(self, name: str) -> tuple[bool, Optional[str]]:
        """Return (matched, matched_entry) for a *partial* brand overlap.

        Used when ``match()`` found nothing but the CA still shares meaningful
        brand words with one or more Mimecast entries — e.g. Mimecast lists
        'deutsche telekom root ca 1' while the server presents
        'Telekom Security ServerID OV Class 2 CA (Deutsche Telekom Security GmbH)'.
        """
        # Extract words from the *raw* names (spaces preserved) so that e.g.
        # 'Telekom Security ... (Deutsche Telekom Security GmbH)' yields real words
        # rather than one long normalized blob.
        name_words = set(_meaningful_words(name))
        if not name_words:
            return False, None

        best_entry: Optional[str] = None
        best_score = 0.0
        for raw in self._names:
            entry_words = set(_meaningful_words(raw))
            shared = name_words & entry_words
            if not shared:
                continue
            score = len(shared) / max(1, min(len(name_words), len(entry_words)))
            # A single very distinctive word (>= 8 chars) is enough on its own.
            if len(shared) == 1 and max(map(len, shared)) >= 8:
                score = max(score, 0.6)
            if score > best_score:
                best_score = score
                best_entry = raw

        # Require a meaningful overlap: at least ~60% of the smaller word set,
        # or two+ shared words.
        if best_entry is not None and (best_score >= 0.6 or len(name_words & set(_meaningful_words(best_entry))) >= 2):
            return True, best_entry
        return False, None


def _fetch_mimecast_names(url: str) -> list[str]:
    """Fetch the article and extract the 'Supported SSL Certificates' name list."""
    resp = requests.get(url, headers=HTTP_HEADERS, timeout=30)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")

    # Locate the heading that introduces the supported-certificate list.
    start_idx = None
    headings = soup.find_all(["h1", "h2", "h3", "h4"])
    for i, h in enumerate(headings):
        if re.search(r"supported\s+ssl\s+certificates", h.get_text(), re.I):
            start_idx = i
            break

    # Collect list items / table cells after that heading until the next section.
    names: list[str] = []
    if start_idx is not None:
        # Walk forward from the heading, collecting list items / table cells until
        # the next section heading appears.
        node = headings[start_idx].find_next()
        while node is not None:
            if node.name in ("h1", "h2", "h3", "h4"):
                break  # reached the next section
            if node.name in ("li", "td"):
                text = node.get_text(" ", strip=True)
                if _looks_like_cert_name(text):
                    names.append(text)
            node = node.find_next()

    # Fallback: if the structural walk found nothing, scan all list items on the page.
    if len(names) < 10:
        names = []
        for li in soup.find_all("li"):
            text = li.get_text(" ", strip=True)
            if _looks_like_cert_name(text):
                names.append(text)

    # De-duplicate preserving order.
    seen = set()
    out = []
    for n in names:
        key = _normalize(n)
        if key and key not in seen:
            seen.add(key)
            out.append(n)
    return out


def _looks_like_cert_name(text: str) -> bool:
    """Heuristic: a supported-cert list entry is short, lowercase-ish, CA-like."""
    t = text.strip()
    if len(t) < 4 or len(t) > 120:
        return False
    # Must contain letters.
    if not re.search(r"[a-z]", t, re.I):
        return False
    # Should look certificate/CA related OR be a known CA brand token.
    ca_hint = re.search(
        r"(root|certificat|ca\b|\bca$|trust|ssl|tls|secure server|authentication)",
        t, re.I,
    )
    brand = re.search(
        r"\b(digi|sectigo|comodo|globalsign|global sign|geotrust|thawte|verisign|"
        r"entrust|swiss|baltimore|addtrust|certplus|quovadis|starfield|godaddy|"
        r"go daddy|microsof|aol|america online|deutsche|eunet|harica|iden|let's? encrypt)\b",
        t, re.I,
    )
    return bool(ca_hint or brand)


def _normalize(s: str) -> str:
    """Lowercase and strip everything but alphanumerics for robust comparison."""
    s = s.lower()
    s = s.replace("&", "and")
    s = re.sub(r"[^a-z0-9]+", "", s)
    return s


def _family_token(norm: str) -> Optional[str]:
    """Leading brand token of a normalized name, e.g. 'digicert' from 'digicertglobalrootca'."""
    m = re.match(r"([a-z]{4,})", norm or "")
    if not m:
        return None
    token = m.group(1)
    # Trim to the brand core (first 8 chars is enough to separate brands).
    return token[:8]


# Words that carry no CA-brand meaning and are ignored for partial matching.
_PARTIAL_GENERIC = {
    "the", "and", "for", "class", "level", "secure", "server", "public",
    "primary", "global", "root", "certificat", "certificate", "ca",
    "trust", "trusted", "authentication", "deutsche", "services",
    # Certificate/attribute noise that appears in DN-style entries.
    "ou", "o", "c", "st", "l", "cn", "gte", "solutions", "gmbh", "ag",
    "security", "serverid", "ov", "email", "mail", "group", "cybertrust",
    # Generic CA-role words that appear across many unrelated CAs.
    "authority", "certification", "assurance", "assured", "intermediate",
    "signing", "ssl", "tls", "id", "x3", "x1", "x2", "g2", "g3",
}


def _meaningful_words(name: str) -> list[str]:
    """Meaningful (non-generic) words from a CA name.

    Operates on the raw, space-separated name so that multi-word names yield real
    tokens. Lowercases and pulls out runs of letters/digits of length >= 3.
    """
    return [w for w in re.findall(r"[a-z0-9]{3,}", (name or "").lower()) if w not in _PARTIAL_GENERIC]


def _brand_token(norm: str) -> Optional[str]:
    """A meaningful CA-brand token from a normalized name.

    Strips generic leading words (deutsche, global, root, ...) so that e.g.
    'deutschetelekomrootca1' yields the brand 'telekom'. Returns None if nothing
    meaningful remains.
    """
    GENERIC = {
        "the", "and", "for", "class", "level", "secure", "server", "public",
        "primary", "global", "root", "certificat", "certificate", "ca",
        "trust", "trusted", "authentication", "deutsche", "services",
    }
    m = re.match(r"([a-z]{4,})", norm or "")
    if not m:
        return None
    token = m.group(1)
    # If the leading word is generic (e.g. 'deutsche'), try to grab the next word.
    words = re.findall(r"[a-z]{3,}", norm or "")
    for w in words:
        if w not in GENERIC and len(w) >= 5:
            return w
    # Fall back to the leading token if it's long enough and non-generic.
    if token not in GENERIC and len(token) >= 5:
        return token[:8]
    return None


mimecast_list = MimecastList()


# --------------------------------------------------------------------------- #
# DNS + TLS inspection                                                        #
# --------------------------------------------------------------------------- #
@dataclass
class HostResult:
    host: str
    priority: int
    status: str  # "ok" | "error"
    matched: bool = False
    partial_matched: bool = False
    root_ca: Optional[str] = None
    leaf_cn: Optional[str] = None
    valid_until: Optional[str] = None
    matched_entry: Optional[str] = None
    partial_entry: Optional[str] = None
    port_used: Optional[int] = None
    error: Optional[str] = None
    details: list[dict] = field(default_factory=list)


def resolve_mx(domain: str) -> list[tuple[int, str]]:
    """Return [(priority, hostname)] for the domain's MX records.

    dns.resolver.resolve(..., 'MX') returns a single MXRecord whose items are
    (preference, exchange) pairs.
    """
    answers = dns.resolver.resolve(domain, "MX")
    mxs = []
    for r in answers:
        pref = int(r.preference)
        exch = r.exchange.decode().rstrip(".") if isinstance(r.exchange, bytes) else str(r.exchange).rstrip(".")
        mxs.append((pref, exch))
    return sorted(mxs)


def _get_cn(cert: x509.Certificate) -> Optional[str]:
    try:
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if attrs:
            return str(attrs[0].value)
    except Exception:
        pass
    return None


def _valid_until(leaf: x509.Certificate) -> Optional[str]:
    """Return the leaf certificate's not-after date as a readable UTC string."""
    try:
        dt = leaf.not_valid_after_utc
    except AttributeError:
        # cryptography < 42 fallback (naive, treated as UTC)
        dt = leaf.not_valid_after.replace(tzinfo=None)
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def _subject_str(cert: x509.Certificate) -> str:
    parts = []
    for oid, value in cert.subject.items():
        try:
            name = oid._name  # type: ignore[attr-defined]
        except Exception:
            name = str(oid)
        parts.append(f"{name}={value}")
    return ", ".join(parts)


def _is_self_signed(cert: x509.Certificate) -> bool:
    try:
        return cert.subject == cert.issuer
    except Exception:
        return False


def inspect_host(host: str, priority: int) -> HostResult:
    """Connect to an MX host over SMTP/TLS and capture its certificate chain."""
    result = HostResult(host=host, priority=priority, status="error")

    # Resolve the hostname (MX entries are already FQDNs).
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except Exception as exc:
        result.error = f"DNS resolution failed for {host}: {exc}"
        return result

    ip = infos[0][4][0]

    # Try STARTTLS on port 25 first; fall back to implicit TLS on 465.
    for port, mode in ((25, "starttls"), (465, "implicit")):
        try:
            chain = _connect_and_get_chain(ip, host, port, mode)
        except Exception as exc:
            result.error = f"port {port} ({mode}): {exc}"
            continue

        if not chain:
            result.error = f"No certificate presented on port {port} ({mode})"
            continue

        root_ca, leaf_cn, derived = _identify_root(chain)
        valid_until = _valid_until(chain[0])
        matched, entry = mimecast_list.match(root_ca)
        partial_matched, partial_entry = (False, None)
        if not matched:
            partial_matched, partial_entry = mimecast_list.match_partial(root_ca)

        result.status = "ok"
        result.port_used = port
        result.root_ca = root_ca
        result.leaf_cn = leaf_cn
        result.valid_until = valid_until
        result.matched = matched
        result.matched_entry = entry
        result.partial_matched = partial_matched
        result.partial_entry = partial_entry
        result.details = _build_cert_details(chain, host)
        if derived:
            result.error = (
                f"Note: server did not send the root certificate; "
                f"'{root_ca}' was derived from the chain's issuer."
            )
        return result

    # All ports failed.
    result.status = "error"
    return result


def _connect_and_get_chain(ip: str, host: str, port: int, mode: str) -> list[x509.Certificate]:
    """Open a TLS connection and return the presented certificate chain.

    The full peer chain (leaf + intermediates + root if sent) is captured via an
    ``ssl.SSLContext.verify_callback``, which OpenSSL invokes for every certificate in
    the chain during the handshake. This works on Python 3.10+ / OpenSSL 1.1.0+ where
    ``SSLSocket.get_unverified_chain()`` (a 3.13+ feature) is unavailable.
    """
    ctx = ssl.create_default_context()
    # We want to *inspect* the chain, not necessarily validate it. Disable hostname
    # checking so we can still read certs from servers with mismatched names, but keep
    # CA validation off as well since self-signed / odd chains are common on mail.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    captured: list[bytes] = []

    def _on_verify(depth: int, der_cert: bytes) -> bool:
        # Record every certificate OpenSSL presents during verification. Returning
        # True keeps the handshake going even for untrusted/self-signed certs.
        try:
            captured.append(der_cert)
        except Exception:
            pass
        return True

    ctx.verify_callback = _on_verify

    raw = socket.create_connection((ip, port), timeout=15)
    try:
        if mode == "starttls":
            # Minimal SMTP handshake to trigger STARTTLS.
            _expect(raw, 220)
            raw.sendall(b"EHLO checktls.local\r\n")
            _expect(raw, 250)  # consume the (possibly multi-line) EHLO reply
            raw.sendall(b"STARTTLS\r\n")
            _expect(raw, 220)
        tls = ctx.wrap_socket(raw, server_hostname=host)

        chain: list[x509.Certificate] = []
        for der in captured:
            try:
                chain.append(x509.load_der_x509_certificate(der))
            except Exception:
                continue
        # Fallback to the leaf only if the callback captured nothing.
        if not chain:
            der_leaf = tls.getpeercert(binary_form=True)
            if der_leaf:
                try:
                    chain.append(x509.load_der_x509_certificate(der_leaf))
                except Exception:
                    pass
        return chain
    finally:
        raw.close()


def _expect(raw: socket.socket, code: int) -> None:
    """Read SMTP response lines until a final (single-space) line with the given code.

    A multi-line SMTP reply ends with ``<code> <space> text``; continuation lines use
    ``<code>-text``. We read byte-by-byte into complete CRLF-terminated lines and stop
    at the first final line whose code matches.
    """
    buf = b""
    while True:
        chunk = raw.recv(4096)
        if not chunk:
            break
        buf += chunk
        # Process every complete line currently in the buffer.
        while b"\r\n" in buf:
            line, buf = buf.split(b"\r\n", 1)
            text = line.decode(errors="ignore")
            parts = text.split(" ", 1)
            if len(parts) >= 2 and parts[0] == str(code):
                return
        # If the buffer is getting large without a match, keep reading.


def _der_to_pem(der: bytes) -> bytes:
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return ("-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n").encode()


def _identify_root(chain: list[x509.Certificate]) -> tuple[str, Optional[str], bool]:
    """Return (root_ca_name, leaf_cn, derived_flag)."""
    if not chain:
        return "unknown", None, False

    leaf = chain[0]
    leaf_cn = _get_cn(leaf)

    # If the last cert in the presented chain is self-signed, it IS the root.
    last = chain[-1]
    if len(chain) > 1 and _is_self_signed(last):
        return (_get_cn(last) or _subject_str(last)), leaf_cn, False

    # Otherwise derive the root from the topmost cert's issuer (server omitted the root).
    # Prefer a readable "CN (O)" form over just the CN so family matching has more to work with.
    issuer_name = last.issuer
    cn = None
    org = None
    try:
        c = issuer_name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if c:
            cn = str(c[0].value)
        o = issuer_name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if o:
            org = str(o[0].value)
    except Exception:
        pass
    if cn and org:
        derived_name = f"{cn} ({org})"
    elif cn:
        derived_name = cn
    else:
        derived_name = _name_to_str(issuer_name)
    return derived_name, leaf_cn, True


def _name_to_str(name: x509.Name) -> str:
    parts = []
    for attr in name:
        try:
            label = attr.oid._name  # type: ignore[attr-defined]
        except Exception:
            label = str(attr.oid)
        parts.append(f"{label}={attr.value}")
    return ", ".join(parts)


# Short labels for the common name-attribute OIDs, used in the slash-style DN.
_OID_SHORT_LABELS = {
    NameOID.COUNTRY_NAME: "C",
    NameOID.STATE_OR_PROVINCE_NAME: "ST",
    NameOID.LOCALITY_NAME: "L",
    NameOID.ORGANIZATION_NAME: "O",
    NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
    NameOID.COMMON_NAME: "CN",
}


def _name_to_slash_str(name: x509.Name) -> str:
    """Render a name in the classic ``/C=DE/O=.../CN=...`` form."""
    parts = []
    for attr in name:
        label = _OID_SHORT_LABELS.get(attr.oid)
        if label is None:
            try:
                label = attr.oid._name  # type: ignore[attr-defined]
            except Exception:
                label = str(attr.oid)
        parts.append(f"{label}={attr.value}")
    return "/" + "/".join(parts) if parts else ""


def _ocsp_status(cert: x509.Certificate, issuer_cert: Optional[x509.Certificate]) -> str:
    """Best-effort OCSP revocation check.

    Returns a short human-readable status string. Falls back to 'unknown' when no
    OCSP responder is configured or the lookup fails (mail servers commonly omit it).
    """
    try:
        ocsp_ext = cert.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess
        ).value
        urls = [u for t, u in ocsp_ext if t == x509.oid.AuthorityInformationAccessOID.OCSP]
    except Exception:
        return "OCSP status unknown (no OCSP responder configured)"
    if not urls or issuer_cert is None:
        return "OCSP status unknown (no OCSP responder configured)"

    try:
        from cryptography.hazmat.primitives.serialization import Encoding
        ocsp_req = (
            x509.ocsp.OCSPRequestBuilder()
            .add_certificate(cert, issuer_cert)
            .build()
        )
        resp_bytes = requests.get(
            urls[0],
            data=ocsp_req.public_bytes(Encoding.DER),
            headers={"Content-Type": "application/ocsp-request"},
            timeout=8,
        ).content
        ocsp_resp = x509.load_der_ocsp_response(resp_bytes)
        status = ocsp_resp.certificate_status
        if status == x509.OCSPResponseStatus.SUCCESSFUL:
            cert_status = ocsp_resp.certifications[0].cert_status
            if cert_status == x509.OCSPCertStatus.GOOD:
                return "cert not revoked by OCSP"
            if cert_status == x509.OCSPCertStatus.REVOKED:
                return "cert REVOKED by OCSP"
            return f"OCSP status: {cert_status}"
        return f"OCSP response status: {status}"
    except Exception:
        return "OCSP status unknown (lookup failed)"


# --------------------------------------------------------------------------- #
# HTTP routes                                                                 #
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json(silent=True) or {}
    domain = (data.get("domain") or "").strip().lower()
    if not domain:
        return jsonify({"error": "Please enter a domain."}), 400

    # Make sure the Mimecast list is fresh before matching.
    try:
        mimecast_list.refresh_if_stale()
    except Exception as exc:
        return jsonify({"error": f"Could not load Mimecast CA list: {exc}"}), 502

    try:
        mxs = resolve_mx(domain)
    except dns.resolver.NXDOMAIN:
        return jsonify({"domain": domain, "mx_count": 0, "hosts": [],
                        "error": f"No MX records found for {domain}."}), 200
    except Exception as exc:
        return jsonify({"domain": domain, "mx_count": 0, "hosts": [],
                        "error": f"DNS lookup failed: {exc}"}), 200

    if not mxs:
        return jsonify({"domain": domain, "mx_count": 0, "hosts": [],
                        "error": f"No MX records found for {domain}."}), 200

    hosts = []
    for priority, host in mxs:
        hr = inspect_host(host, priority)
        hosts.append({
            "host": hr.host,
            "priority": hr.priority,
            "status": hr.status,
            "matched": hr.matched,
            "root_ca": hr.root_ca,
            "leaf_cn": hr.leaf_cn,
            "valid_until": hr.valid_until,
            "partial_matched": hr.partial_matched,
            "partial_entry": hr.partial_entry,
            "matched_entry": hr.matched_entry,
            "details": hr.details,
            "port_used": hr.port_used,
            "error": hr.error,
        })

    return jsonify({
        "domain": domain,
        "mx_count": len(mxs),
        "mimecast_ca_count": mimecast_list.count,
        "hosts": hosts,
    })


def _build_ocsp_request(cert: x509.Certificate, issuer_cert: x509.Certificate) -> bytes:
    """DER-encode an OCSP request for ``cert`` issued by ``issuer_cert``."""
    req = (
        x509.ocsp.OCSPRequestBuilder()
        .add_certificate(cert, issuer_cert)
        .build()
    )
    from cryptography.hazmat.primitives.serialization import Encoding
    return req.public_bytes(Encoding.DER)


def _build_cert_details(chain: list[x509.Certificate], host: str) -> list[dict]:
    """Build per-certificate detail dicts for the collapsed DETAILS view."""
    now = dt_module.datetime.now(dt_module.timezone.utc)
    details = []
    total = len(chain)

    for idx, cert in enumerate(chain):
        try:
            not_before = cert.not_valid_before_utc
        except AttributeError:
            not_before = cert.not_valid_before.replace(tzinfo=dt_module.timezone.utc)
        try:
            not_after = cert.not_valid_after_utc
        except AttributeError:
            not_after = cert.not_valid_after.replace(tzinfo=dt_module.timezone.utc)

        seconds_until_expired = int((not_after - now).total_seconds())
        subject_cn = _get_cn(cert) or ""
        hostname_verified = bool(subject_cn and host.lower() == subject_cn.lower())

        # The issuer certificate is the next one in the presented chain (if any).
        issuer_cert = chain[idx + 1] if idx + 1 < total else None
        ocsp_text = _ocsp_status(cert, issuer_cert)

        details.append({
            "index": idx + 1,
            "total": total,
            "validated": "ok",
            "hostname_verified": hostname_verified,
            "host": host,
            "ocsp": ocsp_text,
            "not_valid_before": not_before.strftime("%b %d %H:%M:%S %Y GMT"),
            "not_valid_after": not_after.strftime("%b %d %H:%M:%S %Y GMT"),
            "seconds_until_expired": seconds_until_expired,
            "subject": _name_to_slash_str(cert.subject),
            "issuer": _name_to_slash_str(cert.issuer),
        })

    return details


# Bind address / port are configurable via environment so the same code runs
# locally (py app.py) and in a container or behind gunicorn.
HOST = os.environ.get("CHECKTLS_HOST", "0.0.0.0")
PORT = int(os.environ.get("CHECKTLS_PORT", "5000"))

if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=False)
