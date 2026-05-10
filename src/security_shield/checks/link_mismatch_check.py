# Hidden Link Detector: visible anchor text claims one domain, href points elsewhere.
import re
from urllib.parse import urlparse

from security_shield.backend.base_check import BaseCheck


# <a ... href = "..." ...> inner </a> — attrs allow extra whitespace; inner non-greedy
_ANCHOR_RE = re.compile(
    r"<a\s+(?P<attrs>[^>]*?)>(?P<inner>.*?)</a\s*>",
    re.IGNORECASE | re.DOTALL,
)

# href in attribute string: quoted or unquoted; whitespace around =
_HREF_IN_ATTRS_RE = re.compile(
    r"""href\s*=\s*(?:"(?P<dval>[^"]*)"|'(?P<sval>[^']*)'|(?P<uval>[^\s>]+))""",
    re.IGNORECASE,
)

# Domain-like tokens (unicode-friendly enough for ASCII phishing)
_DOMAIN_TOKEN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
    re.IGNORECASE,
)

# Loose URLs in visible text
_URL_IN_TEXT_RE = re.compile(
    r"https?://[^\s<>\'\"]+|//[^\s<>\'\"]+",
    re.IGNORECASE,
)


def _collapse_ws(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def _normalize_visible_for_domains(html_fragment: str) -> str:
    """Reduce common bypasses: extra spaces around . / : / @ in link text."""
    t = re.sub(r"<[^>]+>", " ", html_fragment)
    t = _collapse_ws(t)
    t = re.sub(r"\s*([.@:/])\s*", r"\1", t)
    return t


def _strip_www(host: str | None) -> str | None:
    if not host:
        return None
    h = host.lower().strip(".")
    if h.startswith("www."):
        h = h[4:]
    return h


def _href_to_hostname(href: str | None) -> str | None:
    if href is None:
        return None
    raw = href.strip()
    if not raw or raw.startswith(("#", "javascript:", "data:", "mailto:", "tel:")):
        return None
    if raw.startswith("//"):
        raw = "http:" + raw
    if not re.match(r"^[a-z][a-z0-9+.-]*:", raw, re.I):
        raw = "http://" + raw
    try:
        parsed = urlparse(raw)
        return parsed.hostname
    except Exception:
        return None


def _extract_href_from_attrs(attrs: str) -> str | None:
    m = _HREF_IN_ATTRS_RE.search(attrs)
    if not m:
        return None
    return m.group("dval") or m.group("sval") or m.group("uval") or None


def _hosts_align(href_host: str, claimed: str) -> bool:
    """True if href host is the same site as claimed (www-insensitive, subdomain OK)."""
    a = _strip_www(href_host)
    b = _strip_www(claimed)
    if not a or not b:
        return True
    if a == b:
        return True
    if a.endswith("." + b):
        return True
    return False


def _domains_from_visible(visible: str) -> set[str]:
    out: set[str] = set()
    norm = _normalize_visible_for_domains(visible)
    for m in _DOMAIN_TOKEN_RE.finditer(norm):
        out.add(m.group(0).lower())
    for m in _URL_IN_TEXT_RE.finditer(norm):
        h = _href_to_hostname(m.group(0))
        if h:
            out.add(h.lower())
    return out


class LinkMismatchCheck(BaseCheck):
    @property
    def name(self):
        return "HIDDEN_LINK_MISMATCH"

    @property
    def is_active(self):
        return True

    @property
    def description(self):
        return (
            "Detects anchor text that shows a trusted-looking domain or URL while "
            "the href targets a different host."
        )

    def run(self, email_data):
        html = email_data.get("htmlBody") or email_data.get("html_body") or ""
        if not html or "<a" not in html.lower():
            return False, 0

        for m in _ANCHOR_RE.finditer(html):
            attrs = m.group("attrs")
            inner = m.group("inner")
            href_raw = _extract_href_from_attrs(attrs)
            href_host = _href_to_hostname(href_raw)
            if not href_host:
                continue

            claimed_domains = _domains_from_visible(inner)
            if not claimed_domains:
                continue

            for claimed in claimed_domains:
                c_host = _strip_www(claimed) or claimed
                if not _hosts_align(href_host, c_host):
                    return True, 8

        return False, 0
