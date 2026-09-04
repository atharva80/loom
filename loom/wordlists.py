"""loom.wordlists — AssetNote (+SecLists) wordlist resolution.

Wordlists live OUTSIDE the repo (they're tens of MB). Resolution:
  1. $LOOM_WORDLISTS (explicit dir)
  2. /opt/tools/wordlists/assetnote (BB arsenal default)
  3. ~/BB/wordlists/assetnote

Stable filenames (decoupled from AssetNote's date stamps — create
once after download, e.g. `head -20000 httparchive_apiroutes_* >
api-routes-top20k.txt`; the lists are frequency-ordered so head
keeps the best entries):

  api-routes-top20k.txt   httparchive api routes, top 20k
  params-top25k.txt       httparchive params, top 25k (arjun -w)
  php-top15k.txt          httparchive php, top 15k
  aspx-top10k.txt         httparchive aspx/asp/cfm bundle, top 10k
  js-top10k.txt           httparchive js filenames, top 10k
  django/rails/laravel/express-top10k.txt
  flask.txt spring.txt zend.txt coldfusion.txt symfony.txt
  tomcat.txt yii.txt cherrypy.txt cgi_pl.txt xml.txt txt.txt
  jsp_jspa.txt (small, used whole)
  best-dns-wordlist.txt   subdomain brute (amass -brute -w)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

# (stable filename, purpose) — the full contract `loom validate`
# reports on.
EXPECTED_WORDLISTS: tuple[tuple[str, str], ...] = (
    ("api-routes-top20k.txt", "generic endpoint fuzz (ffuf fallback)"),
    ("params-top25k.txt", "arjun -w hidden-param discovery"),
    ("php-top15k.txt", "tech-gated fuzz: php"),
    ("aspx-top10k.txt", "tech-gated fuzz: asp.net/iis"),
    ("js-top10k.txt", "tech-gated fuzz: unlinked JS"),
    ("django-top10k.txt", "tech-gated fuzz: django"),
    ("rails-top10k.txt", "tech-gated fuzz: rails"),
    ("laravel-top10k.txt", "tech-gated fuzz: laravel"),
    ("express-top10k.txt", "tech-gated fuzz: nodejs/express"),
    ("flask.txt", "tech-gated fuzz: flask"),
    ("spring.txt", "tech-gated fuzz: spring/java"),
    ("zend.txt", "tech-gated fuzz: zend/php"),
    ("coldfusion.txt", "tech-gated fuzz: coldfusion"),
    ("symfony.txt", "tech-gated fuzz: symfony/php"),
    ("tomcat.txt", "tech-gated fuzz: tomcat/java"),
    ("yii.txt", "tech-gated fuzz: yii/php"),
    ("cherrypy.txt", "tech-gated fuzz: cherrypy/python"),
    ("cgi_pl.txt", "tech-gated fuzz: cgi/pl"),
    ("xml.txt", "tech-gated fuzz: xml files"),
    ("txt.txt", "tech-gated fuzz: txt files"),
    ("jsp_jspa.txt", "tech-gated fuzz: jsp/java"),
    ("best-dns-wordlist.txt", "subdomain brute full list (manual/opt-in)"),
    ("best-dns-top20k.txt", "subdomain brute (amass -brute -w default)"),
)

ARJUN_PARAMS_FILE = "params-top25k.txt"
API_ROUTES_FILE = "api-routes-top20k.txt"
# Top-20k slice of best-dns-wordlist.txt (9.5M, frequency-ordered).
# The full list stays on disk for manual/opt-in runs; the default
# amass-brute node uses the slice (bounded time, bounded noise).
BEST_DNS_FILE = "best-dns-top20k.txt"

# httpx tech substring → wordlist file. Keys mirror stages.TECH_TAGS
# matching (substring, lowercase).
TECH_WORDLISTS: dict[str, str] = {
    "php": "php-top15k.txt",
    "microsoft asp.net": "aspx-top10k.txt",
    "asp.net": "aspx-top10k.txt",
    "iis": "aspx-top10k.txt",
    "wordpress": "php-top15k.txt",
    "laravel": "laravel-top10k.txt",
    "symfony": "symfony.txt",
    "zend": "zend.txt",
    "django": "django-top10k.txt",
    "tomcat": "tomcat.txt",
    "java": "tomcat.txt",
    "spring": "spring.txt",
    "ruby": "rails-top10k.txt",
    "rails": "rails-top10k.txt",
    "node.js": "express-top10k.txt",
    "express": "express-top10k.txt",
    "flask": "flask.txt",
    "cherrypy": "cherrypy.txt",
    "coldfusion": "coldfusion.txt",
    "yii": "yii.txt",
    "cgi": "cgi_pl.txt",
}


def wordlist_dir() -> Path:
    """Resolve the wordlist directory (never raises)."""
    env = os.environ.get("LOOM_WORDLISTS", "")
    if env:
        return Path(env).expanduser()
    for cand in (
        Path("/opt/tools/wordlists/assetnote"),
        Path.home() / "BB" / "wordlists" / "assetnote",
    ):
        if cand.is_dir():
            return cand
    # Nothing on disk: return the primary default anyway so callers
    # get a deterministic path to report as missing.
    return Path("/opt/tools/wordlists/assetnote")


def _existing(name: str) -> Optional[Path]:
    p = wordlist_dir() / name
    return p if p.is_file() else None


def wordlist_for(techs: set[str],
                 tech_map: Optional[dict[str, str]] = None) -> Optional[Path]:
    """Tech-gated wordlist: first TECH_WORDLISTS hit wins, else the
    generic api-routes list, else None (caller falls back to SecLists
    common.txt). Matching is substring/lowercase like TECH_TAGS."""
    mapping = tech_map if tech_map is not None else TECH_WORDLISTS
    lowered = {str(t).lower() for t in techs}
    # Mapping order (not set order) so selection is deterministic.
    for key, fname in mapping.items():
        if any(key in tech for tech in lowered):
            hit = _existing(fname)
            if hit:
                return hit
    return _existing(API_ROUTES_FILE)


def arjun_params_wordlist() -> Optional[Path]:
    """Params wordlist for `arjun -w`, or None (arjun default)."""
    return _existing(ARJUN_PARAMS_FILE)


def best_dns_wordlist() -> Optional[Path]:
    """Subdomain-brute wordlist for `amass -brute -w`, or None."""
    return _existing(BEST_DNS_FILE)


def wordlist_status() -> tuple[list[str], list[str]]:
    """(present, missing) stable filenames for `loom validate`."""
    present, missing = [], []
    for fname, _purpose in EXPECTED_WORDLISTS:
        (present if _existing(fname) else missing).append(fname)
    return present, missing
