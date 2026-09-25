"""Bulk, credential-free attention inventories collected once per edition.

Each source returns compact rows plus provenance. Every source is optional:
failures, skipped live-only sources, and budget exhaustion stay explicit so a
missing inventory is never read as zero attention. Nothing here asks a model
for popularity; matching and scoring live in ``attention_match``/``attention``.
"""
from __future__ import annotations

import base64
import concurrent.futures as cf
import csv
import email.utils
import fcntl
import gzip
import hashlib
import html
import io
import json
import os
import re
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
import zipfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

import requests

SNAPSHOT_SCHEMA_VERSION = 1
USER_AGENT = "CarterDailyNews/1.0 (+https://news.carter2099.com)"
WINDOW_HOURS = 30
COLLECTION_BUDGET_SECONDS = 240.0
REQUEST_TIMEOUT_SECONDS = 30.0
MAX_RESPONSE_BYTES = 24 * 1024 * 1024
# Live-only inventories describe "now"; they cannot observe a window that ended
# long before collection (a resumed or backfilled edition).
LIVE_SOURCE_MAX_LAG_SECONDS = 3 * 3600
JETSTREAM_RETENTION_SECONDS = 35 * 3600
JETSTREAM_HOSTS = (
    "jetstream1.us-east.bsky.network",
    "jetstream2.us-east.bsky.network",
    "jetstream1.us-west.bsky.network",
    "jetstream2.us-west.bsky.network",
)
JETSTREAM_SLICES = 24
JETSTREAM_SLICE_SECONDS = 240
JETSTREAM_PARALLEL = 8
JETSTREAM_MAX_MESSAGE_BYTES = 4 * 1024 * 1024
GKG_PARALLEL = 8
PANEL_PARALLEL = 16
SNAPSHOT_KEEP_EDITIONS = 3
RETRY_FAILED_WITHIN_SECONDS = 4 * 3600
# Collection attempts per source and edition: the build, one immediate retry, one later retry.
MAX_SOURCE_ATTEMPTS = 3
RETRY_STATUSES = frozenset({"unavailable", "partial"})
_STATUS_RANK = {"unavailable": 0, "partial": 1, "ok": 2}
# GDELT publishes each 15-minute GKG file minutes after its stamp; a window ending on a quarter
# hour at least this old never mistakes a not-yet-published trailing file for a gap.
WINDOW_SETTLE_SECONDS = 1800
SOURCES = (
    "gkg", "panel", "jetstream", "hn", "techmeme", "kagi", "mastodon", "bsky_trends", "wikipedia",
)
LIVE_ONLY_SOURCES = frozenset({"panel", "techmeme", "mastodon", "bsky_trends"})

# Publisher panel: news sitemaps (48-hour census; discovered through robots.txt
# unless an explicit URL is known) plus RSS/Atom feeds for publishers without one.
PANEL_SITEMAPS: dict[str, str | None] = {
    "reuters.com": "https://www.reuters.com/arc/outboundfeeds/news-sitemap/?outputType=xml",
    "bbc.com": None, "theguardian.com": None, "nytimes.com": None, "cnn.com": None,
    "aljazeera.com": None, "france24.com": None, "theverge.com": None, "techcrunch.com": None,
    "wired.com": None, "zdnet.com": None, "businessinsider.com": None, "tomshardware.com": None,
    "theinformation.com": None, "windowscentral.com": None, "xda-developers.com": None,
    "ign.com": None, "kotaku.com": None, "pcgamer.com": None, "polygon.com": None,
    "eurogamer.net": None, "gamesradar.com": None, "rockpapershotgun.com": None,
    "gamedeveloper.com": None, "dexerto.com": None,
}
PANEL_FEEDS: dict[str, str] = {
    "arstechnica.com": "https://feeds.arstechnica.com/arstechnica/index",
    "theregister.com": "https://www.theregister.com/headlines.atom",
    "siliconangle.com": "https://siliconangle.com/feed/",
    "datacenterdynamics.com": "https://www.datacenterdynamics.com/en/rss/",
    "wccftech.com": "https://wccftech.com/feed/",
    "macrumors.com": "https://feeds.macrumors.com/MacRumors-All",
    "engadget.com": "https://www.engadget.com/rss.xml",
    "nintendolife.com": "https://www.nintendolife.com/feeds/latest",
    "pushsquare.com": "https://www.pushsquare.com/feeds/latest",
    "purexbox.com": "https://www.purexbox.com/feeds/latest",
    "gematsu.com": "https://www.gematsu.com/feed",
    "videogameschronicle.com": "https://www.videogameschronicle.com/feed/",
    "gamespot.com": "https://www.gamespot.com/feeds/news/",
    "axios.com": "https://api.axios.com/feed/",
    "politico.com": "https://rss.politico.com/politics-news.xml",
    "dw.com": "https://rss.dw.com/rdf/rss-en-all",
    "abc.net.au": "https://www.abc.net.au/news/feed/51120/rss.xml",
    "npr.org": "https://feeds.npr.org/1001/rss.xml",
    "thehill.com": "https://thehill.com/feed/",
    "news.sky.com": "https://feeds.skynews.com/feeds/rss/world.xml",
    "cbsnews.com": "https://www.cbsnews.com/latest/rss/main",
    "abcnews.go.com": "https://abcnews.go.com/abcnews/topstories",
    "fortune.com": "https://fortune.com/feed/",
    "the-decoder.com": "https://the-decoder.com/feed/",
    "hpcwire.com": "https://www.hpcwire.com/feed/",
    "nextplatform.com": "https://www.nextplatform.com/feed/",
    "servethehome.com": "https://www.servethehome.com/feed/",
    "eetimes.com": "https://www.eetimes.com/feed/",
    "neowin.net": "https://www.neowin.net/news/rss/",
    "9to5google.com": "https://9to5google.com/feed/",
    "gizmodo.com": "https://gizmodo.com/feed",
    "cnet.com": "https://www.cnet.com/rss/news/",
    "pcworld.com": "https://www.pcworld.com/feed",
    "cnbc.com": "https://search.cnbc.com/rs/search/combinedcms/view.xml?partnerId=wrss01&id=100003114",
    "bloomberg.com": "https://feeds.bloomberg.com/technology/news.rss",
    "wsj.com": "https://feeds.content.dowjones.io/public/rss/RSSWorldNews",
    "semafor.com": "https://www.semafor.com/rss.xml",
    "techradar.com": "https://www.techradar.com/rss",
    "tweaktown.com": "https://www.tweaktown.com/news-feed/",
    "androidauthority.com": "https://www.androidauthority.com/feed/",
}
MASTODON_INSTANCES = (
    "mastodon.social", "mstdn.social", "mas.to", "fosstodon.org", "hachyderm.io",
    "infosec.exchange", "mastodon.world", "techhub.social", "universeodon.com",
    "mastodon.online", "mstdn.ca", "aus.social",
)
KAGI_CATEGORIES = frozenset({"world", "usa", "tech", "ai", "gaming", "science", "business"})
WIKIPEDIA_SKIP_PREFIXES = (
    "Main_Page", "Special:", "Wikipedia:", "Portal:", "File:", "Help:", "Talk:", "User:",
    "Template:", "Category:", "Deaths_in_",
)

Row = dict[str, Any]
Collector = Callable[["_Context"], tuple[list[Row], dict[str, Any]]]


class SourceSkipped(Exception):
    """The source cannot observe the requested window; it is not a failure."""


class _Context:
    """Window, deadline, and HTTP helpers shared by one collection."""

    def __init__(
        self,
        window_start: datetime,
        window_end: datetime,
        deadline: float,
        clock: Callable[[], float],
        now: datetime,
    ) -> None:
        self.window_start = window_start
        self.window_end = window_end
        self.start_s = int(window_start.timestamp())
        self.end_s = int(window_end.timestamp())
        self.deadline = deadline
        self.clock = clock
        self.now = now
        self._local = threading.local()

    def remaining(self) -> float:
        return self.deadline - self.clock()

    def session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is None:
            session = requests.Session()
            session.headers["User-Agent"] = USER_AGENT
            self._local.session = session
        return session

    def get(self, url: str, *, params: dict[str, Any] | None = None) -> tuple[int, bytes]:
        """GET with a timeout bounded by the collection deadline and a size cap."""
        remaining = self.remaining()
        if remaining <= 1.0:
            raise TimeoutError("attention snapshot budget exhausted")
        timeout = min(REQUEST_TIMEOUT_SECONDS, remaining)
        with self.session().get(
            url, params=params, timeout=(min(10.0, timeout), timeout), stream=True,
        ) as response:
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(65536):
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise ValueError(f"response exceeded {MAX_RESPONSE_BYTES} bytes")
                if self.clock() > self.deadline:
                    raise TimeoutError("attention snapshot budget exhausted")
                chunks.append(chunk)
            return response.status_code, b"".join(chunks)

    def get_ok(self, url: str, *, params: dict[str, Any] | None = None) -> bytes:
        status, body = self.get(url, params=params)
        if status != 200:
            raise RuntimeError(f"HTTP {status}")
        return body


def _clean(value: Any) -> str:
    return " ".join(html.unescape(str(value or "")).split())


def _domain(url: str) -> str:
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""
    return host[4:] if host.startswith("www.") else host


def _parse_time(value: Any) -> int | None:
    text = _clean(value)
    if not text:
        return None
    try:
        return int(email.utils.parsedate_to_datetime(text).timestamp())
    except (TypeError, ValueError, IndexError, OverflowError):
        pass
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


# ---------------------------------------------------------------- pure parsers

def parse_gkg_archive(data: bytes) -> list[Row]:
    """Rows (time, domain, url, page title) from one GDELT GKG 2.1 15-minute zip."""
    csv.field_size_limit(sys.maxsize)
    rows: list[Row] = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for name in archive.namelist():
            # Stream the member: a 15-minute file expands to ~20 MB of mostly unused fields.
            stream = io.TextIOWrapper(archive.open(name), encoding="utf-8", errors="replace", newline="")
            for record in csv.reader(stream, delimiter="\t", quoting=csv.QUOTE_NONE):
                if len(record) < 27:
                    continue
                match = re.search(r"<PAGE_TITLE>(.*?)</PAGE_TITLE>", record[26])
                title = _clean(match.group(1)) if match else ""
                if not title or not record[4].startswith("http"):
                    continue
                try:
                    stamp = datetime.strptime(record[1], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
                rows.append({
                    "src": "gkg", "t": int(stamp.timestamp()), "domain": record[3].lower(),
                    "url": record[4], "title": title,
                })
    return rows


def parse_news_sitemap(body: bytes, domain: str) -> tuple[list[Row], list[str]]:
    """Return (article rows, child sitemap URLs) from a Google News sitemap or index."""
    if body[:2] == b"\x1f\x8b":
        body = gzip.decompress(body)
    root = ET.fromstring(body)
    if _local(root.tag) == "sitemapindex":
        return [], [(element.text or "").strip() for element in root.iter() if _local(element.tag) == "loc"]
    rows: list[Row] = []
    for entry in root:
        location = title = published = None
        for element in entry.iter():
            tag = _local(element.tag)
            if tag == "loc" and location is None:
                location = (element.text or "").strip()
            elif tag == "title" and title is None:
                title = _clean(element.text)
            elif tag == "publication_date" and published is None:
                published = element.text
        if location and title:
            rows.append({"src": "panel", "domain": domain, "url": location, "title": title,
                         "t": _parse_time(published)})
    return rows, []


def parse_feed(body: bytes, domain: str) -> list[Row]:
    """Rows from an RSS 2.0, RDF, or Atom feed."""
    root = ET.fromstring(body)
    rows: list[Row] = []
    for item in root.iter():
        if _local(item.tag) not in ("item", "entry"):
            continue
        title = link = published = None
        for element in item:
            tag = _local(element.tag)
            if tag == "title":
                title = _clean("".join(element.itertext()))
            elif tag == "link":
                link = (element.get("href") or element.text or "").strip() or link
            elif tag in ("pubDate", "published", "updated", "date") and not published:
                published = element.text
        if title and link:
            rows.append({"src": "panel", "domain": domain, "url": link, "title": title,
                         "t": _parse_time(published)})
    return rows


def parse_techmeme(page: str) -> list[Row]:
    """Front-page clusters: headline link, rank, headline size, and 'More' coverage links."""
    rows: list[Row] = []
    rank = 0
    for part in re.split(r'<DIV CLASS="clus">', page)[1:]:
        head = re.search(
            r'<STRONG CLASS="L(\d)"><A CLASS="ourh" HREF="([^"]+)">(.*?)</A></STRONG>', part, re.S,
        )
        if not head:
            continue
        rank += 1
        more_block = re.search(
            r'<SPAN CLASS="drhed">More:</SPAN>&nbsp;<span class="bls">(.*?)</span>', part, re.S,
        )
        more = re.findall(r'<A HREF="([^"]+)">', more_block.group(1)) if more_block else []
        discussion = 0
        for label in ("X", "Bluesky", "Threads", "LinkedIn", "Forums", "Mastodon"):
            block = re.search(rf'<SPAN CLASS="drhed">{label}:</SPAN>(.*?)</DIV>', part, re.S)
            if block:
                discussion += len(re.findall(r"<A ", block.group(1)))
        rows.append({
            "src": "techmeme", "rank": rank, "size": int(head.group(1)),
            "url": html.unescape(head.group(2)),
            "title": _clean(re.sub(r"<[^>]+>", "", head.group(3))),
            "more": [html.unescape(link) for link in more], "disc": discussion,
        })
    return rows


def link_post_row(event: dict[str, Any]) -> Row | None:
    """A Bluesky post that shares at least one external link, with a hashed author."""
    commit = event.get("commit") or {}
    if commit.get("operation") != "create" or commit.get("collection") != "app.bsky.feed.post":
        return None
    record = commit.get("record") or {}
    uris: set[str] = set()
    title = description = ""
    embed = record.get("embed") or {}
    for candidate in (embed, embed.get("media") or {}):
        if candidate.get("$type") == "app.bsky.embed.external":
            external = candidate.get("external") or {}
            if str(external.get("uri", "")).startswith("http"):
                uris.add(external["uri"])
            title = _clean(external.get("title"))[:300]
            description = _clean(external.get("description"))[:300]
    for facet in record.get("facets") or []:
        for feature in facet.get("features") or []:
            if feature.get("$type") == "app.bsky.richtext.facet#link":
                uri = str(feature.get("uri", ""))
                if uri.startswith("http"):
                    uris.add(uri)
    if not uris:
        return None
    did = str(event.get("did") or "")
    return {
        "src": "jetstream", "t": int(event.get("time_us", 0)) // 1_000_000,
        "author": hashlib.sha256(did.encode()).hexdigest()[:16],
        "urls": sorted(uris)[:8], "url": sorted(uris)[0],
        "title": title, "text": _clean(f"{description} {_clean(record.get('text'))[:300]}"),
    }


# ---------------------------------------------------------------- collectors

def _gkg_stamps(ctx: _Context) -> list[str]:
    stamps = []
    t = ctx.start_s - (ctx.start_s % 900)
    while t < ctx.end_s:
        stamps.append(datetime.fromtimestamp(t, timezone.utc).strftime("%Y%m%d%H%M%S"))
        t += 900
    return stamps


def collect_gkg(ctx: _Context) -> tuple[list[Row], dict[str, Any]]:
    stamps = _gkg_stamps(ctx)
    missing: list[str] = []
    rows: list[Row] = []
    downloaded = 0

    def one(stamp: str) -> tuple[str, list[Row], int]:
        status, body = ctx.get(f"https://data.gdeltproject.org/gdeltv2/{stamp}.gkg.csv.zip")
        if status != 200:
            return stamp, [], -status
        return stamp, parse_gkg_archive(body), len(body)

    with cf.ThreadPoolExecutor(GKG_PARALLEL) as pool:
        for stamp, parsed, size in pool.map(one, stamps):
            if size < 0:
                missing.append(stamp)
                continue
            downloaded += size
            rows.extend(row for row in parsed if ctx.start_s <= row["t"] < ctx.end_s)
    if stamps and len(missing) == len(stamps):
        raise RuntimeError("no GKG files were available for the window")
    meta = {"files": len(stamps), "missing_files": len(missing), "downloaded_bytes": downloaded,
            "domains": len({row["domain"] for row in rows})}
    if missing:
        meta["incomplete"] = f"{len(missing)} of {len(stamps)} GKG files unavailable"
    return rows, meta


def _panel_publisher(ctx: _Context, domain: str, kind: str, url: str | None) -> list[Row]:
    if kind == "feed":
        return parse_feed(ctx.get_ok(url or ""), domain)
    candidates = [url] if url else []
    if not candidates:
        status, robots = ctx.get(f"https://www.{domain}/robots.txt")
        if status != 200:
            status, robots = ctx.get(f"https://{domain}/robots.txt")
        text = robots.decode("utf-8", "replace") if status == 200 else ""
        candidates = [
            link for link in re.findall(r"(?im)^\s*sitemap:\s*(\S+)", text)
            if re.search(r"news|google", link, re.I)
        ][:3]
    for sitemap in candidates:
        status, body = ctx.get(sitemap)
        if status != 200:
            continue
        rows, children = parse_news_sitemap(body, domain)
        for child in children[:2]:
            status, child_body = ctx.get(child)
            if status == 200:
                rows.extend(parse_news_sitemap(child_body, domain)[0])
            if rows:
                break
        if rows:
            return rows
    raise RuntimeError("no parseable news sitemap")


def collect_panel(ctx: _Context) -> tuple[list[Row], dict[str, Any]]:
    jobs = [(domain, "sitemap", url) for domain, url in PANEL_SITEMAPS.items()]
    jobs += [(domain, "feed", url) for domain, url in PANEL_FEEDS.items()]
    failed: dict[str, str] = {}
    rows: list[Row] = []

    def one(job: tuple[str, str, str | None]) -> tuple[str, list[Row] | None, str]:
        domain, kind, url = job
        try:
            return domain, _panel_publisher(ctx, domain, kind, url), ""
        except Exception as error:  # noqa: BLE001 - one publisher never fails the panel
            return domain, None, " ".join(str(error).split())[:120]

    with cf.ThreadPoolExecutor(PANEL_PARALLEL) as pool:
        for domain, parsed, error in pool.map(one, jobs):
            if parsed is None:
                failed[domain] = error
                continue
            rows.extend(row for row in parsed if row["t"] and ctx.start_s <= row["t"] < ctx.end_s)
    if len(failed) == len(jobs):
        raise RuntimeError("every panel publisher failed")
    meta: dict[str, Any] = {"publishers": len(jobs), "failed_publishers": failed}
    if failed:
        meta["incomplete"] = f"{len(failed)} of {len(jobs)} panel publishers failed"
    return rows, meta


class _WebSocket:
    """Minimal read-only RFC 6455 client (TLS) for the Jetstream firehose."""

    _GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, host: str, path: str, timeout: float) -> None:
        raw = socket.create_connection((host, 443), timeout=timeout)
        self.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        self.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nUser-Agent: {USER_AGENT}\r\n\r\n"
        ).encode())
        self.buffer = bytearray()
        while b"\r\n\r\n" not in self.buffer:
            chunk = self.sock.recv(4096)
            if not chunk or len(self.buffer) > 65536:
                raise ConnectionError("websocket handshake failed")
            self.buffer += chunk
        head, _, rest = bytes(self.buffer).partition(b"\r\n\r\n")
        self.buffer = bytearray(rest)
        accept = base64.b64encode(hashlib.sha1((key + self._GUID).encode()).digest())
        if b" 101 " not in head.split(b"\r\n", 1)[0] + b" " or accept not in head:
            raise ConnectionError("websocket upgrade was refused")
        self.offset = 0

    def _read(self, size: int) -> bytes:
        while len(self.buffer) - self.offset < size:
            chunk = self.sock.recv(max(65536, size))
            if not chunk:
                raise ConnectionError("websocket closed")
            if self.offset > 1 << 20:
                del self.buffer[:self.offset]
                self.offset = 0
            self.buffer += chunk
        data = bytes(self.buffer[self.offset:self.offset + size])
        self.offset += size
        return data

    def _send(self, opcode: int, payload: bytes) -> None:
        mask = os.urandom(4)
        size = len(payload)
        header = bytes([0x80 | opcode])
        if size < 126:
            header += bytes([0x80 | size])
        elif size < 65536:
            header += bytes([0x80 | 126]) + struct.pack("!H", size)
        else:
            header += bytes([0x80 | 127]) + struct.pack("!Q", size)
        self.sock.sendall(header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def messages(self):
        fragments: list[bytes] = []
        while True:
            first, second = self._read(2)
            opcode, size = first & 0x0F, second & 0x7F
            if size == 126:
                size = struct.unpack("!H", self._read(2))[0]
            elif size == 127:
                size = struct.unpack("!Q", self._read(8))[0]
            if size > JETSTREAM_MAX_MESSAGE_BYTES:
                raise ValueError("websocket message too large")
            mask = self._read(4) if second & 0x80 else b""
            payload = self._read(size)
            if mask:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if opcode == 0x8:
                return
            if opcode == 0x9:
                self._send(0xA, payload)
                continue
            if opcode in (0x0, 0x1, 0x2):
                fragments.append(payload)
                if first & 0x80:
                    yield b"".join(fragments)
                    fragments = []

    def close(self) -> None:
        try:
            self._send(0x8, b"")
        except OSError:
            pass
        self.sock.close()


_TIME_US = re.compile(rb'"time_us":(\d+)')


def _jetstream_slice(ctx: _Context, index: int, start_s: int, seconds: int) -> tuple[list[Row], int, float]:
    """Replay ``seconds`` of posts from ``start_s``; returns rows, posts seen, seconds covered."""
    end_us = (start_s + seconds) * 1_000_000
    last_error: Exception | None = None
    for attempt in range(2):
        rows: list[Row] = []
        seen = 0
        covered_to = start_s
        host = JETSTREAM_HOSTS[(index + attempt) % len(JETSTREAM_HOSTS)]
        remaining = ctx.remaining()
        if remaining <= 2.0:
            break
        try:
            stream = _WebSocket(
                host,
                f"/subscribe?wantedCollections=app.bsky.feed.post&cursor={start_s * 1_000_000}",
                timeout=min(30.0, remaining),
            )
        except (OSError, ConnectionError, ValueError) as error:
            last_error = error
            continue
        try:
            for message in stream.messages():
                stamp = _TIME_US.search(message)
                if stamp:
                    stamp_us = int(stamp.group(1))
                    if stamp_us >= end_us:
                        return rows, seen, float(seconds)
                    covered_to = stamp_us // 1_000_000
                if ctx.clock() > ctx.deadline:
                    return rows, seen, float(max(0, covered_to - start_s))
                seen += 1
                if b"app.bsky.embed.external" not in message and b"facet#link" not in message:
                    continue
                try:
                    row = link_post_row(json.loads(message))
                except ValueError:
                    continue
                if row is not None:
                    rows.append(row)
            return rows, seen, float(max(0, covered_to - start_s))
        except (OSError, ConnectionError, ValueError) as error:
            last_error = error
            if rows:
                return rows, seen, float(max(0, covered_to - start_s))
        finally:
            stream.close()
    raise RuntimeError(f"jetstream slice failed: {last_error}")


def collect_jetstream(ctx: _Context) -> tuple[list[Row], dict[str, Any]]:
    now_s = int(ctx.now.timestamp())
    if now_s - ctx.end_s > JETSTREAM_RETENTION_SECONDS:
        raise SourceSkipped("window is older than Jetstream replay retention")
    start = max(ctx.start_s, now_s - JETSTREAM_RETENTION_SECONDS)
    span = ctx.end_s - start
    seconds = min(JETSTREAM_SLICE_SECONDS, max(1, span // JETSTREAM_SLICES))
    starts = [start + int(span * (index + 0.5) / JETSTREAM_SLICES) - seconds // 2
              for index in range(JETSTREAM_SLICES)]
    rows: list[Row] = []
    seen = 0
    covered = 0.0
    failed = 0
    with cf.ThreadPoolExecutor(JETSTREAM_PARALLEL) as pool:
        futures = [pool.submit(_jetstream_slice, ctx, index, slice_start, seconds)
                   for index, slice_start in enumerate(starts)]
        for future in futures:
            try:
                slice_rows, slice_seen, slice_covered = future.result()
            except RuntimeError:
                failed += 1
                continue
            rows.extend(slice_rows)
            seen += slice_seen
            covered += slice_covered
    if not covered:
        raise RuntimeError("no Jetstream slice could be replayed")
    # Slices are a time sample by design: a failed slice lowers the covered fraction that
    # scales every story's sharer estimate, so the source stays usable rather than partial.
    return rows, {
        "effective_window_start": datetime.fromtimestamp(start, timezone.utc).isoformat(),
        "slices": JETSTREAM_SLICES, "failed_slices": failed, "posts_seen": seen,
        "covered_seconds": round(covered, 1), "sample_fraction": round(covered / max(1, span), 5),
    }


def collect_hn(ctx: _Context) -> tuple[list[Row], dict[str, Any]]:
    stories: dict[str, Row] = {}
    requests_made = 0
    lower = ctx.start_s
    while lower < ctx.end_s:
        upper = min(lower + 6 * 3600, ctx.end_s)
        page = 0
        while True:
            payload = json.loads(ctx.get_ok(
                "https://hn.algolia.com/api/v1/search_by_date",
                params={"tags": "story", "hitsPerPage": 1000, "page": page,
                        "numericFilters": f"created_at_i>={lower},created_at_i<{upper}"},
            ))
            requests_made += 1
            for hit in payload.get("hits", []):
                stories[str(hit["objectID"])] = {
                    "src": "hn", "id": str(hit["objectID"]), "t": hit.get("created_at_i"),
                    "url": hit.get("url") or "", "title": _clean(hit.get("title")),
                    "points": int(hit.get("points") or 0), "comments": int(hit.get("num_comments") or 0),
                }
            page += 1
            if page >= int(payload.get("nbPages") or 1):
                break
        lower = upper
    return list(stories.values()), {"requests": requests_made}


def collect_techmeme(ctx: _Context) -> tuple[list[Row], dict[str, Any]]:
    rows = parse_techmeme(ctx.get_ok("https://www.techmeme.com/").decode("utf-8", "replace"))
    if not rows:
        raise RuntimeError("no Techmeme clusters parsed")
    return rows, {}


def collect_kagi(ctx: _Context) -> tuple[list[Row], dict[str, Any]]:
    base = "https://news.kagi.com/api"
    earliest = (ctx.window_end - timedelta(days=3)).date().isoformat()
    latest = (ctx.window_end + timedelta(days=1)).date().isoformat()
    batches = json.loads(ctx.get_ok(f"{base}/batches", params={"from": earliest, "to": latest}))["batches"]
    usable = [batch for batch in batches if (_parse_time(batch.get("createdAt")) or 0) <= ctx.end_s]
    if not usable:
        raise RuntimeError("no Kagi News batch published before the window end")
    batch = max(usable, key=lambda item: item["createdAt"])
    batch_time = _parse_time(batch["createdAt"])
    categories = json.loads(ctx.get_ok(f"{base}/batches/{batch['id']}/categories"))["categories"]
    rows: list[Row] = []
    for category in categories:
        if category.get("categoryId") not in KAGI_CATEGORIES:
            continue
        payload = json.loads(ctx.get_ok(
            f"{base}/batches/{batch['id']}/categories/{category['id']}/stories", params={"limit": 100},
        ))
        for story in payload.get("stories") or payload.get("clusters") or []:
            articles = [article for article in story.get("articles") or [] if article.get("link")]
            rows.append({
                "src": "kagi", "t": batch_time, "category": category["categoryId"],
                "rank": story.get("cluster_number"), "title": _clean(story.get("title")),
                "text": _clean(story.get("short_summary"))[:400], "url": "",
                "unique_domains": int(story.get("unique_domains")
                                      or len({article.get("domain") for article in articles})),
                "more": [article["link"] for article in articles][:60],
            })
    return rows, {"batch_created_at": batch["createdAt"]}


def collect_mastodon(ctx: _Context) -> tuple[list[Row], dict[str, Any]]:
    rows: list[Row] = []
    failed: list[str] = []

    def one(instance: str) -> tuple[str, list[Row] | None]:
        found: list[Row] = []
        try:
            for offset in (0, 20):
                links = json.loads(ctx.get_ok(
                    f"https://{instance}/api/v1/trends/links", params={"limit": 20, "offset": offset},
                ))
                for link in links:
                    history = link.get("history") or []
                    found.append({
                        "src": "mastodon", "instance": instance, "url": link.get("url") or "",
                        "title": _clean(link.get("title")),
                        "text": _clean(link.get("description"))[:300],
                        "accounts": sum(int(day.get("accounts", 0) or 0) for day in history[:2]),
                    })
                if len(links) < 20:
                    break
        except Exception:  # noqa: BLE001 - one instance never fails the source
            return instance, None
        return instance, found

    with cf.ThreadPoolExecutor(6) as pool:
        for instance, found in pool.map(one, MASTODON_INSTANCES):
            if found is None:
                failed.append(instance)
            else:
                rows.extend(found)
    if len(failed) == len(MASTODON_INSTANCES):
        raise RuntimeError("every Mastodon instance failed")
    meta: dict[str, Any] = {"instances": len(MASTODON_INSTANCES), "failed_instances": failed}
    if failed:
        meta["incomplete"] = f"{len(failed)} of {len(MASTODON_INSTANCES)} Mastodon instances failed"
    return rows, meta


def collect_bsky_trends(ctx: _Context) -> tuple[list[Row], dict[str, Any]]:
    payload = json.loads(ctx.get_ok(
        "https://public.api.bsky.app/xrpc/app.bsky.unspecced.getTrends", params={"limit": 25},
    ))
    rows = [{
        "src": "bsky_trends", "url": "", "title": _clean(trend.get("displayName")),
        "text": _clean(trend.get("description"))[:300], "posts": int(trend.get("postCount") or 0),
        "status": trend.get("status") or "",
    } for trend in payload.get("trends", [])]
    return rows, {}


def collect_wikipedia(ctx: _Context) -> tuple[list[Row], dict[str, Any]]:
    """Latest complete day's top-1000 English Wikipedia articles with the prior day's views."""
    days: dict[str, dict[str, int]] = {}
    day = (ctx.window_end - timedelta(days=1)).date()
    for _ in range(4):
        status, body = ctx.get(
            "https://wikimedia.org/api/rest_v1/metrics/pageviews/top/en.wikipedia/all-access/"
            f"{day.strftime('%Y/%m/%d')}"
        )
        if status == 200:
            articles = json.loads(body)["items"][0]["articles"]
            days[day.isoformat()] = {item["article"]: int(item["views"]) for item in articles}
            if len(days) == 2:
                break
        elif days:
            break
        day -= timedelta(days=1)
    if not days:
        raise RuntimeError("no Wikipedia top-pageview day is available")
    ordered = sorted(days)
    latest = days[ordered[-1]]
    previous = days[ordered[0]] if len(ordered) == 2 else {}
    rows = [{
        "src": "wikipedia", "article": article, "title": article.replace("_", " "), "url": "",
        "views": views, "prev_views": previous.get(article, 0), "rank": rank,
    } for rank, (article, views) in enumerate(sorted(latest.items(), key=lambda item: -item[1]), 1)
        if not article.startswith(WIKIPEDIA_SKIP_PREFIXES)]
    meta: dict[str, Any] = {"day": ordered[-1], "previous_day": ordered[0] if len(ordered) == 2 else None}
    if len(ordered) < 2:
        # Without the prior day every article's spike would read as its full view count.
        meta["incomplete"] = "prior day's Wikipedia pageviews unavailable"
    return rows, meta


COLLECTORS: dict[str, Collector] = {
    "gkg": collect_gkg,
    "panel": collect_panel,
    "jetstream": collect_jetstream,
    "hn": collect_hn,
    "techmeme": collect_techmeme,
    "kagi": collect_kagi,
    "mastodon": collect_mastodon,
    "bsky_trends": collect_bsky_trends,
    "wikipedia": collect_wikipedia,
}


# ---------------------------------------------------------------- snapshot assembly

def default_window_end(edition: date, now: datetime) -> datetime:
    """The 30 hours before a settled quarter hour of the run, never past noon UTC of the edition date."""
    cap = datetime(edition.year, edition.month, edition.day, 12, tzinfo=timezone.utc)
    settled = now - timedelta(seconds=WINDOW_SETTLE_SECONDS)
    settled = settled.replace(minute=settled.minute - settled.minute % 15, second=0, microsecond=0)
    return min(settled, cap)


def _snapshot_id(snapshot: dict[str, Any]) -> str:
    identity = {
        "schema": snapshot["schema_version"], "window": [snapshot["window_start"], snapshot["window_end"]],
        "built_at": snapshot["built_at"],
        "sources": {name: [meta.get("status"), meta.get("rows")] for name, meta in sorted(snapshot["sources"].items())},
    }
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:16]


def collect_snapshot(
    window_end: datetime,
    *,
    sources: tuple[str, ...] = SOURCES,
    budget_seconds: float = COLLECTION_BUDGET_SECONDS,
    now: datetime | None = None,
    clock: Callable[[], float] = time.monotonic,
    collectors: dict[str, Collector] | None = None,
) -> dict[str, Any]:
    """Collect every requested source concurrently inside one wall-clock budget."""
    observed = now or datetime.now(timezone.utc)
    window_start = window_end - timedelta(hours=WINDOW_HOURS)
    started = clock()
    ctx = _Context(window_start, window_end, started + budget_seconds, clock, observed)
    table = collectors or COLLECTORS
    lag = (observed - window_end).total_seconds()
    statuses: dict[str, dict[str, Any]] = {}
    rows: list[Row] = []
    runnable: list[str] = []
    for name in sources:
        if name in LIVE_ONLY_SOURCES and lag > LIVE_SOURCE_MAX_LAG_SECONDS:
            statuses[name] = {"status": "skipped", "reason": "live-only source cannot observe a past window",
                              "rows": 0}
        else:
            runnable.append(name)

    def run(name: str) -> tuple[str, list[Row], dict[str, Any]]:
        began = clock()
        try:
            found, meta = table[name](ctx)
            # A census missing any planned fetch is partial: counting it would undercount some stories.
            return name, found, {"status": "partial" if meta.get("incomplete") else "ok", "rows": len(found),
                                 **meta, "elapsed_seconds": round(clock() - began, 2)}
        except SourceSkipped as reason:
            return name, [], {"status": "skipped", "reason": str(reason), "rows": 0,
                              "elapsed_seconds": round(clock() - began, 2)}
        except Exception as error:  # noqa: BLE001 - every source is optional
            return name, [], {"status": "unavailable", "rows": 0,
                              "error": " ".join(f"{type(error).__name__}: {error}".split())[:240],
                              "elapsed_seconds": round(clock() - began, 2)}

    pool = cf.ThreadPoolExecutor(max(1, len(runnable)))
    futures = {pool.submit(run, name): name for name in runnable}
    try:
        for future in cf.as_completed(futures, timeout=max(1.0, budget_seconds + 30.0)):
            name, found, meta = future.result()
            statuses[name] = meta
            rows.extend(found)
    except cf.TimeoutError:
        for future, name in futures.items():
            if name not in statuses:
                statuses[name] = {"status": "unavailable", "rows": 0,
                                  "error": "attention snapshot budget exhausted"}
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    snapshot = {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "built_at": observed.isoformat(),
        "elapsed_seconds": round(clock() - started, 2),
        "sources": {name: statuses[name] for name in sources},
        "rows": rows,
    }
    snapshot["id"] = _snapshot_id(snapshot)
    return snapshot


def _write_snapshot(path: Path, snapshot: dict[str, Any]) -> None:
    """Atomically write gzip JSON without materializing the serialized document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(handle, "wb") as stream:
            with gzip.GzipFile(fileobj=stream, mode="wb", compresslevel=6) as compressed:
                with io.TextIOWrapper(compressed, encoding="utf-8") as text:
                    json.dump(snapshot, text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _read_snapshot(path: Path) -> dict[str, Any] | None:
    try:
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            snapshot = json.load(stream)
    except (OSError, ValueError, EOFError):
        return None
    if not isinstance(snapshot, dict) or snapshot.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
        return None
    if not isinstance(snapshot.get("rows"), list) or not isinstance(snapshot.get("sources"), dict):
        return None
    return snapshot


def _retry_incomplete(
    snapshot: dict[str, Any],
    observed: datetime,
    budget_seconds: float,
    collect: Callable[..., dict[str, Any]],
) -> bool:
    """Re-collect unavailable or partial sources; a source's rows change only when the retry is better."""
    pending = tuple(
        name for name, meta in snapshot["sources"].items()
        if meta.get("status") in RETRY_STATUSES and int(meta.get("attempts") or 1) < MAX_SOURCE_ATTEMPTS
    )
    if not pending:
        return False
    retry = collect(datetime.fromisoformat(snapshot["window_end"]), sources=pending, now=observed,
                    budget_seconds=budget_seconds)
    improved = {
        name for name in pending
        if _STATUS_RANK.get(retry["sources"][name].get("status"), 0) > _STATUS_RANK[snapshot["sources"][name]["status"]]
    }
    if improved:
        snapshot["rows"] = [row for row in snapshot["rows"] if row.get("src") not in improved]
        snapshot["rows"].extend(row for row in retry["rows"] if row.get("src") in improved)
    for name in pending:
        previous = snapshot["sources"][name]
        chosen = retry["sources"][name] if name in improved else previous
        snapshot["sources"][name] = {**chosen, "attempts": int(previous.get("attempts") or 1) + 1,
                                     "retried_at": observed.isoformat()}
    snapshot["id"] = _snapshot_id(snapshot)
    return True
def load_or_build_snapshot(
    root: Path,
    edition: date,
    *,
    now: datetime | None = None,
    budget_seconds: float = COLLECTION_BUDGET_SECONDS,
    collect: Callable[..., dict[str, Any]] = collect_snapshot,
) -> dict[str, Any]:
    """Reuse the edition's snapshot, retrying unavailable or partial sources while the window is fresh."""
    observed = now or datetime.now(timezone.utc)
    path = root / edition.isoformat() / "snapshot.json.gz"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path.parent / ".lock", "a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        snapshot = _read_snapshot(path)
        if snapshot is None:
            snapshot = collect(default_window_end(edition, observed), now=observed,
                               budget_seconds=budget_seconds)
            _retry_incomplete(snapshot, observed, budget_seconds, collect)
            _write_snapshot(path, snapshot)
            snapshot["reused"] = False
        else:
            built = datetime.fromisoformat(snapshot["built_at"])
            if (observed - built).total_seconds() < RETRY_FAILED_WITHIN_SECONDS and _retry_incomplete(
                snapshot, observed, budget_seconds, collect,
            ):
                _write_snapshot(path, snapshot)
            snapshot["reused"] = True
        prune_snapshots(root, keep=SNAPSHOT_KEEP_EDITIONS)
    return snapshot


def prune_snapshots(root: Path, *, keep: int) -> None:
    editions = sorted(
        (child for child in root.iterdir() if child.is_dir() and re.fullmatch(r"\d{4}-\d{2}-\d{2}", child.name)),
        key=lambda child: child.name,
    )
    for stale in editions[:-keep] if keep > 0 else editions:
        for item in stale.iterdir():
            try:
                item.unlink()
            except OSError:
                pass
        try:
            stale.rmdir()
        except OSError:
            pass

