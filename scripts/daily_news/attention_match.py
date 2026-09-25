"""Match Daily News candidates to snapshot inventories and measure attention per source.

Lexical retrieval finds plausible documents cheaply; Jev decides whether each
document reports the same event, a related development, or something else.
Counts come only from the observed inventories: Jev never estimates popularity.
A story Jev could not fully adjudicate has no measurement; it is never guessed lexically.
"""
from __future__ import annotations

import collections
import html
import math
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlsplit

from .attention import event_terms
from .contracts import coverage_key
from jev import JevClient, JevUnavailable

TOKEN = re.compile(r"[a-z0-9]+(?:\.[0-9]+)*")
STOPWORDS = frozenset("""a an the and or but of to in on at for from by with without into onto over under
about after before amid among between during via per as is are was were be been being has have had do does did
its it this that these those their his her our your they them he she we you i not no new says said say saying
reports report reported update updates launch launches launched launching announce announces announced unveils
unveiled unveil introduces introduced debut debuts first more most than then just now today week weekly year
years day days how why what when where who which will would can could may might should get gets got make makes
made take takes using use used also still up down out off here there all any some each other one two three four
five six seven eight nine ten amp s t re ve ll d m vs news live latest breaking exclusive video watch read
analysis opinion review guide explained look inside behind big set sets plan plans planned plus back like near
nearly across around against deal deals help helps adds add added available coming comes come goes going go
early late next last top best""".split())
# Press-release wires and bulk republishers: counted as syndication, never as independent coverage.
PR_DOMAINS = frozenset({
    "prnewswire.com", "businesswire.com", "globenewswire.com", "accessnewswire.com", "einpresswire.com",
    "openpr.com", "pr-inside.com", "prweb.com", "newswire.com", "newsfilecorp.com", "finanznachrichten.de",
    "streetinsider.com", "stocktitan.net", "morningstar.com", "marketscreener.com", "newsroomamerica.com",
    "tickerreport.com", "themarketsdaily.com", "dailypolitical.com", "prnewswire.co.uk", "presseportal.de",
    "financialcontent.com", "benzinga.com", "zawya.com", "aijourn.com", "techbullion.com",
})
RELATION_WEIGHTS = {"same": 1.0, "related": 0.5, "different": 0.0}
RELATION_LEVELS = (
    "Different: `{item}` is about a different event or topic; sharing a company, person, product line, or "
    "place with `candidate` is not enough.",
    "Related: `{item}` covers the same ongoing story or product as `candidate` but reports a different "
    "development, an earlier or later stage, background, analysis, a review, or a reaction.",
    "Same: `{item}` reports the specific development described in `candidate`.",
)
TOP_DOCS_PER_SOURCE = 24
JEV_BATCH = 8
JEV_WORKERS = 6
MAX_DF_FOR_RETRIEVAL = 3000
RARE_DF = 200
VERY_RARE_DF = 100
RECENT_SECONDS = 6 * 3600
SYNDICATION_JACCARD = 0.6
MAX_SAMPLES = 6


def toks(text: Any) -> list[str]:
    value = html.unescape(str(text or "")).lower().replace("’", "'")
    value = re.sub(r"'s\b", "", value)
    return [token for token in TOKEN.findall(value)
            if token not in STOPWORDS and (len(token) >= 2 or token.isdigit())]


def entity_tokens(text: Any) -> set[str]:
    """Tokens written capitalized or alphanumeric in sentence-case text (names, products, orgs)."""
    found: set[str] = set()
    for word in re.findall(r"[A-Za-z0-9][A-Za-z0-9.\-’']*", html.unescape(str(text or ""))):
        if word[0].isupper() or any(ch.isdigit() for ch in word) or sum(ch.isupper() for ch in word) > 1:
            found.update(toks(word))
    return found


def registrable_domain(url_or_host: str) -> str:
    value = url_or_host or ""
    host = (urlsplit(value).hostname or "") if "://" in value else value
    parts = host.lower().split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac", "gov") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _row_urls(row: dict[str, Any]) -> list[str]:
    urls = list(row.get("urls") or ([row["url"]] if row.get("url") else []))
    return urls + list(row.get("more") or [])


class Index:
    """Token and URL indexes over one snapshot's rows, built once per section run."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self.tokens: list[frozenset[str]] = []
        self.df: collections.Counter[str] = collections.Counter()
        self.inverted: dict[str, list[int]] = collections.defaultdict(list)
        self.by_url: dict[str, list[int]] = collections.defaultdict(list)
        for index, row in enumerate(rows):
            tokens = frozenset(toks(f"{row.get('title', '')} {row.get('text', '')}"))
            self.tokens.append(tokens)
            self.df.update(tokens)
            for token in tokens:
                self.inverted[token].append(index)
            for url in _row_urls(row):
                key = coverage_key(url)
                if key and len(key.split("/", 1)[-1]) > 8:
                    self.by_url[key].append(index)
        self.size = len(rows)

    def idf(self, token: str) -> float:
        return math.log((self.size + 1) / (self.df.get(token, 0) + 1))


def _doc_key(row: dict[str, Any]) -> str:
    url = row.get("url") or ""
    key = coverage_key(url) if url else ""
    if key and len(key.split("/", 1)[-1]) > 8:
        return key
    return "title:" + " ".join(toks(row.get("title") or row.get("text") or ""))[:160]


def retrieve(candidate: dict[str, Any], index: Index) -> list[dict[str, Any]]:
    """Plausible documents for one candidate, grouped by URL/title and capped per source."""
    terms = event_terms(candidate)
    query = set(toks(" ".join([candidate.get("title", ""), candidate.get("event") or "", " ".join(terms)])))
    if not query:
        return []
    weights = {token: index.idf(token) for token in query}
    denominator = sum(sorted(weights.values(), reverse=True)[:12]) or 1.0
    phrases = [" ".join(toks(term)) for term in terms if len(toks(term)) >= 2]
    title_words = re.findall(r"[A-Za-z][A-Za-z0-9\-’']*", candidate.get("title", ""))
    title_case = bool(title_words) and sum(word[0].isupper() for word in title_words) / len(title_words) > 0.6
    entities = entity_tokens(candidate.get("event") or "") | entity_tokens(" ".join(terms))
    if not title_case:
        entities |= entity_tokens(candidate.get("title", ""))
    entities &= query
    event_words = (query - entities) | {token for token in query if any(ch.isdigit() for ch in token)}

    exact = set(index.by_url.get(coverage_key(candidate.get("url", "")), []))
    pool = set(exact)
    for token in query:
        if index.df.get(token, 0) <= MAX_DF_FOR_RETRIEVAL:
            pool.update(index.inverted.get(token, ()))

    docs: dict[str, dict[str, Any]] = {}
    for row_index in pool:
        row = index.rows[row_index]
        shared = query & index.tokens[row_index]
        score = sum(weights[token] for token in shared) / denominator
        if row_index in exact:
            band = "exact"
        else:
            rare = sum(1 for token in shared if index.df.get(token, 0) <= RARE_DF)
            event_weight = sum(weights[token] for token in shared & event_words)
            has_entity = bool(shared & entities) or not entities
            joined = " ".join(toks(f"{row.get('title', '')} {row.get('text', '')}"))
            phrase = any(item in joined for item in phrases)
            rare_weight = sum(weights[token] for token in shared if index.df.get(token, 0) <= VERY_RARE_DF)
            if ((phrase and score >= 0.30 and rare >= 1) or (has_entity and event_weight >= 5.0 and score >= 0.40)
                    or (rare_weight >= 16 and score >= 0.35)):
                band = "strong"
            elif score >= 0.25 and (rare >= 1 or event_weight >= 3.0):
                band = "ambiguous"
            else:
                continue
        key = "exact" if band == "exact" else _doc_key(row)
        doc = docs.setdefault(key, {"key": key, "rows": [], "score": 0.0, "band": band, "src": row["src"]})
        doc["rows"].append(row_index)
        rank = {"exact": 2, "strong": 1, "ambiguous": 0}
        if rank[band] > rank[doc["band"]] or (band == doc["band"] and score > doc["score"]):
            doc.update(score=round(score, 3), band=band, src=row["src"],
                       title=row.get("title") or "", text=(row.get("text") or "")[:240],
                       domain=row.get("domain") or registrable_domain(row.get("url") or ""))
        doc.setdefault("title", row.get("title") or "")
        doc.setdefault("text", (row.get("text") or "")[:240])
        doc.setdefault("domain", row.get("domain") or registrable_domain(row.get("url") or ""))

    selected = [doc for doc in docs.values() if doc["band"] == "exact"]
    by_source: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for doc in docs.values():
        if doc["band"] != "exact":
            by_source[doc["src"]].append(doc)
    for source_docs in by_source.values():
        source_docs.sort(key=lambda doc: (doc["band"] == "strong", doc["score"]), reverse=True)
        selected.extend(source_docs[:TOP_DOCS_PER_SOURCE])
    return selected


def _relation_questions(count: int) -> dict[str, dict[str, Any]]:
    return {
        f"item_{i}": {
            "type": "score",
            "instructions": f"How does `items[{i}]` relate to the news event described in `candidate`?",
            "criteria": [level.format(item=f"items[{i}]") for level in RELATION_LEVELS],
        }
        for i in range(count)
    }


class Adjudicator:
    """Decides document relations with Jev; stories with a failed batch are reported, never guessed."""

    def __init__(self, client: JevClient) -> None:
        self.client = client
        self.error = ""
        self._lock = threading.Lock()

    def _ask(self, candidate: dict[str, Any], batch: list[dict[str, Any]]) -> bool:
        state = {
            "candidate": {"headline": candidate.get("title", ""), "event": candidate.get("event") or "",
                          "source": candidate.get("source_domain") or registrable_domain(candidate.get("url", ""))},
            "items": [{"headline": doc["title"] or doc["text"][:200], "source": doc["domain"]} for doc in batch],
        }
        try:
            answers = self.client.ask("news.relation", state, _relation_questions(len(batch)))
        except JevUnavailable as error:
            with self._lock:
                self.error = str(error) or "Jev unavailable"
            return False
        for i, doc in enumerate(batch):
            answer = answers[f"item_{i}"]
            level = min(2, max(0, int(float(answer["score"]) + 0.5)))
            doc["relation"] = ("different", "related", "same")[level]
            doc["relation_confidence"] = round(float(answer["confidence"]), 3)
            doc["decided_by"] = "jev"
        return True

    def adjudicate(self, work: list[tuple[dict[str, Any], list[dict[str, Any]]]]) -> set[int]:
        """Fill ``relation`` for every document; returns indexes of work Jev could not finish.

        The client's consecutive-failure breaker stops the remaining batches during an
        outage, so it costs seconds rather than the phase budget.
        """
        batches: list[tuple[int, dict[str, Any], list[dict[str, Any]]]] = []
        for position, (candidate, docs) in enumerate(work):
            pending = []
            for doc in docs:
                if doc["band"] == "exact":
                    doc.update(relation="same", relation_confidence=1.0, decided_by="url")
                else:
                    pending.append(doc)
            for start in range(0, len(pending), JEV_BATCH):
                batches.append((position, candidate, pending[start:start + JEV_BATCH]))
        if not batches:
            return set()
        with ThreadPoolExecutor(JEV_WORKERS) as pool:
            finished = list(pool.map(lambda job: self._ask(job[1], job[2]), batches))
        return {position for (position, _, _), done in zip(batches, finished) if not done}


def _near_duplicate(tokens: set[str], groups: list[dict[str, Any]]) -> dict[str, Any] | None:
    for group in groups:
        union = tokens | group["tokens"]
        if union and len(tokens & group["tokens"]) / len(union) >= SYNDICATION_JACCARD:
            return group
    return None


def measure(
    candidate: dict[str, Any],
    docs: list[dict[str, Any]],
    index: Index,
    *,
    window_end_s: int,
    sample_fraction: float | None,
) -> dict[str, Any]:
    """Per-source observed measures (full window and last six hours) for one candidate."""
    own = registrable_domain(candidate.get("url", ""))
    recent_from = window_end_s - RECENT_SECONDS
    row_weight: dict[int, float] = {}
    for doc in docs:
        weight = RELATION_WEIGHTS.get(doc.get("relation", "different"), 0.0)
        for row_index in doc["rows"]:
            row_weight[row_index] = max(row_weight.get(row_index, 0.0), weight)

    measures = collections.Counter()
    recent = collections.Counter()
    # Press is counted per source so either inventory can be left out on its own.
    press_groups: dict[str, list[dict[str, Any]]] = {"gkg": [], "panel": []}
    recent_groups: dict[str, list[dict[str, Any]]] = {"gkg": [], "panel": []}
    press_domains: dict[str, dict[str, float]] = {"gkg": {}, "panel": {}}
    recent_domains: dict[str, dict[str, float]] = {"gkg": {}, "panel": {}}
    authors: dict[str, float] = {}
    recent_authors: dict[str, float] = {}
    mastodon: dict[tuple[str, str], float] = {}
    hn_points = hn_recent_points = 0.0
    techmeme: dict[str, Any] | None = None
    first_seen: int | None = None
    for row_index, weight in row_weight.items():
        if weight <= 0:
            continue
        row = index.rows[row_index]
        source = row["src"]
        stamp = row.get("t") or 0
        is_recent = stamp >= recent_from
        if stamp and source in ("gkg", "panel", "jetstream", "hn"):
            first_seen = stamp if first_seen is None else min(first_seen, stamp)
        if source in ("gkg", "panel"):
            domain = registrable_domain(row.get("domain") or row.get("url") or "")
            if not domain or domain == own:
                continue
            if domain in PR_DOMAINS:
                measures["pr_copies"] += 1
                continue
            tokens = set(toks(row.get("title")))
            targets = [(press_groups[source], press_domains[source])] + (
                [(recent_groups[source], recent_domains[source])] if is_recent else []
            )
            for groups, domains in targets:
                group = _near_duplicate(tokens, groups) if tokens else None
                if group is None:
                    groups.append({"tokens": tokens, "weight": weight})
                else:
                    group["weight"] = max(group["weight"], weight)
                domains[domain] = max(domains.get(domain, 0.0), weight)
        elif source == "jetstream":
            authors[row["author"]] = max(authors.get(row["author"], 0.0), weight)
            if is_recent:
                recent_authors[row["author"]] = max(recent_authors.get(row["author"], 0.0), weight)
        elif source == "mastodon":
            key = (row.get("instance", ""), coverage_key(row.get("url", "")))
            mastodon[key] = max(mastodon.get(key, 0.0), weight * float(row.get("accounts") or 0))
        elif source == "hn":
            hn_points = max(hn_points, weight * float(row.get("points") or 0))
            measures["hn_comments"] += weight * float(row.get("comments") or 0)
            if is_recent:
                hn_recent_points = max(hn_recent_points, weight * float(row.get("points") or 0))
                recent["hn_comments"] += weight * float(row.get("comments") or 0)
        elif source == "bsky_trends":
            measures["trend_posts"] = max(measures["trend_posts"], weight * float(row.get("posts") or 0))
        elif source == "wikipedia":
            views, previous = float(row.get("views") or 0), float(row.get("prev_views") or 0)
            spike = 1.0 if previous <= 0 else min(1.0, max(0.0, views / previous - 1.0))
            measures["wiki_spike_views"] = max(measures["wiki_spike_views"], weight * views * spike)
        elif source == "techmeme":
            if techmeme is None or row["rank"] < techmeme["rank"]:
                techmeme = {"rank": row["rank"], "weight": weight, "more": len(row.get("more") or []),
                            "disc": int(row.get("disc") or 0)}
        elif source == "kagi":
            measures["kagi_domains"] = max(measures["kagi_domains"], weight * float(row.get("unique_domains") or 0))

    for source in ("gkg", "panel"):
        measures[f"{source}_groups"] = round(sum(group["weight"] for group in press_groups[source]), 2)
        measures[f"{source}_domains"] = round(sum(press_domains[source].values()), 2)
        recent[f"{source}_groups"] = round(sum(group["weight"] for group in recent_groups[source]), 2)
        recent[f"{source}_domains"] = round(sum(recent_domains[source].values()), 2)
    fraction = sample_fraction if sample_fraction and sample_fraction > 0 else None
    measures["bsky_sharers_sampled"] = round(sum(authors.values()), 2)
    measures["bsky_sharers_est"] = round(sum(authors.values()) / fraction, 1) if fraction else 0.0
    recent["bsky_sharers_est"] = round(sum(recent_authors.values()) / fraction, 1) if fraction else 0.0
    measures["mastodon_accounts"] = round(sum(mastodon.values()), 1)
    measures["hn_points"] = round(hn_points, 1)
    recent["hn_points"] = round(hn_recent_points, 1)
    if techmeme is not None:
        measures["techmeme_rank"] = techmeme["rank"]
        measures["techmeme_weight"] = techmeme["weight"]
        measures["techmeme_more"] = round(techmeme["weight"] * techmeme["more"], 1)
        measures["techmeme_discussion"] = round(techmeme["weight"] * techmeme["disc"], 1)

    accepted = [doc for doc in docs if RELATION_WEIGHTS.get(doc.get("relation", "different"), 0.0) > 0]
    accepted.sort(key=lambda doc: (RELATION_WEIGHTS[doc["relation"]], doc["score"]), reverse=True)
    samples = [{
        "source": doc["src"], "domain": doc.get("domain", ""), "title": (doc.get("title") or doc.get("text", ""))[:160],
        "relation": doc["relation"], "decided_by": doc.get("decided_by", ""),
    } for doc in accepted[:MAX_SAMPLES]]
    decided = collections.Counter(doc.get("decided_by", "") for doc in docs)
    return {
        "measures": {key: value for key, value in sorted(measures.items()) if value},
        "recent": {key: value for key, value in sorted(recent.items()) if value},
        "samples": samples,
        "first_seen": first_seen,
        "adjudication": {
            "documents": len(docs), "accepted": len(accepted),
            "jev": decided.get("jev", 0), "url": decided.get("url", 0),
        },
    }
