#!/usr/bin/env python3
"""Behavioral contracts for observed attention, Jev importance, and product priority."""
from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timezone

from daily_news import attention_match, attention_sources
from daily_news.attention import (
    DEFAULT_REFERENCE,
    EDITORIAL_POINTS,
    REFERENCE_MIN_SAMPLES,
    SOURCE_WEIGHTS,
    assess_importance,
    canonicalize_publisher_url,
    enforce_editorial_significance,
    event_terms,
    importance_from_answers,
    importance_score,
    measured_attention,
    normalize_editorial_significance,
    priority_sort_key,
    reference_scales,
    score_attention,
    score_ongoing,
    section_sources,
)
from jev import JevClient, JevUnavailable

WINDOW_END = datetime(2026, 9, 24, 6, 0, tzinfo=timezone.utc)
END_S = int(WINDOW_END.timestamp())
ALL_SOURCES = frozenset(SOURCE_WEIGHTS)


def check(condition: bool, message: object) -> None:
    if not condition:
        raise AssertionError(message)


class FakeJev:
    """Answers relation questions from a headline -> relation table; importance from a fixed table."""

    def __init__(self, relations: dict[str, str] | None = None, *, fail: bool = False) -> None:
        self.relations = relations or {}
        self.fail = fail
        self.calls = 0

    def ask(self, purpose: str, state: dict, questions: dict) -> dict:
        self.calls += 1
        if self.fail:
            raise JevUnavailable("rate", "HTTP 429")
        answers = {}
        for key in questions:
            index = int(key.split("_")[1])
            relation = self.relations.get(state["items"][index]["headline"], "different")
            level = {"different": 0.0, "related": 1.0, "same": 2.0}[relation]
            answers[key] = {"type": "score", "score": level, "confidence": 0.9}
        return answers


CANDIDATE = {
    "title": "Acme ships Quasar 9 accelerator for data centers",
    "event": "Acme released the Quasar 9 accelerator for data centers.",
    "event_terms": ["Quasar 9 accelerator", "Acme Quasar 9"],
    "url": "https://acme.example/news/quasar-9",
    "source_domain": "acme.example",
    "editorial_significance": "medium",
}
AP_HEADLINE = "Acme ships Quasar 9 accelerator as data center demand grows"


def _rows() -> list[dict]:
    rows = [
        # One wire story syndicated to three outlets collapses into one independent write-up.
        {"src": "gkg", "t": END_S - 3600, "domain": "wire-one.example", "url": "https://wire-one.example/a1",
         "title": AP_HEADLINE},
        {"src": "gkg", "t": END_S - 3500, "domain": "wire-two.example", "url": "https://wire-two.example/a1",
         "title": AP_HEADLINE},
        {"src": "gkg", "t": END_S - 30000, "domain": "wire-three.example", "url": "https://wire-three.example/a1",
         "title": AP_HEADLINE + " - Wire Three"},
        {"src": "panel", "t": END_S - 7200, "domain": "techsite.example", "url": "https://techsite.example/q9",
         "title": "Hands on with Acme's Quasar 9 accelerator launch"},
        {"src": "gkg", "t": END_S - 7000, "domain": "prnewswire.com", "url": "https://prnewswire.com/q9",
         "title": "Acme Ships Quasar 9 Accelerator"},
        {"src": "gkg", "t": END_S - 6000, "domain": "acme.example", "url": "https://acme.example/blog/q9-2",
         "title": "Acme Quasar 9 accelerator now shipping"},
        {"src": "gkg", "t": END_S - 5000, "domain": "business.example", "url": "https://business.example/earnings",
         "title": "Acme quarterly earnings beat estimates on accelerator demand"},
        {"src": "jetstream", "t": END_S - 1000, "author": "a1", "urls": [CANDIDATE["url"]],
         "url": CANDIDATE["url"], "title": "Acme Quasar 9", "text": ""},
        {"src": "jetstream", "t": END_S - 900, "author": "a2", "urls": [CANDIDATE["url"]],
         "url": CANDIDATE["url"], "title": "Acme Quasar 9", "text": ""},
        {"src": "jetstream", "t": END_S - 800, "author": "a2", "urls": [CANDIDATE["url"]],
         "url": CANDIDATE["url"], "title": "Acme Quasar 9", "text": ""},
        {"src": "hn", "t": END_S - 20000, "id": "1", "url": "https://techsite.example/q9",
         "title": "Acme Quasar 9 accelerator", "points": 120, "comments": 40},
    ]
    # A realistic inventory is mostly unrelated coverage; it gives event words their rarity.
    rows += [{"src": "gkg", "t": END_S - 100 * i, "domain": f"local{i}.example",
              "url": f"https://local{i}.example/story-{i}", "title": f"Council meeting agenda item {i} on roads"}
             for i in range(300)]
    return rows


def _measure(client) -> dict:
    index = attention_match.Index(_rows())
    documents = attention_match.retrieve(CANDIDATE, index)
    attention_match.Adjudicator(client).adjudicate([(CANDIDATE, documents)])
    return attention_match.measure(CANDIDATE, documents, index, window_end_s=END_S, sample_fraction=0.05)


def test_bulk_parsers_extract_titled_rows() -> None:
    record = ["x"] * 27
    record[1], record[3], record[4] = "20260924051500", "wire.example", "https://wire.example/story"
    record[26] = "<PAGE_TITLE>Acme ships Quasar 9 &amp; more</PAGE_TITLE>"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("x.gkg.csv", "\t".join(record) + "\n" + "\t".join(["short"] * 5) + "\n")
    gkg = attention_sources.parse_gkg_archive(buffer.getvalue())
    check(len(gkg) == 1 and gkg[0]["title"] == "Acme ships Quasar 9 & more", gkg)
    check(gkg[0]["t"] == int(datetime(2026, 9, 24, 5, 15, tzinfo=timezone.utc).timestamp()), gkg)

    sitemap = b"""<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
      xmlns:news="http://www.google.com/schemas/sitemap-news/0.9"><url><loc>https://pub.example/a</loc>
      <news:news><news:publication_date>2026-09-24T04:00:00Z</news:publication_date>
      <news:title>Quasar 9 ships</news:title></news:news></url></urlset>"""
    rows, children = attention_sources.parse_news_sitemap(sitemap, "pub.example")
    check(children == [] and rows[0]["title"] == "Quasar 9 ships" and rows[0]["t"], rows)
    index_xml = b"""<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <sitemap><loc>https://pub.example/news-1.xml</loc></sitemap></sitemapindex>"""
    check(attention_sources.parse_news_sitemap(index_xml, "pub.example") == ([], ["https://pub.example/news-1.xml"]),
          "sitemap index children")
    atom = b"""<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Atom story</title>
      <link href="https://pub.example/atom"/><updated>2026-09-24T03:00:00Z</updated></entry></feed>"""
    check(attention_sources.parse_feed(atom, "pub.example")[0]["url"] == "https://pub.example/atom", "atom link")

    page = ('<DIV CLASS="clus"><STRONG CLASS="L3"><A CLASS="ourh" HREF="https://pub.example/lead">Lead '
            '<b>story</b></A></STRONG><SPAN CLASS="drhed">More:</SPAN>&nbsp;<span class="bls">'
            '<A HREF="https://a.example/1">A</A>, <A HREF="https://b.example/2">B</A></span></DIV>')
    techmeme = attention_sources.parse_techmeme(page)
    check(techmeme[0]["title"] == "Lead story" and len(techmeme[0]["more"]) == 2 and techmeme[0]["size"] == 3,
          techmeme)

    event = {"did": "did:plc:secret", "time_us": END_S * 1_000_000, "commit": {
        "operation": "create", "collection": "app.bsky.feed.post",
        "record": {"text": "worth reading", "embed": {"$type": "app.bsky.embed.external", "external": {
            "uri": "https://pub.example/a", "title": "Quasar 9 ships", "description": "Acme's new chip"}},
            "facets": [{"features": [{"$type": "app.bsky.richtext.facet#link", "uri": "https://b.example/2"}]}]}}}
    post = attention_sources.link_post_row(event)
    check(post["urls"] == ["https://b.example/2", "https://pub.example/a"], post)
    check("did:plc" not in json.dumps(post) and len(post["author"]) == 16, "author identity must be hashed")
    plain = {"did": "did:plc:x", "commit": {"operation": "create", "collection": "app.bsky.feed.post",
                                             "record": {"text": "no links here"}}}
    check(attention_sources.link_post_row(plain) is None, "posts without links are not inventory")


def test_same_event_counts_once_per_write_up_and_excludes_wires_and_self() -> None:
    relations = {AP_HEADLINE: "same", AP_HEADLINE + " - Wire Three": "same",
                 "Hands on with Acme's Quasar 9 accelerator launch": "same",
                 "Acme Quasar 9 accelerator": "same", "Acme Ships Quasar 9 Accelerator": "same",
                 "Acme Quasar 9 accelerator now shipping": "same"}
    found = _measure(FakeJev(relations))
    measures = found["measures"]
    check(measures["gkg_groups"] == 1 and measures["gkg_domains"] == 3, measures)
    check(measures["panel_groups"] == 1 and measures["panel_domains"] == 1, measures)
    check(measures["pr_copies"] == 1, measures)
    check(measures["bsky_sharers_sampled"] == 2 and measures["bsky_sharers_est"] == 40, measures)
    check(measures["hn_points"] == 120 and measures["hn_comments"] == 40, measures)
    check(found["recent"]["gkg_groups"] == 1 and found["recent"]["panel_groups"] == 1, found["recent"])
    check(found["first_seen"] == END_S - 30000, found["first_seen"])
    check(all("earnings" not in sample["title"] for sample in found["samples"]), found["samples"])


def test_related_coverage_counts_at_half_weight() -> None:
    relations = {AP_HEADLINE: "related", "Hands on with Acme's Quasar 9 accelerator launch": "same"}
    measures = _measure(FakeJev(relations))["measures"]
    check(measures["gkg_groups"] == 0.5 and measures["gkg_domains"] == 1.0, measures)
    check(measures["panel_groups"] == 1.0, measures)


def test_a_failed_adjudication_is_reported_per_story_and_stops_during_an_outage() -> None:
    class DownFor:
        def __init__(self, headline: str | None) -> None:
            self.headline, self.calls = headline, 0

        def ask(self, purpose: str, state: dict, questions: dict) -> dict:
            self.calls += 1
            if self.headline is None or state["candidate"]["headline"] == self.headline:
                raise JevUnavailable("server", "HTTP 503")
            return FakeJev({AP_HEADLINE: "same"}).ask(purpose, state, questions)

    index = attention_match.Index(_rows())
    other = {**CANDIDATE, "title": "Other Quasar 9 accelerator story"}
    work = [(CANDIDATE, attention_match.retrieve(CANDIDATE, index)), (other, attention_match.retrieve(other, index))]
    failed = attention_match.Adjudicator(DownFor(CANDIDATE["title"])).adjudicate(work)
    check(failed == {0}, failed)
    check(any(doc.get("decided_by") == "jev" for doc in work[1][1]), work[1][1])
    check(all(doc.get("decided_by") in (None, "url") for doc in work[0][1]), "failed story must not be guessed")
    posts: list[int] = []

    class Down:
        status_code, headers = 503, {}

    def post(*args, **kwargs):
        posts.append(1)
        return Down()

    outage = JevClient("key", sleep=lambda seconds: None, post=post)
    many = [(CANDIDATE, attention_match.retrieve(CANDIDATE, index)) for _ in range(20)]
    check(attention_match.Adjudicator(outage).adjudicate(many) == set(range(20)), "every story reported")
    # The client's breaker stops the outage: at most the in-flight asks when it opens are sent.
    asks = outage.usage()["purposes"]["news.relation"]
    check(outage.usage()["failures"] < outage.breaker + attention_match.JEV_WORKERS, outage.usage())
    check(asks["asks"] == 20 and len(posts) == 3 * outage.usage()["failures"], (asks, len(posts)))


def test_measured_zero_is_not_unavailable() -> None:
    empty = {"measures": {}, "recent": {}, "adjudication": {"documents": 3, "jev": 3}}
    zero, _ = measured_attention(empty, section="world", measured_sources=ALL_SOURCES,
                                 references=DEFAULT_REFERENCE, window_end=WINDOW_END)
    check(zero["status"] == "no_matches", zero)
    check(zero["attention_now"] == 0 and zero["digest_prominence"] == 0 and zero["confidence"] > 0, zero)
    check(set(zero["normalized_signals"]) == set(section_sources("world")), zero)


def test_a_missing_source_is_left_out_instead_of_counted_as_zero() -> None:
    found = {"measures": {"gkg_groups": 6, "gkg_domains": 8, "techmeme_weight": 1.0, "techmeme_more": 4},
             "recent": {}, "adjudication": {"jev": 5}}

    def attention_with(measured: frozenset[str]) -> dict:
        return measured_attention(found, section="ai-tech", measured_sources=measured,
                                  references=DEFAULT_REFERENCE, window_end=WINDOW_END)[0]

    complete = attention_with(ALL_SOURCES)
    panel_failed = attention_with(ALL_SOURCES - {"panel"})
    check("panel" not in panel_failed["normalized_signals"], panel_failed)
    check(panel_failed["evidence"]["sources_excluded"] == ["panel"], panel_failed)
    # Measured-and-zero panel coverage pulls the blend down; a failed panel does not.
    check(panel_failed["digest_prominence"] > complete["digest_prominence"], (panel_failed, complete))
    check(panel_failed["confidence"] < complete["confidence"], (panel_failed, complete))
    nothing, magnitudes = measured_attention(found, section="ai-tech", measured_sources=frozenset(),
                                             references=DEFAULT_REFERENCE, window_end=WINDOW_END)
    check(nothing["status"] == "unavailable" and nothing["confidence"] == 0 and magnitudes == {}, nothing)
    # Hacker News feeds only the tech sections.
    check("hn" not in section_sources("world") and "hn" in section_sources("agents"), section_sources("world"))


def test_failed_jev_importance_leaves_only_that_story_at_editorial_points() -> None:
    class Flaky:
        def ask(self, purpose: str, state: dict, questions: dict) -> dict:
            if state["story"]["headline"] == "Second":
                raise JevUnavailable("server", "HTTP 500")
            return {
                "consequence": {"type": "score", "score": 3.0, "confidence": 0.8},
                "scope": {"type": "score", "score": 3.0, "confidence": 0.8},
                **{key: {"type": "noul", "noul": 0.0} for key in ("routine", "binding", "harm", "first", "opinion")},
            }
    judged, failures = assess_importance([{"title": "First"}, {"title": "Second"}], Flaky(), section_label="World")
    check(judged[0] is not None and judged[1] is None and failures == 1, judged)
    check(importance_score("medium", judged[1]) == EDITORIAL_POINTS["medium"], judged)


def test_reference_scales_follow_history_once_it_is_deep_enough() -> None:
    shallow = reference_scales({"gkg": [1.0] * (REFERENCE_MIN_SAMPLES - 1)})
    check(shallow == DEFAULT_REFERENCE, shallow)
    deep = reference_scales({"gkg": [float(value) for value in range(1, 41)]})
    check(deep["gkg"] == 36.0 and deep["panel"] == DEFAULT_REFERENCE["panel"], deep)
    found = {"measures": {"gkg_groups": 3, "gkg_domains": 3}, "recent": {}, "adjudication": {"jev": 1}}
    attention, magnitudes = measured_attention(
        found, section="world", measured_sources=ALL_SOURCES,
        references={**DEFAULT_REFERENCE, "gkg": 2.0}, window_end=WINDOW_END)
    check(magnitudes["gkg"] > 2.0 and attention["normalized_signals"]["gkg"] == 100.0, attention)


def test_importance_rewards_broad_consequence_and_discounts_routine_updates() -> None:
    def answers(consequence: float, scope: float, **nouls: float) -> dict:
        values = {"routine": 0.0, "binding": 0.0, "harm": 0.0, "first": 0.0, "opinion": 0.0, **nouls}
        return {
            "consequence": {"type": "score", "score": consequence, "confidence": 0.8},
            "scope": {"type": "score", "score": scope, "confidence": 0.6},
            **{key: {"type": "noul", "noul": value} for key, value in values.items()},
        }

    major = importance_from_answers(answers(3.0, 4.0, harm=0.9))
    niche = importance_from_answers(answers(3.0, 0.0))
    routine = importance_from_answers(answers(2.0, 2.0, routine=0.95))
    check(major["score"] > niche["score"] > routine["score"], (major, niche, routine))
    check(major["confidence"] == 0.7, major)
    check(0.0 <= routine["score"] <= 100.0 and major["score"] <= 100.0, (major, routine))


def _evidence(level: float) -> dict:
    measures = {} if not level else {
        "gkg_groups": level, "gkg_domains": level, "panel_groups": level / 2, "panel_domains": level / 2,
        "bsky_sharers_est": 20 * level, "hn_points": 25 * level, "hn_comments": 5 * level,
        "techmeme_weight": 1.0, "techmeme_more": level,
    }
    return {"measures": measures, "recent": {}, "adjudication": {"documents": 4, "jev": 4},
            "samples": [], "first_seen": END_S - 7200}


def test_priority_blends_importance_with_confident_attention_only() -> None:
    items = [{**CANDIDATE, "title": "Quiet medium story"}, {**CANDIDATE, "title": "Loud medium story"}]
    scored, observations = score_attention(
        items, section="ai-hardware", evidence=[_evidence(0), _evidence(20)], importance=[None, None],
        measured_sources=ALL_SOURCES, references=DEFAULT_REFERENCE, window_end=WINDOW_END)
    quiet, loud = scored
    check(loud["priority_score"] > EDITORIAL_POINTS["medium"] > quiet["priority_score"], scored)
    check(sorted(scored, key=priority_sort_key, reverse=True)[0]["title"] == "Loud medium story", scored)
    check(observations[1]["priority_score"] == loud["priority_score"], observations[1])

    unadjudicated, rows = score_attention(
        [dict(CANDIDATE)], section="world", evidence=[{"unavailable_reason": "adjudication_failed"}],
        importance=[{"score": 20.0, "confidence": 1.0, "answers": {}}],
        measured_sources=ALL_SOURCES, references=DEFAULT_REFERENCE, window_end=WINDOW_END)
    story = unadjudicated[0]
    check(story["attention"]["status"] == "unavailable" and story["attention"]["confidence"] == 0, story)
    check(story["attention"]["evidence"]["unavailable_reason"] == "adjudication_failed", story)
    check(story["priority_score"] == importance_score("medium", story["jev_importance"]), story)
    check(rows[0]["magnitudes"] == {}, rows[0])


def test_ongoing_items_rank_on_importance_without_attention() -> None:
    older = score_ongoing([dict(CANDIDATE)], section="world",
                          importance=[{"score": 100.0, "confidence": 1.0, "answers": {}}])
    check(older[0]["attention"]["status"] == "out_of_scope" and older[0]["attention"]["confidence"] == 0, older)
    check(older[0]["priority_score"] == importance_score("medium", older[0]["jev_importance"]), older)
    check(older[0]["priority_score"] > EDITORIAL_POINTS["medium"], older)


def test_attention_never_rewrites_editorial_significance() -> None:
    unsupported_high = {**CANDIDATE, "editorial_significance": "high"}
    scored, observations = score_attention(
        [unsupported_high], section="ai-hardware", evidence=[_evidence(30)],
        importance=[{"score": 100.0, "confidence": 1.0, "answers": {}}],
        measured_sources=ALL_SOURCES, references=DEFAULT_REFERENCE, window_end=WINDOW_END)
    check(scored[0]["editorial_significance"] == "medium", scored[0])
    check(scored[0]["significance_validation"]["status"] == "downgraded", scored[0])
    check(observations[0]["editorial_significance"] == "medium", observations[0])


def test_high_significance_requires_grounded_broad_impact() -> None:
    deprecated = {
        "title": "Codex MCP server command deprecated",
        "summary": "OpenAI deprecated the command and directed users to a replacement app server.",
        "editorial_significance": "high",
        "significance_evidence": {
            "basis": "widespread_mandatory_migration",
            "affected_scope": "sector",
            "impact": "Users of the deprecated command can move to the replacement app server.",
        },
    }
    enforce_editorial_significance(deprecated)
    check(deprecated["editorial_significance"] == "medium", deprecated)
    check(
        "lacks demonstrated broad impact"
        in deprecated["significance_validation"]["reason"],
        deprecated,
    )

    binding = {
        "title": "National regulator adopts binding AI safety rule",
        "summary": "The national regulator adopted a binding AI safety rule covering every provider.",
        "editorial_significance": "high",
        "significance_evidence": {
            "basis": "binding_policy_or_law",
            "affected_scope": "broad",
            "impact": "The binding AI safety rule covers every national provider.",
        },
    }
    enforce_editorial_significance(binding)
    check(binding["editorial_significance"] == "high", binding)
    check(binding["significance_validation"]["status"] == "accepted", binding)


def test_priority_ties_use_evidence_not_discovery_order() -> None:
    lower = {
        "title": "Discovered first",
        "priority_score": 80.0,
        "editorial_significance": "high",
        "attention": {
            "digest_prominence": 60.0,
            "attention_now": 70.0,
            "confidence": 0.7,
        },
        "significance_evidence": {"affected_scope": "sector"},
    }
    higher = {
        "title": "Discovered second",
        "priority_score": 80.0,
        "editorial_significance": "medium",
        "attention": {
            "digest_prominence": 90.0,
            "attention_now": 80.0,
            "confidence": 0.8,
        },
        "significance_evidence": {"affected_scope": "broad"},
    }
    ranked = sorted([lower, higher], key=priority_sort_key, reverse=True)
    check(ranked[0]["title"] == "Discovered second", ranked)


def test_event_term_fallback_and_legacy_migration() -> None:
    item = {"title": "Nvidia unveils Rubin GPU platform", "importance": "high"}
    normalize_editorial_significance(item)
    check(item["editorial_significance"] == "high", item)
    check("importance" not in item, item)
    terms = event_terms(item)
    check(len(terms) == 1 and len(terms[0].split()) >= 3, terms)
    check("Nvidia" in terms[0], terms)


def test_canonicalize_publisher_url_maps_sample_hosts_only() -> None:
    canonical = canonicalize_publisher_url(
        "https://monorepo-sample1.nyt.net/2026/08/24/world/europe/"
        "russia-drones-autonomous-ai-kill-ukraine-war.html"
    )
    check(
        canonical
        == "https://www.nytimes.com/2026/08/24/world/europe/"
        "russia-drones-autonomous-ai-kill-ukraine-war.html",
        canonical,
    )
    check(
        canonicalize_publisher_url("https://sample2.nyt.net/story?ref=test")
        == "https://www.nytimes.com/story?ref=test",
        "query preserved",
    )
    for untouched in (
        "https://www.nytimes.com/2026/08/24/world/europe/story.html",
        "https://arstechnica.com/ai/2026/08/none",
        "https://blogs.nvidia.com/blog/2026/08/none",
        "",
        "not-a-url",
    ):
        check(canonicalize_publisher_url(untouched) == untouched, untouched)


def main() -> None:
    tests = [
        test_bulk_parsers_extract_titled_rows,
        test_same_event_counts_once_per_write_up_and_excludes_wires_and_self,
        test_related_coverage_counts_at_half_weight,
        test_a_failed_adjudication_is_reported_per_story_and_stops_during_an_outage,
        test_measured_zero_is_not_unavailable,
        test_a_missing_source_is_left_out_instead_of_counted_as_zero,
        test_failed_jev_importance_leaves_only_that_story_at_editorial_points,
        test_reference_scales_follow_history_once_it_is_deep_enough,
        test_importance_rewards_broad_consequence_and_discounts_routine_updates,
        test_priority_blends_importance_with_confident_attention_only,
        test_ongoing_items_rank_on_importance_without_attention,
        test_attention_never_rewrites_editorial_significance,
        test_high_significance_requires_grounded_broad_impact,
        test_priority_ties_use_evidence_not_discovery_order,
        test_event_term_fallback_and_legacy_migration,
        test_canonicalize_publisher_url_maps_sample_hosts_only,
    ]
    for test in tests:
        test()
        print(f"OK  {test.__name__}")
    print("ALL PASSED")


if __name__ == "__main__":
    main()
