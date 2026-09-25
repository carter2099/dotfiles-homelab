#!/usr/bin/env python3
"""Behavioral contracts for the static news publisher and email delivery."""

from __future__ import annotations

import json
import shutil
import sys
from html.parser import HTMLParser
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import news_publish as news  # noqa: E402
from workflow_state import WorkflowState  # noqa: E402


def check(condition: bool, message: object) -> None:
    if not condition:
        raise AssertionError(message)


def sample_publication(topic: dict, issue_date: str, marker: str) -> dict:
    return {
        "schema_version": 2,
        "ranking_schema_version": 3,
        "date": issue_date,
        "slug": topic["web_slug"],
        "title": topic["web_title"],
        "source_category": topic["category"],
        "status": "published",
        "notice": "",
        "standfirst": f"{marker} reporting details the verified developments shaping this section.",
        "fresh": [{
            "title": f"{marker} lead story",
            "url": f"https://example.com/{topic['web_slug']}/lead",
            "source_domain": "example.com",
            "date_published": issue_date,
            "summary": f"{marker} source-backed summary with the material facts.",
            "category": "News",
            "editorial_significance": "high",
            "priority_score": 80.0,
            "priority_explanation": "High significance with observed coverage.",
        }],
        "ongoing": [{
            "title": f"{marker} developing story",
            "url": f"https://example.com/{topic['web_slug']}/developing",
            "summary": f"{marker} ongoing source-backed summary.",
            "category": "Developing",
            "editorial_significance": "high",
            "priority_score": 70.0,
            "why_still_relevant": "A second-day source established a material change.",
        }],
        "generated_at": f"{issue_date}T12:00:00+00:00",
    }


def write_assets(root: Path) -> Path:
    assets = root / "assets"
    assets.mkdir()
    (assets / "news.css").write_text("body { color: #171716; }")
    (assets / "news.js").write_text("void 0;")
    return assets


def test_external_link_arrow_uses_neutral_ink() -> None:
    css_path = Path(__file__).resolve().parents[1] / "news" / "assets" / "news.css"
    css = css_path.read_text()
    block = css.split(".external {", 1)[1].split("}", 1)[0]
    check("color: var(--ink);" in block, block)
    check("color: var(--accent);" not in block, block)
    for forbidden in ("#7a3030", "#5f2020", "#7b2f2f", "122, 48, 48"):
        check(forbidden not in css.casefold(), forbidden)
    check("--accent: #59616b;" in css, css[:300])


def test_legacy_html_migration() -> None:
    parser = news.LegacyDigestParser()
    parser.feed("""
      <h1>Gaming Digest</h1><p>June 15, 2026</p>
      <p>A sufficiently detailed editorial introduction for the historical edition.</p>
      <h2>Fresh — Last 24 Hours</h2>
      <p><a href="https://example.com/fresh">Fresh title</a><span> · Industry</span></p>
      <p>Fresh factual summary.</p>
      <h2>Recent &amp; Relevant</h2>
      <p><a href="https://example.com/ongoing">Ongoing title</a><span> · Policy</span></p>
      <p>Ongoing factual summary.</p><p>↳ Material second-day change.</p>
    """)
    check(parser.standfirst.startswith("A sufficiently"), parser.standfirst)
    check(parser.fresh[0]["category"] == "Industry", parser.fresh)
    check(parser.fresh[0]["summary"] == "Fresh factual summary.", parser.fresh)
    check(parser.ongoing[0]["why_still_relevant"] == "Material second-day change.", parser.ongoing)


def test_digest_meta_and_truncated_copy_are_rewritten() -> None:
    topic = news.TOPICS["ai-hardware"]
    publication = news._normalize_publication({
        "status": "published",
        "intro": "Today’s digest leads with new accelerator designs at Ho",
        "fresh": [{
            "title": "New accelerator designs",
            "url": "https://example.com/hardware",
            "summary": "Chipmakers introduced new accelerator designs with higher memory bandwidth. Production begins next quarter.",
            "editorial_significance": "high",
            "priority_score": 90.0,
        }],
        "ongoing": [],
    }, topic, "2026-08-25")
    standfirst = publication["standfirst"]
    check("digest" not in standfirst.casefold(), standfirst)
    check(standfirst.endswith("."), standfirst)
    check("higher memory bandwidth" in standfirst, standfirst)




def test_front_page_guarantees_sections_then_applies_global_floor() -> None:
    date_editions = {}
    secondary_scores = [64.0, 66.0, 75.0, 85.0, 95.0]
    for index, key in enumerate(news.TOPIC_ORDER):
        topic = news.TOPICS[key]
        date_editions[topic["web_slug"]] = {
            "fresh": [
                {
                    "title": f"{topic['web_title']} section lead",
                    "url": f"https://example.com/{topic['web_slug']}/lead",
                    "priority_score": 100.0 - index,
                    "editorial_significance": "medium",
                    "attention": {
                        "digest_prominence": 100.0 - index,
                        "attention_now": 90.0 - index,
                        "confidence": 0.8,
                    },
                },
                {
                    "title": f"{topic['web_title']} secondary",
                    "url": f"https://example.com/{topic['web_slug']}/secondary",
                    "priority_score": secondary_scores[index],
                    "editorial_significance": "medium",
                    "attention": {
                        "digest_prominence": secondary_scores[index],
                        "attention_now": secondary_scores[index],
                        "confidence": 0.7,
                    },
                },
            ],
            "ongoing": [],
        }
    lead, sections = news._front_page_sections(date_editions)
    selected = [story for section in sections for story in section["stories"]]
    check(len(sections) == 5, sections)
    check(all(section["stories"] for section in sections), sections)
    check(len(selected) == 9, selected)
    check(
        "https://example.com/ai-tech/secondary"
        not in {story["url"] for story in selected},
        selected,
    )
    check(lead and lead["priority_score"] == 100.0, lead)
    class EmailLinks(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self.links = []
            self.current = None

        def handle_starttag(self, tag, attrs) -> None:
            if tag == "a":
                self.current = [dict(attrs).get("href"), ""]
                self.links.append(self.current)

        def handle_data(self, data) -> None:
            if self.current is not None:
                self.current[1] += data

        def handle_endtag(self, tag) -> None:
            if tag == "a":
                self.current = None

    email = EmailLinks()
    email.feed(news.render_headline_email("2026-08-25", date_editions))
    expected_links = [
        [f'{news.BASE_URL}/2026-08-25/{story["_section_slug"]}/', story["title"]]
        for story in selected
    ]
    check(email.links[:-1] == expected_links, email.links)
    check(email.links[-1][0] == f"{news.BASE_URL}/2026-08-25/", email.links)


def test_publish_builds_separate_history_and_one_email() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        digests = root / "digests"
        news_dir = digests / "news"
        assets = write_assets(root)
        current_date = "2026-08-25"
        older_date = "2026-06-15"
        interrupted_state: WorkflowState | None = None

        for key in news.TOPIC_ORDER:
            topic = news.TOPICS[key]
            run_dir = digests / topic["category"] / current_date
            run_dir.mkdir(parents=True)
            marker = topic["web_title"]
            publication = sample_publication(topic, current_date, marker)
            if key == "ai-tech":
                publication["fresh"][0]["title"] = "AI <script>alert(1)</script> lead"
            if key == "gaming":
                publication["fresh"][0]["priority_score"] = 99.0
            publication_path = run_dir / "publication.json"
            if key == "ai-tech":
                interrupted_state = WorkflowState(
                    run_dir, "daily-news", run_id=run_dir.name
                )
                interrupted_state.begin_phase(
                    "research",
                    inputs={"fixture": "interrupted"},
                    artifact_path=run_dir / "01-research-raw.json",
                )
                interrupted_state.begin_phase(
                    "archive",
                    inputs={"fixture": "publication"},
                    artifact_path=publication_path,
                    schema_version=news.PUBLICATION_SCHEMA_VERSION,
                )
                interrupted_state.complete_json("archive", publication)
            else:
                publication_path.write_text(json.dumps(publication))

        gaming_dir = digests / news.TOPICS["gaming"]["category"]
        (gaming_dir / f"{older_date}.html").write_text("""
          <h1>Gaming Digest</h1><p>June 15, 2026</p>
          <p>Historical gaming briefing with enough detail to qualify as an introduction.</p>
          <h2>Fresh — Last 24 Hours</h2>
          <p><a href="https://example.com/legacy">Legacy gaming story</a><span> · Industry</span></p>
          <p>A historical source-backed summary.</p>
        """)

        sent: list[tuple[str, str, list[str]]] = []

        def fake_send(subject: str, body: str, recipients: list[str]) -> None:
            sent.append((subject, body, recipients))

        result = news.publish(
            current_date,
            digests_dir=digests,
            news_dir=news_dir,
            asset_dir=assets,
            send_func=fake_send,
        )
        check(result["categories"] == 5, result)
        check(result["dates"] == 2, result)
        check(result["email_sent"], result)
        check(len(sent) == 1, sent)
        check(interrupted_state is not None, "interrupted fixture was not created")
        research = interrupted_state.phase_record("research")
        check(research["status"] == "aborted", research)
        check(research["completion_outcome"] == "aborted", research)
        connection = interrupted_state._connect()
        try:
            run = connection.execute(
                """
                SELECT status, completed_at, error
                FROM workflow_runs
                WHERE workflow = ? AND run_id = ?
                """,
                (interrupted_state.workflow, interrupted_state.run_id),
            ).fetchone()
        finally:
            connection.close()
        check(run["status"] == "succeeded", dict(run))
        check(run["completed_at"] is not None, dict(run))
        check(run["error"] is None, dict(run))
        email_body = sent[0][1]
        check("source-backed summary" not in email_body, email_body)
        check(
            f'href="{news.BASE_URL}/{current_date}/"' in email_body,
            email_body,
        )
        for key in news.TOPIC_ORDER:
            topic = news.TOPICS[key]
            marker = topic["web_title"].replace("&", "&amp;")
            expected = (
                "AI &lt;script&gt;alert(1)&lt;/script&gt; lead"
                if key == "ai-tech"
                else f"{marker} lead story"
            )
            check(expected in email_body, email_body)
            check(f"{marker} reporting details" not in email_body, email_body)
            check(f"{marker} developing story" not in email_body, email_body)

        current = news_dir / "current"
        check(current.is_symlink(), current)
        ai_page = (current / current_date / "ai-tech" / "index.html").read_text()
        check("&lt;script&gt;alert(1)&lt;/script&gt;" in ai_page, ai_page)
        check("Gaming lead story" not in ai_page, "category content leaked onto AI page")
        front_page = (current / current_date / "index.html").read_text()
        check("<h1>Front Page</h1>" in front_page, front_page)
        check("Priority combines editorial consequence" not in front_page, front_page)
        check("<span>Updated daily.</span>" in front_page, front_page)
        check("/assets/news.css?v=6" in front_page, front_page)
        for key in news.TOPIC_ORDER:
            marker = news.TOPICS[key]["web_title"]
            expected = (
                "AI &lt;script&gt;alert(1)&lt;/script&gt; lead"
                if key == "ai-tech"
                else f"{marker} lead story".replace("&", "&amp;")
            )
            check(expected in front_page, marker)
            category_page = (
                current / current_date / news.TOPICS[key]["web_slug"] / "index.html"
            ).read_text()
            check('<section class="introduction"' not in category_page, category_page)
            check('id="briefing-heading"' not in category_page, category_page)
        stored = json.loads(
            (news_dir / "publications" / current_date / "gaming.json").read_text()
        )
        check(stored["ranking_schema_version"] == 3, stored)
        check("FRONT PAGE" in (current / "archive" / "index.html").read_text().upper(),
              "archive omitted front-page links")
        check((current / current_date / "gaming" / "index.html").exists(), "gaming page missing")
        check((current / older_date / "gaming" / "index.html").exists(), "historical page missing")
        check("Legacy gaming story" in (current / older_date / "gaming" / "index.html").read_text(),
              "legacy story not migrated")
        check((current / "archive" / "index.html").exists(), "archive page missing")

        second = news.publish(
            current_date,
            digests_dir=digests,
            news_dir=news_dir,
            asset_dir=assets,
            send_func=fake_send,
        )
        check(not second["email_sent"], second)
        check(len(sent) == 1, f"summary email sent {len(sent)} times")
        check(len(list((news_dir / "releases").iterdir())) == 2, "rollback release retention failed")


def test_stateful_publication_requires_matching_archive_record() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        run_dir = Path(temporary) / "2026-08-25"
        run_dir.mkdir()
        topic = news.TOPICS["ai-tech"]
        publication_path = run_dir / "publication.json"
        publication = sample_publication(topic, run_dir.name, "Stateful")
        state = WorkflowState(run_dir, "daily-news", run_id=run_dir.name)
        state.begin_phase(
            "archive",
            inputs={"fixture": 1},
            artifact_path=publication_path,
            schema_version=news.PUBLICATION_SCHEMA_VERSION,
        )
        state.complete_json("archive", publication)

        loaded = news._publication_from_run(topic, run_dir.name, run_dir)
        check(loaded is not None, "valid state-owned publication was rejected")

        publication["fresh"][0]["title"] = "Tampered after completion"
        publication_path.write_text(json.dumps(publication))
        (run_dir / "06-curated.json").write_text(json.dumps(publication))
        try:
            news._publication_from_run(topic, run_dir.name, run_dir)
            fell_back = True
        except news.PublicationStateError:
            fell_back = False
        check(not fell_back, "stateful run fell back to tampered or legacy artifacts")


def test_publications_frozen_after_mail_sent() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        digests = root / "digests"
        news_dir = digests / "news"
        current_date = "2026-08-25"

        for key in news.TOPIC_ORDER:
            topic = news.TOPICS[key]
            run_dir = digests / topic["category"] / current_date
            run_dir.mkdir(parents=True)
            (run_dir / "publication.json").write_text(json.dumps(
                sample_publication(topic, current_date, topic["web_title"])
            ))

        publications_dir = news_dir / "publications"
        news.sync_publications(digests_dir=digests, publications_dir=publications_dir)
        frozen_path = publications_dir / current_date / "ai-tech.json"
        archived = json.loads(frozen_path.read_text())

        mail_dir = news_dir / "mail"
        mail_dir.mkdir(parents=True)
        (mail_dir / f"{current_date}.sent.json").write_text(json.dumps({
            "sent_at": "2026-08-25T15:42:49+00:00",
            "date": current_date,
        }))

        topic = news.TOPICS["ai-tech"]
        rerun = sample_publication(topic, current_date, "RERUN")
        rerun["fresh"][0]["title"] = "Rerun replacement story"
        (digests / topic["category"] / current_date / "publication.json").write_text(
            json.dumps(rerun)
        )

        editions = news.sync_publications(
            digests_dir=digests, publications_dir=publications_dir
        )
        after = json.loads(frozen_path.read_text())
        check(after == archived, "archived publication changed after mail was sent")
        check(
            editions[current_date]["ai-tech"]["fresh"][0]["title"]
            != "Rerun replacement story",
            "mailed edition regenerated after shipping",
        )


def test_front_page_dedups_same_event_before_section_leads() -> None:
    """Duplicate events are removed before each section chooses its lead.

    Regression for 2026-09-22: Googlebook led AI Hardware (Ars) and World
    (Google's blog) on one front page, and raw-link comparison let the same
    canonical article through under tracking/host variants.
    """
    def story(title: str, url: str, event: str, score: float, prominence: float) -> dict:
        return {
            "title": title,
            "url": url,
            "event": event,
            "summary": f"{title}.",
            "editorial_significance": "high",
            "priority_score": score,
            "attention": {"digest_prominence": prominence, "confidence": 0.5},
        }

    date_editions = {
        "ai-tech": {"fresh": [story(
            "Chipmaker reports record quarterly revenue",
            "https://www.example.com/shared-report?utm_source=feed",
            "A chipmaker reported record quarterly revenue.", 90.0, 90.0,
        )], "ongoing": []},
        "agents": {"fresh": [
            story(
                "Chipmaker reports record quarterly revenue",
                "https://example.com/shared-report/",
                "A chipmaker reported record quarterly revenue.", 85.0, 85.0,
            ),
            story(
                "Agent framework adds sandboxed tool execution",
                "https://agents.example/framework-sandbox",
                "An agent framework added sandboxed tool execution.", 50.0, 50.0,
            ),
        ], "ongoing": []},
        "ai-hardware": {"fresh": [
            story(
                "Googlebooks launch October 4 starting at $899—here are the five "
                "models you can preorder today",
                "https://arstechnica.com/gadgets/2026/09/googlebook-laptops-launch/",
                "Google launched Googlebook, its first Android-based laptop platform "
                "with Snapdragon X Elite and Intel Core Ultra models designed for "
                "Gemini Intelligence, starting at $899.", 100.0, 95.0,
            ),
            story(
                "Memory makers raise HBM output targets",
                "https://hardware.example/hbm-output",
                "Memory makers raised HBM output targets.", 60.0, 60.0,
            ),
        ], "ongoing": []},
        "world": {"fresh": [
            story(
                "Googlebook: The laptop Australian Android phone owners have been "
                "waiting for",
                "https://blog.google/intl/en-au/products/devices-services/googlebook/",
                "Google announced Googlebook, a new laptop category blending Android "
                "and ChromeOS with Gemini AI and phone integration.", 100.0, 90.0,
            ),
            story(
                "Parliament passes national budget after overnight session",
                "https://world.example/budget-vote",
                "A parliament passed the national budget.", 55.0, 55.0,
            ),
        ], "ongoing": []},
    }
    lead, sections = news._front_page_sections(date_editions)
    leads = {section["slug"]: section["stories"][0]["url"] for section in sections if section["stories"]}
    check(
        leads.get("world") == "https://world.example/budget-vote",
        f"World led with a duplicate event instead of its next story: {leads!r}",
    )
    check(
        leads.get("agents") == "https://agents.example/framework-sandbox",
        f"Agents led with a canonical-URL duplicate: {leads!r}",
    )
    selected = [story["url"] for section in sections for story in section["stories"]]
    googlebook = [url for url in selected if "googlebook" in url]
    check(len(googlebook) == 1, f"Googlebook appeared {len(googlebook)} times: {selected!r}")
    check(lead is not None and "arstechnica" in lead["url"], lead)

    # Two stories sharing only a rare-ish verb and a name are distinct events
    # (2026-09-24: Trump/Zelensky meeting vs. Trump/Xi export-controls debate).
    distinct = {
        "world": {"fresh": [story(
            "Trump to meet with Zelensky as Russia-Ukraine attacks intensify",
            "https://world.example/zelensky-meeting",
            "Trump will meet Zelensky as attacks intensify.", 90.0, 90.0,
        )], "ongoing": []},
        "ai-hardware": {"fresh": [story(
            "AI export controls debate rages as Trump, Xi meet",
            "https://hardware.example/export-controls",
            "Chip export controls are debated during the summit.", 80.0, 80.0,
        )], "ongoing": []},
    }
    _, sections = news._front_page_sections(distinct)
    check(
        all(section["stories"] for section in sections),
        f"distinct events were merged: {sections!r}",
    )


def test_publisher_never_silently_uses_stale_or_out_of_window_content() -> None:
    """Invalid run state never falls back to old HTML; Fresh dates are rechecked."""
    issue_date = "2026-09-24"
    topic = news.TOPICS["ai-tech"]

    def stateful_run(digests: Path, publication: dict) -> Path:
        run_dir = digests / topic["category"] / issue_date
        run_dir.mkdir(parents=True)
        state = WorkflowState(run_dir, "daily-news", run_id=run_dir.name)
        state.begin_phase(
            "archive",
            inputs={"fixture": 1},
            artifact_path=run_dir / "publication.json",
            schema_version=news.PUBLICATION_SCHEMA_VERSION,
        )
        state.complete_json("archive", publication)
        (digests / topic["category"] / f"{issue_date}.html").write_text("""
          <h1>AI &amp; Tech</h1><p>September 24, 2026</p>
          <p>An older rendered briefing with enough detail to qualify as an introduction.</p>
          <h2>Fresh — Last 24 Hours</h2>
          <p><a href="https://example.com/stale-html">Stale HTML story</a><span> · Industry</span></p>
          <p>An older rendered summary.</p>
        """)
        return run_dir

    # Corrupt state (artifact no longer matches its recorded hash).
    with tempfile.TemporaryDirectory() as temporary:
        digests = Path(temporary) / "digests"
        run_dir = stateful_run(digests, sample_publication(topic, issue_date, "Valid"))
        tampered = sample_publication(topic, issue_date, "Tampered")
        (run_dir / "publication.json").write_text(json.dumps(tampered))
        editions = news.sync_publications(
            digests_dir=digests, publications_dir=digests / "news" / "publications"
        )
        titles = [
            story["title"]
            for story in editions.get(issue_date, {}).get("ai-tech", {}).get("fresh", [])
        ]
        check(
            "Stale HTML story" not in titles and "Tampered lead story" not in titles,
            f"corrupt run state silently published fallback content: {titles!r}",
        )

    # Missing state for a run created after workflow-state adoption.
    with tempfile.TemporaryDirectory() as temporary:
        digests = Path(temporary) / "digests"
        run_dir = stateful_run(digests, sample_publication(topic, issue_date, "Valid"))
        (run_dir / "workflow-state.sqlite3").unlink()
        editions = news.sync_publications(
            digests_dir=digests, publications_dir=digests / "news" / "publications"
        )
        check(
            "ai-tech" not in editions.get(issue_date, {}),
            f"stateless post-adoption run was published: {editions.get(issue_date)!r}",
        )

    # A valid publication still passes, minus Fresh stories outside the window.
    with tempfile.TemporaryDirectory() as temporary:
        digests = Path(temporary) / "digests"
        publication = sample_publication(topic, issue_date, "Window")
        base = publication["fresh"][0]
        publication["fresh"] = [
            {**base, "title": "In-window story", "url": "https://example.com/in",
             "date_published": "2026-09-23", "date_confirmed": "2026-09-23"},
            {**base, "title": "Three-day-old story", "url": "https://example.com/old",
             "date_published": "2026-09-21", "date_confirmed": "2026-09-21"},
            {**base, "title": "Future-dated story", "url": "https://example.com/future",
             "date_published": "2026-09-27", "date_confirmed": "2026-09-27"},
        ]
        stateful_run(digests, publication)
        editions = news.sync_publications(
            digests_dir=digests, publications_dir=digests / "news" / "publications"
        )
        titles = [story["title"] for story in editions[issue_date]["ai-tech"]["fresh"]]
        check(titles == ["In-window story"], f"Fresh window not rechecked at publish: {titles!r}")

        # Once the run directory is cleaned, the imported durable copy remains
        # the section's record; the rendered HTML never replaces it.
        shutil.rmtree(digests / topic["category"] / issue_date)
        editions = news.sync_publications(
            digests_dir=digests, publications_dir=digests / "news" / "publications"
        )
        titles = [story["title"] for story in editions[issue_date]["ai-tech"]["fresh"]]
        check(titles == ["In-window story"], f"cleaned run lost its durable publication: {titles!r}")


def main() -> None:
    tests = [
        test_legacy_html_migration,
        test_external_link_arrow_uses_neutral_ink,
        test_digest_meta_and_truncated_copy_are_rewritten,
        test_front_page_guarantees_sections_then_applies_global_floor,
        test_publish_builds_separate_history_and_one_email,
        test_stateful_publication_requires_matching_archive_record,
        test_publications_frozen_after_mail_sent,
        test_front_page_dedups_same_event_before_section_leads,
        test_publisher_never_silently_uses_stale_or_out_of_window_content,
    ]
    for test in tests:
        test()
        print(f"OK  {test.__name__}")
    print("ALL PASSED")


if __name__ == "__main__":
    main()
