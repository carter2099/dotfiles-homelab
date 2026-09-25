#!/usr/bin/env python3
"""P0b memoirs: long sessions are checked in chunks, never from a truncated transcript
(F258), and an up-to-date memoir costs no model call (J008). Fake model calls only."""
from __future__ import annotations
import json
import os
import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from steward import setup

START = datetime(2026, 9, 24, 1, 0, tzinfo=timezone.utc)


def packet(obj):
    return "```json\n" + json.dumps(obj) + "\n```"


class FakeModel:
    """Routes each no-tools call by its prompt; records every prompt."""

    def __init__(self, fail_chunk=None):
        self.fail_chunk = fail_chunk
        self.chunk_prompts, self.merge_prompts, self.final_prompts = [], [], []
        self.chunk_timeouts = []

    def __call__(self, prompt, **kwargs):
        if prompt.startswith("You are condensing one chunk"):
            self.chunk_prompts.append(prompt)
            self.chunk_timeouts.append(kwargs["timeout"])
            index = int(re.search(r"CHUNK (\d+) of", prompt).group(1))
            if index == self.fail_chunk:
                raise RuntimeError("model timeout")
            return packet({"notes": "saw " + ",".join(re.findall(r"MSG-\d{3}", prompt))})
        if prompt.startswith("You are merging"):
            self.merge_prompts.append(prompt)
            return packet({"notes": "merged " + ",".join(re.findall(r"MSG-\d{3}", prompt)[::10])})
        if prompt.startswith("You are a light filter judge"):
            return packet({"verdict": "document", "reason": "real work"})
        self.final_prompts.append(prompt)
        if prompt.startswith("You are writing a session memoir"):
            return packet({"label": "long-session", "markdown": "**Topics:** everything"})
        return packet({"verdict": "update", "reason": "missing later part",
                       "updated_markdown": "**Topics:** whole session"})


class MemoirChunkTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.memoir = self.dir / "memoir.md"
        self.original = "# memoir\n**Topics:** first half, middle, second half\n"
        self.memoir.write_text(self.original)
        self.memoir_written_at(START - timedelta(hours=1))
        self.entry = {"date": "2026-09-24", "project": "-", "title": "t",
                      "started": START.isoformat(), "session_id": "s1"}

    def memoir_written_at(self, when):
        os.utime(self.memoir, (when.timestamp(), when.timestamp()))

    def session(self, messages, size=5000):
        path = self.dir / "session.jsonl"
        with path.open("w") as out:
            for i in range(messages):
                out.write(json.dumps({
                    "type": "message",
                    "timestamp": (START + timedelta(minutes=i)).isoformat().replace("+00:00", "Z"),
                    "message": {"role": "user" if i % 2 else "assistant",
                                "content": f"MSG-{i:03d} " + "x" * size},
                }) + "\n")
        return path

    def judge(self, path, model):
        with patch.object(setup, "_call_omp_p", side_effect=model):
            return setup._judge_existing_memoir(path, self.entry, self.memoir)

    def test_long_session_maps_every_chunk_and_reduce_sees_the_middle(self):
        path = self.session(60)  # ~300k chars, far beyond the old 40k truncation
        model = FakeModel()
        result = self.judge(path, model)
        self.assertEqual(result["action"], "updated")
        self.assertGreater(result["chunks"], 5)
        self.assertEqual(len(model.chunk_prompts), result["chunks"])
        mapped = set(re.findall(r"MSG-\d{3}", "".join(model.chunk_prompts)))
        self.assertEqual(mapped, {f"MSG-{i:03d}" for i in range(60)})
        (reduce_prompt,) = model.final_prompts
        self.assertIn("MSG-030", reduce_prompt)  # middle of the session, via its notes
        self.assertIn("whole session", self.memoir.read_text())
        self.assertIn("updated: 2026-09-24T01:59:00+00:00", self.memoir.read_text())

    def test_notes_over_budget_are_merged_before_reduce(self):
        path = self.session(60)
        model = FakeModel()
        with patch.object(setup, "MEMOIR_NOTES_BUDGET", 200):
            result = self.judge(path, model)
        self.assertEqual(result["action"], "updated")
        self.assertTrue(model.merge_prompts)
        self.assertIn("merged", model.final_prompts[0])
        self.assertIn("MSG-030", model.final_prompts[0])

    def test_failing_chunk_leaves_memoir_unchanged(self):
        path = self.session(60)
        model = FakeModel(fail_chunk=3)
        result = self.judge(path, model)
        self.assertEqual(result["action"], "judge_error")
        self.assertEqual(model.final_prompts, [])
        self.assertEqual(self.memoir.read_text(), self.original)

    def test_up_to_date_memoir_makes_no_model_call(self):
        path = self.session(60)
        self.memoir_written_at(START + timedelta(hours=2))
        model = FakeModel()
        result = self.judge(path, model)
        self.assertEqual(result["action"], "up_to_date")
        self.assertEqual(model.chunk_prompts + model.final_prompts, [])
        self.assertEqual(self.memoir.read_text(), self.original)

    def test_frontmatter_updated_wins_over_mtime(self):
        path = self.session(3)
        self.memoir.write_text("---\ntitle: t\nupdated: 2026-09-24T00:30:00+00:00\n---\n"
                               + self.original)  # fresh mtime, stale coverage
        model = FakeModel()
        result = self.judge(path, model)
        self.assertEqual(result["action"], "updated")
        self.assertEqual(model.chunk_prompts, [])  # short session: whole transcript inline

    def test_stale_memoir_of_60_chunk_session_maps_only_the_later_part(self):
        path = self.session(60, size=23000)  # one ~23k message per chunk: 60 chunks
        self.assertEqual(len(setup._chunk_blocks(setup._session_messages(path)[0])), 60)
        self.memoir_written_at(START + timedelta(minutes=44, seconds=30))
        model = FakeModel()
        result = self.judge(path, model)
        self.assertEqual(result["action"], "updated")
        self.assertEqual(result["chunks"], 15)
        mapped = set(re.findall(r"MSG-\d{3}", "".join(model.chunk_prompts)))
        self.assertEqual(mapped, {f"MSG-{i:03d}" for i in range(45, 60)})
        (extend_prompt,) = model.final_prompts
        self.assertIn(self.original.strip(), extend_prompt)  # earlier content kept in view
        self.assertIn("2026-09-24T01:44:30+00:00", extend_prompt)

    def test_later_part_over_delta_cap_is_skipped_untouched(self):
        path = self.session(60)
        model = FakeModel()
        with patch.object(setup, "MEMOIR_MAX_DELTA_CHUNKS", 3):
            result = self.judge(path, model)
        self.assertEqual(result["action"], "judge_skipped")
        self.assertIn("too long", result["reason"])
        self.assertEqual(model.chunk_prompts + model.final_prompts, [])
        self.assertEqual(self.memoir.read_text(), self.original)

    def test_extend_sees_whole_memoir_longer_than_6000_chars(self):
        path = self.session(3)
        self.original = "# memoir\n" + "- early bullet\n" * 600 + "- TAIL-BULLET kept\n"
        self.memoir.write_text(self.original)
        self.memoir_written_at(START - timedelta(hours=1))
        self.assertGreater(len(self.original), 6000)
        model = FakeModel()
        result = self.judge(path, model)
        self.assertEqual(result["action"], "updated")
        self.assertIn("TAIL-BULLET kept", model.final_prompts[0])

    def test_memoir_over_bound_is_skipped_untouched(self):
        path = self.session(3)
        self.original = "# memoir\n" + "x" * (setup.MEMOIR_MAX_MEMOIR_CHARS + 1)
        self.memoir.write_text(self.original)
        self.memoir_written_at(START - timedelta(hours=1))
        model = FakeModel()
        result = self.judge(path, model)
        self.assertEqual(result["action"], "judge_skipped")
        self.assertIn("memoir too long", result["reason"])
        self.assertEqual(model.final_prompts, [])
        self.assertEqual(self.memoir.read_text(), self.original)

    def test_earlier_mtime_wins_over_later_frontmatter(self):
        path = self.session(3)
        self.memoir.write_text("---\nupdated: 2026-09-24T05:00:00+00:00\n---\n" + self.original)
        self.memoir_written_at(START - timedelta(hours=1))  # file older than its claim
        model = FakeModel()
        result = self.judge(path, model)
        self.assertEqual(result["action"], "updated")

    def test_chunk_calls_are_capped_at_180s(self):
        path = self.session(60)
        model = FakeModel()
        with patch.object(setup, "_call_omp_p", side_effect=model):
            setup._judge_existing_memoir(path, self.entry, self.memoir,
                                         setup.time.monotonic() + 3600)
        self.assertTrue(model.chunk_timeouts)
        self.assertTrue(all(t <= 180 for t in model.chunk_timeouts))

    def test_passed_deadline_makes_no_call_and_leaves_memoir(self):
        path = self.session(60)
        model = FakeModel()
        with patch.object(setup, "_call_omp_p", side_effect=model), \
                self.assertRaises(setup._DeadlinePassed):
            setup._judge_existing_memoir(path, self.entry, self.memoir,
                                         setup.time.monotonic() - 1)
        self.assertEqual(model.chunk_prompts + model.final_prompts, [])
        self.assertEqual(self.memoir.read_text(), self.original)

    def test_new_memoir_over_whole_session_cap_is_skipped(self):
        path = self.session(60)
        model = FakeModel()
        with patch.object(setup, "MEMOIR_MAX_CHUNKS", 3), \
                patch.object(setup, "SESSION_MEMOIR_DIR", self.dir / "vault"), \
                patch.object(setup, "_call_omp_p", side_effect=model):
            result = setup._document_session(path, self.entry)
        self.assertEqual(result["action"], "summarizer_skipped")
        self.assertEqual(model.chunk_prompts + model.final_prompts, [])
        self.assertFalse((self.dir / "vault").exists())

    def test_new_memoir_of_long_session_uses_chunk_notes(self):
        path = self.session(60)
        model = FakeModel()
        vault = self.dir / "vault"
        with patch.object(setup, "SESSION_MEMOIR_DIR", vault), \
                patch.object(setup, "_call_omp_p", side_effect=model):
            result = setup._document_session(path, self.entry)
        self.assertEqual(result["action"], "documented")
        self.assertEqual(len(model.chunk_prompts), result["chunks"])
        (summary_prompt,) = model.final_prompts
        self.assertIn("MSG-030", summary_prompt)
        self.assertIn("everything", Path(result["memoir"]).read_text())


class ChunkBlocksTests(unittest.TestCase):
    def test_chunks_keep_order_split_at_boundaries_and_respect_limit(self):
        blocks = ["a" * 40, "b" * 40, "c" * 250, "d" * 10]
        chunks = setup._chunk_blocks(blocks, limit=100)
        self.assertTrue(all(len(c) <= 100 for c in chunks))
        self.assertEqual("".join(chunks).replace("\n", ""), "".join(blocks))
        self.assertEqual(chunks[0], "a" * 40 + "\n" + "b" * 40)


class DeadlineCarryOverTests(unittest.TestCase):
    def test_previous_deadline_skips_are_scanned_again_once(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        sessions, runs = root / "sessions", root / "runs"
        (sessions / "proj").mkdir(parents=True)
        old, fresh, done = (sessions / "proj" / f"{n}.jsonl" for n in ("old", "fresh", "done"))
        for p in (old, fresh, done):
            p.write_text(json.dumps({"type": "session", "id": p.stem}) + "\n")
        long_ago = (START - timedelta(days=3)).timestamp()
        for p in (old, done):
            os.utime(p, (long_ago, long_ago))
        prev = runs / "2026-09-24"
        prev.mkdir(parents=True)
        (prev / "00b-session-memory.json").write_text(json.dumps({"sessions": [
            {"path": str(old), "action": "skipped_deadline"},
            {"path": str(fresh), "action": "skipped_deadline"},  # also changed: once
            {"path": str(done), "action": "documented"},
            {"path": "/etc/passwd", "action": "skipped_deadline"},
        ]}))
        tonight = runs / "2026-09-25"
        tonight.mkdir()
        with patch.object(setup, "SESSION_INTERACTIVE_DIR", sessions), \
                patch.object(setup, "RUN_DIR_BASE", runs):
            scanned = [p for _, p, _, _ in setup._sessions_to_scan(START, tonight)]
        self.assertEqual(sorted(scanned), sorted([fresh, old]))

    def test_without_previous_artifact_only_changed_sessions(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "sessions").mkdir()
        with patch.object(setup, "SESSION_INTERACTIVE_DIR", root / "sessions"), \
                patch.object(setup, "RUN_DIR_BASE", root / "runs"):
            self.assertEqual(list(setup._sessions_to_scan(START, root / "runs" / "x")), [])


if __name__ == "__main__":
    unittest.main()
