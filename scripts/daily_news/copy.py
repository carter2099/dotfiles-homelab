"""Newspaper standfirst generation and source-grounded copy validation."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from . import runtime
from .catalog import STANDFIRST_PROMPT_VERSION
from .contracts import parse_date

# Periods inside these short tokens do not end a sentence: "U.S.", "Aug.",
# "Mr.", "e.g.", etc. Splitting on them truncated standfirst copy in the
# 2026-09-02 world edition ("The U.S. Nepal's Foreign Ministry said ... after
# the Aug."), so sentence extraction and validation must treat them as
# mid-token punctuation rather than sentence boundaries.
_ABBREVIATION_TOKENS = frozenset({
    # Honorifics and titles
    "mr", "mrs", "ms", "mx", "dr", "prof", "rev", "sir", "sr", "jr",
    "st", "sgt", "capt", "gen", "col", "lt", "gov", "sen", "rep",
    # Common abbreviated words
    "vs", "etc", "e.g", "i.e", "dept", "est", "inc", "ltd", "co",
    "approx", "mt", "ft", "min", "max", "avg",
    # Month abbreviations
    "jan", "feb", "mar", "apr", "jun", "jul", "aug", "sep", "sept",
    "oct", "nov", "dec",
    # Geographic and credential short forms used mid-sentence
    "u.s", "u.k", "u.n", "u.s.s.r", "u.a.e", "d.c", "ph.d",
})
_MIN_SENTENCE_WORDS = 3
_SENTENCE_END_RE = re.compile(r"""[.!?…]["'’”)]*(?=\s|$)""")
_ABBREVIATION_ENDING_RE = re.compile(r"""\b([A-Za-z0-9’'.&-]+)\.["'’”)]*$""")


def _is_abbreviation_period(text: str, start: int) -> bool:
    """True when the period at ``start`` terminates a known abbreviation token."""
    end = start
    while end > 0 and (text[end - 1].isalnum() or text[end - 1] in "’.'&-"):
        end -= 1
    return text[end:start].rstrip(".").casefold() in _ABBREVIATION_TOKENS


def _sentence_ends(text: str) -> list[int]:
    """End indices of genuine sentence boundaries, skipping abbreviation periods."""
    ends: list[int] = []
    for match in _SENTENCE_END_RE.finditer(text):
        if (
            match.group().startswith(".")
            and _is_abbreviation_period(text, match.start())
        ):
            continue
        ends.append(match.end())
    return ends


def _ends_abbreviated(text: str) -> bool:
    """True when the final punctuation closes a known abbreviation token."""
    match = _ABBREVIATION_ENDING_RE.search(text)
    if match is None:
        return False
    return match.group(1).rstrip(".").casefold() in _ABBREVIATION_TOKENS


def validate_standfirst(standfirst: str, stories: list[dict]) -> tuple[bool, str]:
    text = " ".join(standfirst.split()) if isinstance(standfirst, str) else ""
    if len(text) < 40:
        return False, "standfirst is too short"
    if len(text) > 900:
        return False, "standfirst exceeds 900 characters"
    if not re.search(r"""[.!?…]["'’”)]*$""", text):
        return False, "standfirst ends mid-sentence"
    if _ends_abbreviated(text):
        return False, "standfirst ends mid-sentence (abbreviation period)"
    if re.search(r"https?://|www\.", text, re.IGNORECASE):
        return False, "standfirst contains a URL"
    if "<" in text or ">" in text:
        return False, "standfirst contains HTML"
    if re.search(
        r"\b(?:today[’']s|this)\s+(?:digest|edition|briefing)\b|"
        r"\b(?:digest|edition)\s+(?:leads|focuses|covers|includes)\b|"
        r"\bread on\b|\balso in focus\b",
        text,
        re.IGNORECASE,
    ):
        return False, "standfirst uses digest-style meta language"
    source_text = " ".join(
        f"{story.get('title', '')} {story.get('summary', '')} "
        f"{story.get('why_still_relevant', '')}"
        for story in stories
    )
    source_numbers = set(re.findall(r"\b\d[\d,.]*%?\b", source_text))
    standfirst_numbers = set(re.findall(r"\b\d[\d,.]*%?\b", text))
    unsupported = sorted(standfirst_numbers - source_numbers)
    if unsupported:
        return False, f"standfirst introduced unsupported numbers: {', '.join(unsupported)}"
    entity_pattern = r"\b[A-Z][A-Za-z0-9’'-]{1,}\b"
    source_entities = {
        re.sub(r"[’']s$", "", entity.casefold())
        for entity in re.findall(entity_pattern, source_text)
    }
    standfirst_entities = {
        re.sub(r"[’']s$", "", entity.casefold())
        for entity in re.findall(entity_pattern, text)
        if (
            re.sub(r"[’']s$", "", entity).isupper()
            or any(
                char.isupper()
                for char in re.sub(r"[’']s$", "", entity)[1:]
            )
        )
    }
    unsupported_entities = sorted(standfirst_entities - source_entities)
    if unsupported_entities:
        return False, (
            "standfirst introduced unsupported names: "
            + ", ".join(unsupported_entities)
        )
    return True, ""


def first_complete_sentence(value: Any) -> str:
    """Extract the first complete sentence, ignoring abbreviation periods.

    Periods inside known abbreviations (U.S., Aug., Mr.) are not sentence
    boundaries, and a captured sentence must contain at least
    ``_MIN_SENTENCE_WORDS`` words, so fragments like "The U.S." or
    "...after the Aug." are never returned as complete newspaper copy.
    """
    text = " ".join(value.split()) if isinstance(value, str) else ""
    if not text:
        return ""
    candidate = ""
    for end in _sentence_ends(text):
        sentence = text[:end]
        if len(re.findall(r"\S+", sentence)) >= _MIN_SENTENCE_WORDS:
            candidate = sentence
            break
    if candidate and len(candidate) <= 850:
        return candidate
    # No boundary produced a usable sentence. Accept the whole short text
    # only when it is not truncated on an abbreviation period ("...after the
    # Aug."); such an ending means the sentence continues past the text.
    if len(text) <= 850 and not candidate and not _ends_abbreviated(text):
        return text if re.search(r"""[.!?…]["'’”)]*$""", text) else f"{text}."
    return ""


def fallback_standfirst(fresh: list[dict], ongoing: list[dict]) -> str:
    """Deterministic standfirst from complete summary sentences.

    The sentence-based output is re-validated against the source stories and
    degrades to a lead-title standfirst when it does not validate, so a
    truncated fragment like "...after the Aug." can never be published.
    """
    stories = fresh or ongoing
    if not stories:
        return "No publishable stories were selected for this section."
    sentences = [
        first_complete_sentence(story.get("summary", ""))
        for story in stories[:3]
    ]
    sentences = [sentence for sentence in sentences if sentence]
    candidates: list[str] = []
    if sentences:
        standfirst = sentences[0]
        if len(sentences) > 1 and len(f"{standfirst} {sentences[1]}") <= 850:
            standfirst = f"{standfirst} {sentences[1]}"
        candidates.append(standfirst)
    title = " ".join(str(stories[0].get("title", "Lead story")).split())
    candidates.append(title if re.search(r"[.!?…]$", title) else f"{title}.")
    for candidate in candidates:
        valid, _ = validate_standfirst(candidate, stories)
        if valid:
            return candidate
    # Neither candidate validated (usually a short title); keep the
    # sentence-based copy as the closest match to newspaper prose.
    return candidates[0]


def standfirst_story_fingerprint(stories: list[dict]) -> str:
    payload = [
        {
            "url": story.get("url", ""),
            "summary": story.get("summary", ""),
            "priority_score": story.get("priority_score"),
        }
        for story in stories
    ]
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()



def model_attempts(*models: str) -> list[tuple[str, str]]:
    """Return distinct requested/effective model pairs in stable order."""
    attempts: list[tuple[str, str]] = []
    seen: set[str] = set()
    for requested in models:
        effective = runtime._effective_model(requested)
        if effective not in seen:
            seen.add(effective)
            attempts.append((requested, effective))
    return attempts


def summarize_model_error(error: Exception) -> str:
    if isinstance(error, subprocess.TimeoutExpired):
        return f"timed out after {error.timeout}s"
    return " ".join(str(error).split())[:500]


@runtime.track_phase_failure("standfirst")
def generate_section_standfirst(
    topic: dict,
    fresh: list[dict],
    ongoing: list[dict],
    run_dir: Path,
) -> str:
    """Generate newspaper copy only after selection and priority ranking."""
    artifact_path = run_dir / "07-standfirst.json"
    stories = fresh + ongoing
    story_fingerprint = standfirst_story_fingerprint(stories)
    phase_inputs = runtime.phase_inputs(
        "standfirst", topic=topic,
        upstream={"stories": runtime.canonical_fingerprint(stories)},
        policy={"prompt_version": STANDFIRST_PROMPT_VERSION},
    )
    state, cached = runtime.begin_or_load_phase(
        run_dir,
        "standfirst",
        inputs=phase_inputs,
        artifact_path=artifact_path,
        schema_version=STANDFIRST_PROMPT_VERSION,
        validator=lambda value: (
            isinstance(value, dict)
            and value.get("story_fingerprint") == story_fingerprint
            and validate_standfirst(value.get("standfirst", ""), stories)[0]
        ),
    )
    if cached is not None:
        return str(cached["standfirst"])
    if not stories:
        standfirst = fallback_standfirst(fresh, ongoing)
        runtime.complete_phase_json(
            state,
            "standfirst",
            artifact_path,
            {
                "prompt_version": STANDFIRST_PROMPT_VERSION,
                "story_fingerprint": story_fingerprint,
                "standfirst": standfirst,
                "status": "empty",
                "model": "",
                "errors": [],
            },
            outcome="empty",
            reason="no selected stories for standfirst",
        )
        runtime.write_phase_status(
            artifact_path,
            status="empty",
            reason="no selected stories for standfirst",
            inputs=phase_inputs,
        )
        return standfirst


    system = (
        "Write a concise two- or three-sentence newspaper standfirst for one section. "
        "Lead directly with the most consequential verified fact, then connect one or "
        "two supporting developments in natural newspaper prose. Use only facts, names, "
        "and numbers in the approved story data. Do not add URLs, HTML, new reporting, "
        "or claims about rejected stories. Never mention a digest, edition, briefing, "
        "candidate list, ranking, the writing process, or the reader. Do not use phrases "
        "such as 'today's digest leads with', 'also in focus', or 'read on'. Finish every "
        "sentence completely. Write in English and keep any supplied English story title "
        'unchanged. Output one JSON object: {"standfirst":"..."}'
    )
    user = (
        f"Newspaper section: {topic['web_title']}\n\n"
        f"Approved stories in priority order:\n{json.dumps(stories, indent=2)}"
    )
    errors: list[str] = []
    standfirst = ""
    model_used = ""
    status = "model"
    for requested_model, effective_model in model_attempts(runtime.MODEL, runtime.MODEL_FALLBACK):
        try:
            raw = runtime._call_llm_proxy(
                system, user, model=requested_model, timeout=runtime.INTRO_TIMEOUT
            )
            result = runtime._extract_json(raw, f"section standfirst ({effective_model})")
            if not isinstance(result, dict):
                raise ValueError("standfirst output must be a JSON object")
            candidate = " ".join(str(result.get("standfirst", "")).split())
            valid, reason = validate_standfirst(candidate, stories)
            if not valid:
                raise ValueError(reason)
            standfirst = candidate
            model_used = effective_model
            break
        except Exception as error:
            error_summary = summarize_model_error(error)
            errors.append(f"{effective_model}: {error_summary}")
            print(
                f"  [7 retry] standfirst failed with {effective_model}: "
                f"{error_summary}"
            )
    if not standfirst:
        standfirst = fallback_standfirst(fresh, ongoing)
        status = "deterministic_fallback"
    runtime.complete_phase_json(
        state,
        "standfirst",
        artifact_path,
        {
            "prompt_version": STANDFIRST_PROMPT_VERSION,
            "story_fingerprint": story_fingerprint,
            "standfirst": standfirst,
            "status": status,
            "model": model_used,
            "errors": errors,
        },
        outcome="degraded" if status == "deterministic_fallback" else "succeeded",
        reason=(
            "; ".join(errors)[:1000] or "no model produced a valid standfirst"
            if status == "deterministic_fallback"
            else None
        ),
    )
    return standfirst