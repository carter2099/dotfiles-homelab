"""Canonical Daily News topic catalog and editorial policy."""
from __future__ import annotations

from pathlib import Path
from typing import Any

RANKING_SCHEMA_VERSION = 3

STANDFIRST_PROMPT_VERSION = 2

BATCH_SIZE = 10  # findings/summaries per LLM call in phases 2 and 5

FRESH_CAP = 12       # Pool A: max fresh findings passed to Phase 4

ONGOING_CAP = 5      # Pool B: max older articles passed to Phase 4

SIF_CAP = 3          # Pool C: max qualified developing stories passed to Phase 6

FOLLOWUP_STORY_CAP = 8  # high-significance tracker stories checked for developments

MIN_DEVELOPMENT_DAYS = 2  # evidence-backed developments on distinct UTC dates

DEVELOPMENT_HISTORY_CAP = 30

COOL_AFTER_DAYS = 5     # auto-cool after 5 days without evidence-backed movement

PRUNE_AFTER_DAYS = 7    # remove cooled stories after 7 days without movement

RESURFACE_CAP_DAYS = COOL_AFTER_DAYS - 1

CROSS_DAY_DEDUP_DAYS = 5

REFERENCED_URLS_SCHEMA_VERSION = 1

REFERENCED_URL_TIMEOUT = 25          # per-page bound for link collection

HTML_FETCH_HEADERS = {
    "User-Agent": "Mozilla/5.0 (homelab Daily News; link collector)",
}

REFERENCED_URL_SKIP_HOSTS = {
    "twitter.com", "x.com", "facebook.com", "instagram.com", "linkedin.com",
    "reddit.com", "threads.net", "youtube.com", "youtu.be", "tiktok.com",
    "mstdn.social", "bsky.app",
}

REFERENCED_URL_SKIP_SEGMENTS = {
    "about", "contact", "privacy", "terms", "terms-of-service", "terms-of-use",
    "login", "log-in", "signup", "sign-up", "subscribe", "newsletter",
    "feed", "rss", "sitemap", "search", "press", "advertise", "careers",
    "jobs", "team", "legal", "cookies", "cookie-policy", "help", "faq",
    "shop", "store", "account", "settings",
}

EDITORIAL_SIGNIFICANCE_RUBRIC_SHARED = (
    "EDITORIAL SIGNIFICANCE RUBRIC (shared — applies to every topic):\n"
    "- high — major consequence, broad impact, or a significant change to the "
    "landscape; plausible front-page material on consequence alone.\n"
    "- medium — notable and meaningful to people who follow the space, but not "
    "a lead story on consequence alone.\n"
    "- low — incremental, niche, minor, or speculative.\n"
    "Judge consequence only. Never infer popularity, virality, coverage volume, "
    "or audience interest; those are measured separately from observable signals.\n"
)

DEVELOPING_STORY_RULES = (
    "DEVELOPING AND ONGOING CONTRACT:\n"
    "- Only stories with high editorial significance qualify.\n"
    "- A story must have material factual developments on at least two distinct "
    "UTC dates. Age, continued relevance, or an unresolved possibility is not a "
    "second development.\n"
    "- Material development means the underlying event changed: a new official "
    "action, decision, filing, vote, confirmed outcome, escalation, measurable "
    "impact, or comparably substantive fact.\n"
    "- Never qualify a single announcement, launch, release, patch, result, "
    "one-off article, opinion, analysis, recap, or new commentary that merely "
    "reframes the same facts. A different article about the same broad theme is "
    "not a development.\n"
)

EDITORIAL_SIGNIFICANCE_RUBRIC_SPECIFIC: dict[str, str] = {
    "ai-tech": (
        "PER-TOPIC EDITORIAL SIGNIFICANCE:\n"
        "- high: Major model release (GPT/Claude-tier), $100M+ funding, landmark regulation, "
        "significant breach.\n"
        "- medium: New tool/feature from known player, $10M+ round, research paper with "
        "practical impact, notable acquisition.\n"
        "- low: Minor version bumps, small rounds, speculative reports, "
        "\"X announced they will announce\".\n"
    ),
    "agentic-platform": (
        "PER-TOPIC EDITORIAL SIGNIFICANCE:\n"
        "- high: Breaking change to a major platform (Claude Code, Codex, Copilot), "
        "new agent architecture that meaningfully changes capabilities, critical vulnerability.\n"
        "- medium: New feature in a known platform, MCP/server tool releases, "
        "interesting benchmark result, SDK release.\n"
        "- low: Minor patch notes, small community projects, pre-announcements without substance.\n"
    ),
    "gaming": (
        "PER-TOPIC EDITORIAL SIGNIFICANCE:\n"
        "- high: AAA release or announcement, major studio news (closure, acquisition), "
        "platform-shifting event, esports championship result.\n"
        "- medium: Notable indie release, significant patch/expansion, industry trend piece, "
        "hardware news.\n"
        "- low: Minor updates, DLC announcements, rumors, small esports events.\n"
    ),
    "world": (
        "PER-TOPIC EDITORIAL SIGNIFICANCE:\n"
        "- high: Armed conflict escalation, major election result, natural disaster with "
        "casualties, significant policy change, international crisis.\n"
        "- medium: Diplomatic development, economic data release, legislative progress, "
        "notable protest or speech.\n"
        "- low: Process stories, incremental political maneuvering, local-interest pieces.\n"
    ),
    "ai-hardware": (
        "PER-TOPIC EDITORIAL SIGNIFICANCE:\n"
        "- high: Flagship accelerator launch (NVIDIA/AMD datacenter-class), $1B+ chip or "
        "datacenter deal, export control change, major supply disruption (HBM, CoWoS, "
        "TSMC capacity).\n"
        "- medium: Notable benchmark or perf-per-watt result, consumer GPU launch, hyperscaler "
        "capex update, startup silicon milestone, memory pricing shift.\n"
        "- low: Unconfirmed leaks/rumors, minor product refreshes, incremental firmware/driver "
        "news.\n"
    ),
}

TOPICS: dict[str, dict[str, Any]] = {
    "ai-tech": {
        "title": "AI & Tech Digest",
        "category": "ai-tech",
        "web_slug": "ai-tech",
        "web_title": "AI & Tech",
        "editorial_significance_rubric_specific": EDITORIAL_SIGNIFICANCE_RUBRIC_SPECIFIC["ai-tech"],
        "research_angles": [
            {
                "id": "models-releases",
                "prompt": (
                    "Search for AI model releases, major LLM announcements, and significant "
                    "model updates from the last 24 hours. Check sources like TechCrunch AI section "
                    "(https://techcrunch.com/category/artificial-intelligence/), The Verge AI "
                    "(https://www.theverge.com/ai-artificial-intelligence), Ars Technica AI "
                    "(https://arstechnica.com/ai/), and Hacker News (https://news.ycombinator.com/).\n\n"
                    "For each story found, record from the web_search results:\n"
                    "- Title\n"
                    "- URL (the exact URL returned by web_search — do not guess or construct)\n"
                    "- Source domain (e.g. techcrunch.com)\n"
                    "- Publication date (from the search evidence, ISO format if available)\n"
                    "- 1-2 sentence factual summary (no opinion, just what happened)\n"
                    "- Category: Model Releases, AI Infrastructure, or Research\n"
                    "- Editorial significance (consequence only, never popularity): high / medium / low\n\n"
                    "If a search result lacks enough evidence, skip it. Prioritize stories from today. "
                    "Only include stories web_search actually returned. "
                    "Avoid low-quality aggregators (e.g. buildfastwithai.com) that repackage other outlets' content."
                ),
            },
            {
                "id": "platforms-tools",
                "prompt": (
                    "Search for agentic AI platform news, developer tools, open source AI projects, "
                    "and coding agent developments from the last 24 hours. Check TechCrunch, "
                    "The Verge, Ars Technica, Hacker News, and dev.to.\n\n"
                    "For each story found, record from the web_search results:\n"
                    "- Title\n"
                    "- URL (the exact URL returned by web_search — do not guess or construct)\n"
                    "- Source domain\n"
                    "- Publication date (from the search evidence, ISO format if available)\n"
                    "- 1-2 sentence factual summary\n"
                    "- Category: Agentic/Agent Platforms, Open Source, or Tools & Developer\n"
                    "- Editorial significance (consequence only, never popularity): high / medium / low\n\n"
                    "Prioritize stories from today. Only include stories web_search actually "
                    "returned. If a search result lacks enough evidence, skip it. "
                    "Avoid low-quality aggregators (e.g. buildfastwithai.com) that repackage other outlets' content."
                ),
            },
            {
                "id": "industry-community",
                "prompt": (
                    "Search for AI industry news, funding announcements, policy/regulation, major "
                    "company moves, and notable community discussions from the last 24 hours. "
                    "Check TechCrunch, The Verge, Ars Technica, Hacker News, and Reddit r/MachineLearning.\n\n"
                    "For each story found, record from the web_search results:\n"
                    "- Title\n"
                    "- URL (the exact URL returned by web_search — do not guess or construct)\n"
                    "- Source domain\n"
                    "- Publication date (from the search evidence, ISO format if available)\n"
                    "- 1-2 sentence factual summary\n"
                    "- Category: Industry News, Policy, Funding, or Community\n"
                    "- Editorial significance (consequence only, never popularity): high / medium / low\n\n"
                    "Prioritize stories from today. Only include stories web_search actually "
                    "returned. If a search result lacks enough evidence, skip it. "
                    "Avoid low-quality aggregators (e.g. buildfastwithai.com) that repackage other outlets' content."
                ),
            },
        ],
        "judgment_rules": (
            "For each finding, evaluate against these rules and assign a verdict.\n\n"
            "1. SOURCE CHECK (HARD RULE): buildfastwithai.com is a low-quality aggregator "
            "that repackages other outlets' reporting without original content. ANY finding "
            "from buildfastwithai.com or similar aggregators MUST be dropped with reason "
            "'unreliable_source'. This takes precedence over all other rules. Only accept "
            "stories from known reputable outlets: TechCrunch, The Verge, Ars Technica, "
            "Wired, ZDNet, VentureBeat, Hacker News, official company blogs, GitHub repos "
            "with significant activity, academic papers on arxiv. Personal blogs are OK if "
            "they have substance.\n"
            "2. RELEVANCE CHECK: Is this about AI, tech, developer tools, or the tech industry? "
            "If it's general business news, politics, or non-tech topics, drop with reason 'not_relevant'.\n"
            "3. DUPLICATE CHECK: Is this the same underlying story as another finding? "
            "If yes, mark the lower-quality one as drop with reason 'duplicate_of:<other_finding_index>'.\n"
            "4. SUBSTANCE CHECK: Does this story have actual news value? Press releases with "
            "no new information, minor version bumps, and 'X company announced they will announce "
            "something' should be dropped with reason 'no_substance'.\n"
            "5. EDITORIAL SIGNIFICANCE REVIEW: Review the consequence-only label from "
            "research. Adjust it if impact differs; never infer popularity or attention.\n\n"
            "CRITICAL: The date has ALREADY been checked by a pre-processor. You do NOT need "
            "to re-check dates. All findings you receive have been pre-filtered for freshness. "
            "Focus on source quality, relevance, duplicates, substance, and significance accuracy.\n\n"
            "Output each finding in the 'approved' or 'rejected' array based on your verdict."
        ),
        "categories": [
            "Model Releases", "Agentic/Agent Platforms", "Open Source",
            "Tools & Developer", "Industry News", "Policy", "Funding",
            "AI Infrastructure", "Research", "Community",
        ],
    },
    "agentic-platform": {
        "title": "Agentic Platform Digest",
        "category": "agentic-platform",
        "web_slug": "agents",
        "web_title": "Agents",
        "editorial_significance_rubric_specific": EDITORIAL_SIGNIFICANCE_RUBRIC_SPECIFIC["agentic-platform"],
        "research_angles": [
            {
                "id": "platforms-features",
                "prompt": (
                    "Search for agentic AI platform news: new features, launches, and major "
                    "updates from platforms like Claude Code, Codex, Cursor, omp, Pi, Aider, "
                    "OpenCode, Windsurf, Copilot, OpenClaw, Devin, Kiro, Jules, Replit Agent, "
                    "and other coding or general-purpose agent platforms. The examples are not "
                    "exhaustive. Use three complementary searches: one broad platform-launch "
                    "query, one major coding-agent/vendor query, and one open-source or "
                    "general-purpose agent query covering primary project blogs and Hacker News. "
                    "Do not spend every search on the named vendors. Focus on the last 24 hours.\n\n"
                    "For each story found, record from the web_search results:\n"
                    "- Title\n"
                    "- URL (exact URL returned by web_search)\n"
                    "- Source domain\n"
                    "- Publication date\n"
                    "- 1-2 sentence factual summary based only on the search evidence\n"
                    "- Category: Platform Updates, Releases, or Industry News\n"
                    "- Editorial significance (consequence only, never popularity): high / medium / low\n\n"
                    "Only include stories that web_search actually returned; article verification happens later."
                ),
            },
            {
                "id": "ecosystem-tools",
                "prompt": (
                    "Search for agentic AI ecosystem news: MCP servers and tools, agent SDKs, "
                    "orchestration frameworks, workflow engines, evaluation benchmarks, "
                    "and notable community projects from the last 24 hours. "
                    "Check GitHub trending, Hacker News, dev.to, and AI newsletters.\n\n"
                    "For each story found, record from the web_search results:\n"
                    "- Title, exact URL returned by web_search, source domain, publication date\n"
                    "- 1-2 sentence factual summary based only on the search evidence\n"
                    "- Category: MCP/Ecosystem, SDKs & Frameworks, Benchmarks, or Community Projects\n"
                    "- Editorial significance (consequence only, never popularity): high / medium / low\n\n"
                    "Only include stories that web_search actually returned; article verification happens later."
                ),
            },
            {
                "id": "techniques-research",
                "prompt": (
                    "Search for advances in agentic AI techniques: multi-agent patterns, "
                    "deterministic orchestration, agent evaluation methods, prompting strategies, "
                    "context management, and relevant research papers from the last 24 hours.\n\n"
                    "For each finding, record from the web_search results:\n"
                    "- Title, exact URL returned by web_search, source domain, publication date\n"
                    "- 1-2 sentence factual summary based only on the search evidence\n"
                    "- Category: Techniques & Patterns, Research, or Evaluation\n"
                    "- Editorial significance (consequence only, never popularity): high / medium / low\n\n"
                    "Only include findings that web_search actually returned; article verification happens later."
                ),
            },
        ],
        "judgment_rules": (
            "For each finding, evaluate against these rules and assign a verdict.\n\n"
            "1. SOURCE CHECK: Reputable? Tech blogs, official docs, GitHub repos, company blogs "
            "are good. Drop content farms and low-quality aggregators.\n"
            "2. RELEVANCE CHECK: About agentic platforms, coding agents, multi-agent systems, "
            "MCP ecosystem, agent dev tooling, or AI agent research? Drop general AI news "
            "without an agent angle.\n"
            "3. DUPLICATE CHECK: Same story? Keep the best version, drop duplicates.\n"
            "4. SUBSTANCE CHECK: Actual news or meaningful analysis? Drop empty announcements.\n"
            "5. EDITORIAL SIGNIFICANCE REVIEW: Review consequence only; never infer popularity.\n\n"
            "CRITICAL: The date has ALREADY been checked by a pre-processor. You do NOT need "
            "to re-check dates. Focus on source, relevance, duplicates, substance, and significance.\n\n"
            "Output each finding in the 'approved' or 'rejected' array based on your verdict."
        ),
        "categories": [
            "Platform Updates", "New Features", "Launches", "MCP/Ecosystem",
            "SDKs & Frameworks", "Benchmarks", "Techniques & Patterns",
            "Research", "Evaluation", "Community Projects",
        ],
    },
    "ai-hardware": {
        "title": "AI Hardware Digest",
        "category": "ai-hardware",
        "web_slug": "ai-hardware",
        "web_title": "AI Hardware",
        "editorial_significance_rubric_specific": EDITORIAL_SIGNIFICANCE_RUBRIC_SPECIFIC["ai-hardware"],
        "research_angles": [
            {
                "id": "accelerators-silicon",
                "prompt": (
                    "Search for AI accelerator and silicon news from the last 24 hours: new GPUs, "
                    "TPUs, NPUs, and custom AI ASICs from NVIDIA, AMD, Intel, Google, AWS, Meta, "
                    "Microsoft, and silicon startups (Cerebras, Groq, Tenstorrent, SambaNova). "
                    "Check Tom's Hardware (https://www.tomshardware.com/), SemiAnalysis "
                    "(https://semianalysis.com/), The Next Platform "
                    "(https://www.nextplatform.com/), Ars Technica (https://arstechnica.com/), "
                    "and Hacker News (https://news.ycombinator.com/).\n\n"
                    "For each story found, record from the web_search results:\n"
                    "- Title\n"
                    "- URL (the exact URL returned by web_search — do not guess or construct)\n"
                    "- Source domain (e.g. tomshardware.com)\n"
                    "- Publication date (from the search evidence, ISO format if available)\n"
                    "- 1-2 sentence factual summary (no opinion, just what happened)\n"
                    "- Category: Accelerators & Silicon or Custom/Startup Silicon\n"
                    "- Editorial significance (consequence only, never popularity): high / medium / low\n\n"
                    "If a search result lacks enough evidence, skip it. Prioritize stories from today. "
                    "Only include stories web_search actually returned."
                ),
            },
            {
                "id": "datacenter-infrastructure",
                "prompt": (
                    "Search for AI datacenter and infrastructure hardware news from the last 24 "
                    "hours: HBM and memory (SK Hynix, Samsung, Micron), interconnect and "
                    "networking (NVLink, InfiniBand, Ethernet, optical), servers and rack "
                    "systems, power and cooling, hyperscaler datacenter buildouts and capex, "
                    "and the fab supply chain (TSMC, CoWoS, advanced packaging). Check The Next "
                    "Platform (https://www.nextplatform.com/), ServeTheHome "
                    "(https://www.servethehome.com/), Data Center Dynamics "
                    "(https://www.datacenterdynamics.com/), SemiAnalysis "
                    "(https://semianalysis.com/), and Reuters technology "
                    "(https://www.reuters.com/technology/).\n\n"
                    "For each story found, record from the web_search results:\n"
                    "- Title\n"
                    "- URL (the exact URL returned by web_search — do not guess or construct)\n"
                    "- Source domain\n"
                    "- Publication date (from the search evidence, ISO format if available)\n"
                    "- 1-2 sentence factual summary\n"
                    "- Category: Memory & HBM, Networking & Interconnect, Datacenter & Power, "
                    "or Supply Chain & Fabs\n"
                    "- Editorial significance (consequence only, never popularity): high / medium / low\n\n"
                    "If a search result lacks enough evidence, skip it. Prioritize stories from today. "
                    "Only include stories web_search actually returned."
                ),
            },
            {
                "id": "consumer-edge",
                "prompt": (
                    "Search for consumer and edge AI hardware news from the last 24 hours: "
                    "consumer GPUs (GeForce, Radeon, Arc), AI PC processors and NPUs "
                    "(Snapdragon X, Intel Core Ultra, AMD Ryzen AI), Apple silicon for local "
                    "inference, workstation and homelab AI hardware, and edge AI devices. "
                    "Check Tom's Hardware (https://www.tomshardware.com/), TechPowerUp "
                    "(https://www.techpowerup.com/), Ars Technica (https://arstechnica.com/), "
                    "The Verge (https://www.theverge.com/), and Hacker News "
                    "(https://news.ycombinator.com/).\n\n"
                    "For each story found, record from the web_search results:\n"
                    "- Title\n"
                    "- URL (the exact URL returned by web_search — do not guess or construct)\n"
                    "- Source domain\n"
                    "- Publication date (from the search evidence, ISO format if available)\n"
                    "- 1-2 sentence factual summary\n"
                    "- Category: Consumer & Edge\n"
                    "- Editorial significance (consequence only, never popularity): high / medium / low\n\n"
                    "If a search result lacks enough evidence, skip it. Prioritize stories from today. "
                    "Only include stories web_search actually returned."
                ),
            },
        ],
        "judgment_rules": (
            "For each finding, evaluate against these rules and assign a verdict.\n\n"
            "1. SOURCE CHECK: Is this from a known reputable outlet? Tom's Hardware, "
            "SemiAnalysis, The Next Platform, ServeTheHome, Data Center Dynamics, TechPowerUp, "
            "Ars Technica, The Verge, Reuters, Bloomberg, Hacker News, official company "
            "newsrooms and blogs. Personal blogs are OK if they have substance. Content farms, "
            "SEO spam, rumor sites with no track record, and low-quality aggregators should be "
            "dropped with reason 'unreliable_source'.\n"
            "2. RELEVANCE CHECK: Is this about hardware that enables AI — accelerators, "
            "silicon, memory, networking, datacenter infrastructure, fabs, or consumer/edge "
            "AI hardware? Pure software, model releases, and AI application news belong to "
            "other digests — drop with reason 'not_relevant'. General PC/tech news with no "
            "AI angle is also not_relevant.\n"
            "3. DUPLICATE CHECK: Is this the same underlying story as another finding? "
            "If yes, mark the lower-quality one as drop with reason 'duplicate_of:<other_finding_index>'.\n"
            "4. SUBSTANCE CHECK: Does this story have actual news value? Press releases with "
            "no new information, unconfirmed leaks without evidence, and 'X announced they "
            "will announce something' should be dropped with reason 'no_substance'.\n"
            "5. EDITORIAL SIGNIFICANCE REVIEW: Review the consequence-only label from "
            "research. Adjust it if impact differs; never infer popularity or attention.\n\n"
            "CRITICAL: The date has ALREADY been checked by a pre-processor. You do NOT need "
            "to re-check dates. All findings you receive have been pre-filtered for freshness. "
            "Focus on source quality, relevance, duplicates, substance, and significance accuracy.\n\n"
            "Output each finding in the 'approved' or 'rejected' array based on your verdict."
        ),
        "categories": [
            "Accelerators & Silicon", "Custom/Startup Silicon", "Memory & HBM",
            "Networking & Interconnect", "Datacenter & Power", "Supply Chain & Fabs",
            "Consumer & Edge", "Policy & Export Controls",
        ],
    },
    "gaming": {
        "title": "Gaming Digest",
        "category": "gaming-digest",
        "web_slug": "gaming",
        "web_title": "Gaming",
        "editorial_significance_rubric_specific": EDITORIAL_SIGNIFICANCE_RUBRIC_SPECIFIC["gaming"],
        "research_angles": [
            {
                "id": "releases-announcements",
                "prompt": (
                    "Search for gaming news from the last 24 hours: game releases, major updates, "
                    "patches, DLC announcements, and platform news (Steam, Epic, console). "
                    "Check Kotaku, IGN, PC Gamer, Eurogamer, GameSpot, and gaming subreddits.\n\n"
                    "For each story, record from the web_search results:\n"
                    "- Title, URL, source domain, publication date\n"
                    "- 1-2 sentence factual summary\n"
                    "- Category: Releases, Updates & Patches, DLC/Expansions, or Platform News\n"
                    "- Editorial significance (consequence only, never popularity): high / medium / low\n\n"
                    "Only include stories web_search actually returned."
                ),
            },
            {
                "id": "industry-esports",
                "prompt": (
                    "Search for gaming industry news from the last 24 hours: studio news, "
                    "esports results, industry trends, hardware, and major community events. "
                    "Check gaming news sites and relevant subreddits.\n\n"
                    "For each story, record from the web_search results:\n"
                    "- Title, URL, source domain, publication date\n"
                    "- 1-2 sentence factual summary\n"
                    "- Category: Industry, Esports, Hardware, or Community\n"
                    "- Editorial significance (consequence only, never popularity): high / medium / low\n\n"
                    "Only include stories web_search actually returned."
                ),
            },
            {
                "id": "indie-highlights",
                "prompt": (
                    "Search for notable indie game news from the last 24 hours: new indie releases, "
                    "early access launches, Steam Next Fest highlights, and indie dev stories. "
                    "Check Steam new releases, indie game subreddits, and gaming news sites.\n\n"
                    "For each story, record from the web_search results:\n"
                    "- Title, URL, source domain, publication date\n"
                    "- 1-2 sentence factual summary\n"
                    "- Category: Indie, Early Access, or Dev Stories\n"
                    "- Editorial significance (consequence only, never popularity): high / medium / low\n\n"
                    "Only include stories web_search actually returned."
                ),
            },
        ],
        "judgment_rules": (
            "For each finding, evaluate and assign a verdict.\n\n"
            "1. SOURCE CHECK: Reputable gaming press or official sources? Drop spam/content farms.\n"
            "2. RELEVANCE CHECK: About video games, gaming industry, or gaming hardware? "
            "Not general entertainment.\n"
            "3. DUPLICATE CHECK: Same story? Keep best version, drop duplicates.\n"
            "4. SUBSTANCE CHECK: 'Game X tweeted an emoji' is not news. Drop empty stories.\n"
            "5. EDITORIAL SIGNIFICANCE REVIEW: Review consequence only; never infer popularity.\n\n"
            "CRITICAL: The date has ALREADY been checked by a pre-processor. You do NOT need "
            "to re-check dates. Focus on source, relevance, duplicates, substance, and significance.\n\n"
            "Output each finding in the 'approved' or 'rejected' array based on your verdict."
        ),
        "categories": [
            "Releases", "Updates & Patches", "DLC/Expansions", "Platform News",
            "Industry", "Esports", "Hardware", "Indie", "Early Access",
            "Dev Stories", "Community",
        ],
    },
    "world": {
        "title": "World Digest",
        "category": "world-digest",
        "web_slug": "world",
        "web_title": "World",
        "editorial_significance_rubric_specific": EDITORIAL_SIGNIFICANCE_RUBRIC_SPECIFIC["world"],
        "research_angles": [
            {
                "id": "us-news",
                "prompt": (
                    "Search for major U.S. news from the last 24 hours: politics, policy, "
                    "economy, Supreme Court, Congress, executive actions. Check AP News, "
                    "Reuters, NPR, BBC US section, and major newspaper sites.\n\n"
                    "For each story, record from the web_search results:\n"
                    "- Title, URL, source domain, publication date\n"
                    "- 1-2 sentence factual summary (strictly factual, no editorializing)\n"
                    "- Category: Politics, Policy, Economy, Judiciary, or Executive\n"
                    "- Editorial significance (consequence only, never popularity): high / medium / low\n\n"
                    "Only include stories web_search actually returned."
                ),
            },
            {
                "id": "world-affairs",
                "prompt": (
                    "Search for major international news from the last 24 hours: geopolitics, "
                    "conflicts, diplomacy, international organizations, global economy. "
                    "Check AP News, Reuters, BBC World, Al Jazeera, and major outlets.\n\n"
                    "For each story, record from the web_search results:\n"
                    "- Title, URL, source domain, publication date\n"
                    "- 1-2 sentence factual summary\n"
                    "- Category: Geopolitics, Conflict, Diplomacy, Global Economy, or International\n"
                    "- Editorial significance (consequence only, never popularity): high / medium / low\n\n"
                    "Only include stories web_search actually returned."
                ),
            },
            {
                "id": "science-culture",
                "prompt": (
                    "Search for notable science, technology, health, environment, and cultural "
                    "news from the last 24 hours. Check major outlets, science journals' news "
                    "sections, and reputable science news sites.\n\n"
                    "For each story, record from the web_search results:\n"
                    "- Title, URL, source domain, publication date\n"
                    "- 1-2 sentence factual summary\n"
                    "- Category: Science, Health, Environment, Technology, or Culture\n"
                    "- Editorial significance (consequence only, never popularity): high / medium / low\n\n"
                    "Only include stories web_search actually returned."
                ),
            },
        ],
        "judgment_rules": (
            "For each finding, evaluate and assign a verdict.\n\n"
            "1. SOURCE CHECK: Reputable news organization? Drop blogs posing as news, "
            "content farms, and known misinformation sources.\n"
            "2. RELEVANCE CHECK: Significant U.S. or world event? Not local crime, "
            "celebrity gossip, or sports (unless major international significance).\n"
            "3. DUPLICATE CHECK: Same story? Keep best version, drop duplicates.\n"
            "4. SUBSTANCE CHECK: Is this actually news? 'Politician says something' "
            "without significant context or consequence is not news.\n"
            "5. EDITORIAL SIGNIFICANCE REVIEW: Review consequence only; never infer popularity.\n\n"
            "CRITICAL: The date has ALREADY been checked by a pre-processor. You do NOT need "
            "to re-check dates. Focus on source, relevance, duplicates, substance, and significance.\n\n"
            "Output each finding in the 'approved' or 'rejected' array based on your verdict."
        ),
        "categories": [
            "Politics", "Policy", "Economy", "Judiciary", "Executive",
            "Geopolitics", "Conflict", "Diplomacy", "Global Economy",
            "International", "Science", "Health", "Environment",
            "Technology", "Culture",
        ],
    },
}

def editorial_significance_rubric_text(topic: dict) -> str:
    """Build the consequence-only editorial rubric for a topic."""
    specific = topic.get("editorial_significance_rubric_specific", "")
    return (
        f"{EDITORIAL_SIGNIFICANCE_RUBRIC_SHARED}\n{specific}"
        if specific else EDITORIAL_SIGNIFICANCE_RUBRIC_SHARED
    )
