---
description: Design and implement a deterministic, artifact-focused verification pipeline for an application repository.
---

Design and implement a comprehensive deterministic verification pipeline for this repository from scratch.

Assume no meaningful verification pipeline currently exists. First inspect the repository to determine:

- what kind of application this is
- its language(s), frameworks, build system, package/module system, and runtime
- how it is built, started, tested, packaged, and deployed
- its major architectural boundaries and external dependencies
- whether it is a library, CLI, server, browser application, desktop app, worker, monorepo, or combination
- what artifacts are actually shipped to users or production

Then build a verification system appropriate to the project.

The goal is not merely to install common tools. The goal is to establish executable evidence that incorrect changes fail before reaching production.

Design the pipeline in layers, using the cheapest and most deterministic checks capable of verifying each property. Include, where applicable:

- formatting/source hygiene
- compiler or type checking
- linting and correctness-oriented static analysis
- dependency/module hygiene
- dead-code or unused-dependency analysis
- unit tests
- integration tests
- end-to-end/system tests
- concurrency/race testing
- fuzz/property-based testing where valuable
- security/vulnerability checks
- build verification
- smoke tests
- browser verification for browser-facing applications
- CLI/process verification for command-line applications
- package/install/consumer verification for libraries or packages
- container/artifact verification for deployable services
- platform/runtime compatibility checks where the project claims compatibility

Do not add layers simply because they are conventional. For every layer, be able to explain what failure class it detects and why it belongs there.

Pay particular attention to system boundaries. Identify important interactions with things such as:

- databases
- filesystems
- subprocesses
- HTTP APIs
- message queues
- caches
- external services
- browsers
- operating-system facilities

Where the semantics of a real dependency matter, create integration tests using the real dependency or a sufficiently faithful isolated instance rather than mocking everything.

Identify important application invariants and failure modes from the existing code and behavior. Add executable checks for important cases such as, where relevant:

- invalid input
- partial failure
- retries
- timeouts
- duplicate requests/messages
- concurrency
- process crashes
- restart/recovery
- persistence
- cancellation
- malformed external responses
- unavailable dependencies
- interrupted operations

Make tests deterministic. Avoid arbitrary sleeps, dependence on test execution order, shared mutable environments, uncontrolled randomness, wall-clock assumptions, and external network dependencies in normal merge-blocking tests. Prefer condition-based waiting, isolated test state, temporary resources, seeded randomness, fake clocks where appropriate, and reproducible fixtures.

Critically, verify the actual artifact that will be shipped. Do not consider successful source-level tests sufficient. Build the production artifact and exercise that artifact directly. Depending on the project, this may mean testing:

- compiled binaries
- package archives
- fresh package installation
- external consumer projects
- Docker/container images
- production bundles
- generated assets
- startup commands
- migrations
- representative production-like workflows

Whenever practical, build an artifact once and test that exact artifact rather than rebuilding a different artifact later.

Create a clear project-level interface for verification. At minimum provide commands equivalent to:

- a fast deterministic verification command suitable for frequent local use
- a complete deterministic verification command suitable for CI

Use naming appropriate to the repository's ecosystem rather than forcing a particular task runner.

Organize CI so failures are understandable and expensive checks do not unnecessarily block feedback from cheaper checks. Separate major concerns into useful jobs/stages when doing so improves diagnostics or parallelism.

Determine what should run:

- continuously in the editor if supported
- locally during normal development
- on every pull request
- on scheduled/nightly runs
- before a release

The pull-request gate should prioritize deterministic, high-signal verification. Move expensive compatibility matrices, stress tests, long fuzzing runs, or external-service checks to scheduled or release workflows when appropriate.

If CI configuration exists, integrate the verification pipeline into it. If branch protection cannot be configured from this repository, document exactly which CI checks should be marked as required merge checks.

Treat the verification system itself as important code. Do not weaken or disable existing meaningful checks merely to make the pipeline green. Avoid broad ignores, skipped tests, unnecessary exclusions, or silent retries that conceal failures.

When finished:

1. Run the complete deterministic pipeline yourself.
2. Fix any failures caused by your changes.
3. Confirm the repository builds and the relevant shipped artifact works.
4. Summarize:
   - the verification layers added
   - what each layer proves
   - the canonical local verification command
   - the canonical full verification command
   - the CI checks that should be required
   - any important risks or verification gaps that remain

Prefer a smaller set of high-signal checks over a large collection of noisy tools. The final result should be a verification system maintainers can understand, run locally, trust in CI, and extend as the application evolves.
