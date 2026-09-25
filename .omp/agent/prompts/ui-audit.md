---
description: Visually inspect and performance-profile a browser UI across viewport sizes, including interaction, responsive layout, animation, scrolling, hitches, and stutters.
---

# UI Audit

Audit the actual rendered browser UI described by the invocation. Use OMP's browser tool for interaction and screenshots; source inspection or DOM assertions alone are not visual proof.

## Invocation

$ARGUMENTS

## Scope

- Treat supplied URLs, flows, viewport sizes, devices, symptoms, and acceptance criteria as authoritative.
- If no URL is supplied, infer the relevant application and start command from the current project, its scripts, and its documentation. Use the running application rather than a static file whenever possible.
- If no flow is supplied, exercise the primary flow relevant to the named surface or current task. Do not wander into unrelated product areas.
- Audit only by default. Modify source only when the invocation explicitly requests a fix or this command is invoked as verification within an existing implementation task.
- Use an image-capable model. If the active model cannot inspect browser screenshots, switch to an available image-capable model or report that exact blocker; do not substitute DOM-only inspection.

## Required workflow

### 1. Open the real surface

- Launch or reuse the actual application and wait for readiness.
- Open a dedicated named browser tab. Default to OMP's shared headless Chromium.
- Do not attach to the user's Chrome, use Browser Relay, or navigate a logged-in user tab unless the invocation explicitly requests real-browser testing.
- Capture the initial ARIA snapshot or observation to understand the interactive surface.

### 2. Exercise responsive sizes

Use every viewport supplied by the user. If none are supplied, test:

- phone: 390×844, device scale factor 2, mobile and touch enabled;
- tablet: 768×1024, device scale factor 2, touch enabled;
- desktop: 1440×900, device scale factor 1.

Set mobile/touch viewport properties before navigation because changing them may reload the page. If the project defines a relevant breakpoint near one of these sizes, also inspect immediately below and above that breakpoint when doing so can expose a boundary bug.

At each size:

- drive the requested flow rather than merely loading the page;
- capture screenshots before and after each material state transition;
- use viewport screenshots and focused element crops for fine details instead of relying only on a downscaled full-page image;
- record the actual viewport, device-pixel ratio, document scroll dimensions, and whether document-level horizontal overflow exists.

### 3. Drive the UI reliably

- Locate ordinary controls through `tab.ariaSnapshot()` or `tab.observe()` and interact using fresh ARIA references or selectors.
- Exercise relevant click, keyboard, typing, hover, scroll, drag, and touch behavior.
- Re-observe after navigation or a rerender before reusing references.
- Use screenshot-derived coordinates only for genuinely non-semantic surfaces such as canvas, maps, or custom graphics.
- Test reachable loading, empty, error, expanded, collapsed, open, and closed states only when they belong to the requested flow.

### 4. Perform visual inspection

Actually inspect every emitted screenshot. Check for:

- overlap, clipping, truncation, unintended wrapping, and offscreen controls;
- horizontal overflow, incorrect scroll containers, content hidden under fixed elements, and broken full-height layouts;
- incorrect stacking, popover/dialog placement, stale layers, flashes, and partially rendered states;
- spacing, alignment, hierarchy, contrast, image sizing/cropping, and controls that are technically present but visually unusable;
- layout jumps or incorrect intermediate states during interaction;
- differences between viewport sizes that are not explained by the intended responsive design.

Corroborate visual findings with DOM geometry when useful, but never claim that geometry alone proves the UI looks correct.

### 5. Measure motion and responsiveness

When the requested flow contains animation, transition, scrolling, dragging, expansion/collapse, or a reported hitch/stutter, run a measurement pass without video recording:

1. Feature-detect and collect `long-animation-frame` entries with `PerformanceObserver`.
2. Sample `requestAnimationFrame` intervals across the exact interaction.
3. Collect relevant long tasks, interaction timing, and layout shifts when supported.
4. Record a Chrome performance trace with screenshots while repeating the exact interaction.
5. Report counts, maximums, and useful percentiles rather than only an average.
6. Attribute delays where the trace provides evidence: JavaScript, style calculation, layout, paint, compositing, loading, or another named cause.

Use the display's applicable frame budget when known. Otherwise explain results against 60 Hz (approximately 16.7 ms per frame). Treat Long Animation Frames over 50 ms as severe events, not as the only possible dropped frames.

Do not use Lighthouse as a substitute for exercising and profiling the runtime interaction.

### 6. Capture temporal visual evidence separately

For animation, scrolling, or a reported hitch/stutter, repeat the flow in a separate capture pass:

- record a short WebM with Puppeteer's `page.screencast()`;
- keep the recording focused on the exact interaction;
- extract timestamped frames or a contact sheet with `ffmpeg` and inspect the resulting images;
- look for visible pauses, repeated frames, snapping, blank frames, flicker, jumps, or incorrect intermediate layout.

Do not claim that screencast FPS equals physically presented display FPS. Recording can add load or omit frames; use the trace and timing metrics for measurement and the video frames for visual evidence.

### 7. Distinguish lab and real-device evidence

Headless Chromium can prove responsive layout, rendered states, interaction behavior, and many main-thread/rendering regressions. It cannot by itself prove behavior specific to Safari/WebKit, browser chrome, a physical phone, a particular GPU/driver, extensions, or a 120 Hz display.

If the invocation requires one of those, run on the named real browser/device through an explicitly authorized dedicated profile or state exactly what remains unverified. Never expose or connect to a CDP/relay endpoint without the user's authorization.

### 8. Fix and recheck when requested

If source changes are in scope:

- reproduce the issue first and preserve the exact failing flow, size, and metrics;
- fix the source rather than suppressing the symptom;
- rerun the same visual and performance scenario;
- compare before and after evidence;
- verify the actual browser surface after the change.

### 9. Clean up

- Close managed browser tabs created for the audit.
- Stop only development processes started by this command.
- Keep useful screenshots, metrics, traces, and recordings as session artifacts; remove disposable intermediates.

## Final report

Lead with the conclusion. Include:

1. **Coverage:** URLs, flows, viewport sizes, browser mode, and states exercised.
2. **Visual findings:** each issue with viewport/state and screenshot evidence.
3. **Interaction findings:** failures or confirmed behavior from the driven flow.
4. **Motion findings:** frame gaps, Long Animation Frames, trace attribution, and visible recording evidence when applicable.
5. **Fix verification:** exact before/after evidence if changes were requested.
6. **Limits:** anything requiring a real browser/device or otherwise not verified.
7. **Artifacts:** paths or links for screenshots, metrics, trace, and optional recording/contact sheet.

Do not report "looks good" without having inspected screenshots from the material states at the tested sizes. Do not call an animation smooth based only on a video or a single average frame rate.
