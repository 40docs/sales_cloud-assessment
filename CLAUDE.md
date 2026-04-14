# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Interactive security maturity assessment for the AWS Summit booth. A prospect walks through four attack scenarios (Network Security, Application Security, Cloud Visibility, Service Visibility), picks one of three outcomes per scenario, and submits their email so the sales team can follow up. Intended as a lead-gen tool, not a self-serve report — the submission goes to the sales team, not the prospect.

## Architecture

Three HTML files, all self-contained (inline HTML/CSS/JS, no build step):

- **`security-maturity-assessment.html`** — tiny router. Device-detects and redirects to `-browser.html` or `-mobile.html`. Rule: mobile if `innerWidth < 768` or if `(pointer: coarse)` and `innerWidth < 1024`. Has a `<noscript>` fallback to the browser version.
- **`security-maturity-assessment-browser.html`** — the full desktop version. This is the canonical content file; mobile is a fork.
- **`security-maturity-assessment-mobile.html`** — mobile variant. Starts as an exact copy of browser and gets adapted. **Copy content-level changes to both files** unless the change is layout/viewport-specific.

Key structure inside each content file:

- **`scenarios` array** — the data model. Each entry has `domain`, `color`, `setup` (split on " — " into a small eyebrow and a hero title), `story`, `question`, a `visual` diagram (absolutely-positioned icon elements with `x`/`y` percents), and three `outcomes` each with a `score` (0/1/2), `color` (red/yellow/green), and `insight`. To add/edit a scenario, edit this array — rendering, scoring, and results cards all derive from it.
- **Three `.scene` divs** (`sceneIntro`, `sceneScenario`, `sceneResults`) swapped by `goTo(id)` via `.active`/`.exit` classes. `renderScenario()` rebuilds `sceneScenario`'s innerHTML each step from the current `scenarios[current]`.
- **Flow** — email is captured on the intro page before scenarios start; the results page has a single `Submit` button and no email field. `userEmail` holds the captured address; `begin()` validates and stores it, `sendReport()` logs the payload and shows an inline confirmation.
- **Scoring** — `pick(idx)` stores the chosen outcome in `scores[scenario.id]` and calls `updatePips()` for live progress-bar coloring. `showResults()` sums scores, computes a percentage, and picks one of four summary states (Strong Posture / Getting There / Mixed / Significant Gaps) based on `pct` and the count of red answers.
- **Progress pips** — the topbar pip bar doubles as a scorecard: each pip fills with the selected outcome's color (red/yellow/green) the moment the user picks.
- **`sendReport()`** currently just `console.log`s the payload. No backend wired up — if a real submission endpoint is needed, it has to be added here.
- **Theme** — `toggleTheme()` flips a `light-mode` class on `<html>`; all light-mode overrides live in a single CSS block. The theme toggle itself is a fixed-position floating button in the bottom-right corner.
- **Type scale** — 6 sizes: display (28–42px 800), hero (22–28px 800), body (15px 400), body-emphasis (13px 600), meta (12px), eyebrow (11px 600, 1.8px tracking, uppercase). Keep this scale when adding new UI — don't invent new sizes.

## Deployment

`.github/workflows/pages.yml` deploys to GitHub Pages on every push to `main`. The workflow generates an `index.html` at build time that meta-refreshes to `security-maturity-assessment.html` (the router), so that file is the entry point — do not commit a hand-written `index.html`.
