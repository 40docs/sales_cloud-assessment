# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Single-page interactive security maturity assessment. A prospect walks through four attack scenarios (Network, Web App, Cloud, SaaS), picks one of three outcomes per scenario, and gets a scored breakdown with an email capture for a follow-up report. Intended as a sales/lead-gen tool.

## Architecture

The entire app is one self-contained file: `security-maturity-assessment.html`. HTML, CSS, and JS all live inline — no build step, no dependencies beyond the Google Fonts `<link>`. To run it, open the file in a browser.

Key structure inside that file:

- **`scenarios` array (js, ~line 204)** — the data model for the whole app. Each entry defines a domain, color, narrative copy, a `visual` diagram (absolutely-positioned icon elements with `x`/`y` percents), and three `outcomes` each with a `score` (0/1/2), `color` (red/yellow/green), and `insight` text. **To add/edit a scenario, edit this array** — the rendering, scoring, and results cards all derive from it.
- **Three `.scene` divs** (`sceneIntro`, `sceneScenario`, `sceneResults`) swapped by `goTo(id)` via `.active`/`.exit` classes. `renderScenario()` rebuilds `sceneScenario`'s innerHTML each step from the current `scenarios[current]`.
- **Scoring** — `pick(idx)` stores the chosen outcome in `scores[scenario.id]`; `showResults()` sums scores, computes a percentage, and picks one of four summary states (Strong / Getting There / Mixed / Significant Gaps) based on `pct` and the count of red answers.
- **`sendReport()`** currently just `console.log`s the payload. There is no backend wired up — if a real submission endpoint is needed, it has to be added here.
- **Theme** — `toggleTheme()` flips a `light-mode` class on `<html>`; all light-mode overrides live in a single CSS block.

## Deployment

`.github/workflows/pages.yml` deploys to GitHub Pages on every push to `main`. The workflow generates an `index.html` at build time that meta-refreshes to `security-maturity-assessment.html`, so the assessment file is the canonical source — do not commit a hand-written `index.html`.
