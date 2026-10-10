# AVHSOL reports

AVHSOL turns a directory of runs into a security assessment report: a branded, paginated document
with an executive summary, scope and method, risk summary, detailed findings (attack path, incident
timeline, payload, effect of the guard, analyst reasoning, reproduction), defense validation, a
no-attack baseline, remediation roadmap, limitations and appendices.

```
avhsol export -in out-coding-live -scenario devops-coder -format pdf
avhsol export -format html|pdf|md|json|sarif  [-skeleton NAME_OR_FILE]  [-o FILE]
              [-classification CONFIDENTIAL] [-title "..."] [-scenario ID]
avhsol export -list-skeletons            # security-report, executive-brief
avhsol export -dump-skeleton security-report > my-layout.json
```

The same reports are downloadable from the dashboard (Verdict page → Security report), and from the
API: `GET /api/report?format=pdf&skeleton=security-report` (viewer role).

Samples generated from real runs are in `docs/sample/`.

## Formats

| Format | For | Notes |
|---|---|---|
| `html` | reading, archiving | one self-contained file; no scripts, no external requests; light and dark |
| `pdf` | handing to people | A4, cover page, contents, running footer with report id, classification and page numbers. Needs Chrome or Chromium (`AVHSOL_CHROME` to point at one) |
| `md` | wikis, tickets, diffs | same structure; charts become small tables with text bars |
| `json` | tooling | the complete data behind the report |
| `sarif` | CI and code-scanning | SARIF 2.1.0: one result per finding, stable fingerprints, trace ids and OWASP tags in `properties` |

## What the report will and will not claim

* A finding is an attack that achieved a **critical objective** (a planted secret reaching a test
  server, a host file read, a forbidden call), decided by deterministic checks, never by the model.
* Rates exclude **errored runs** (for example a context-window overflow). They are listed, not counted as defended.
* Reliability is only stated with **3 or more repeats**; with fewer, the report says so. The overall
  rating is "Critical" only for an attack that reliably worked across repeats; otherwise "High".
* A run with the **simulated model** is never rated, and the report says so on the cover and in the summary.
* The **no-attack control** is shown beside each objective; if none was run, the report warns that the
  agent's own habits cannot be separated from attack effects.
* Secrets are redacted to fingerprints. Attacker-controlled text (payloads, tool output) is HTML-escaped
  everywhere; invisible Unicode in a payload is made visible and highlighted.
* Every report carries its sha256 digest, and is signed when a signing key is configured. Traces are
  verified against the public key and the counts are shown in Appendix B.

## Skeletons: the layout as JSON

A **skeleton** describes a report as data. The engine binds it to the report's data and renders the
result to HTML, PDF or Markdown, so a different required format means a different JSON file, not code.
Unknown fields and block types are errors (a typo cannot silently drop part of a report).

```json
{
  "format": "avhsol-report-skeleton/1",
  "name": "One-page audit note",
  "theme": { "accent": "#1b5fd1", "classification": "INTERNAL" },
  "footer": "{{doc.report_id}}",
  "sections": [
    { "title": "Result", "blocks": [
      { "type": "paragraph", "text": "{{headline}}" },
      { "type": "stats", "items": [ { "label": "Rating", "value": "{{risk_rating}}", "tone": "breach" } ] }
    ] }
  ]
}
```

A complete example is `docs/skeletons/one-page-audit.json`; the shipped layouts are
`core/internal/export/skeletons/`.

### Top level

`format` (must be `avhsol-report-skeleton/1`), `name`, `theme` (`accent` colour, `classification`),
`cover` (`classification`, `title`, `subtitle`, `meta[]` of `label`/`value`, `note`), `header`,
`footer`, `toc` (contents page), `sections[]`.

A **section** has `title`, optional `id`, `page_break`, `if` / `unless`, and `blocks[]`. Sections are
numbered automatically.

### Blocks

| `type` | fields |
|---|---|
| `heading` | `level` (2 to 4), `text` |
| `paragraph` | `text` |
| `callout` | `tone` (`warn`, `breach`, `held`), `title`, `text` |
| `list` | `lines[]`, or `data` (an array path) with optional `field`; `empty` |
| `stats` | `items[]` of `label`, `value`, `tone` |
| `kv` | `items[]` of `label`, `value` (rows with an empty value are dropped) |
| `table` | `data`, `columns[]` of `header`, `value`, `align`, `style` (`plain`, `mono`, `pill`, `severity`, `outcome`), `title`, `empty` |
| `chart` | `chart.kind`: `bar`, `compare`, `donut`, `strip` (see below) |
| `code` | `text`, `reveal_hidden` (show invisible characters) |
| `attack_path` | `data` (an array of path nodes, e.g. `f.path`) |
| `each` | `data`, `as`, `blocks[]`: repeat the blocks for every item; `{{index}}` is 1-based; `empty` text |
| `pagebreak`, `spacer` | |

Every block accepts `if` and `unless`.

### Charts

* `bar`: `data`, `label`, `value`, `of` (bar = value / of), `tone`
* `compare`: `data`, `label`, `a`, `a_of`, `b`, `b_of`, `a_label`, `b_label` (attack versus control)
* `donut`: `slices[]` of `label`, `value` (a data path or a literal number), `tone`
* `strip`: `data`, `time` (a millisecond field), `outcome` (a field): dots on a time axis

### Expressions

Strings may contain `{{path}}` or `{{path|filter}}`. Paths are dotted (`defense_summary.blocked`,
`findings.0.id`); inside `each`, the loop variable named by `as` is available (`{{f.title}}`), and
inside a `table`, the current row is `row` (`{{row.severity}}`). A missing value renders as nothing,
never as the raw `{{...}}`.

Filters: `pct` (0.5 → 50%), `upper`, `lower`, `title` (`task_embedding` → Task embedding), `short:N`,
`join` or `join:SEP`, `count`, `num`, `date`.

Conditions (`if` / `unless`) test a path for truth (non-empty, non-zero, not false); prefix `!` to negate.
Handy flags: `simulated`, `has_findings`, `has_defense`, `has_control`, `has_advisories`.

### Data

`avhsol export -format json` prints exactly what a skeleton can see: `doc`, `scope`, `headline`,
`risk_rating`, `risk_basis`, `findings[]` (with `path`, `timeline`, `payload`, `advisory`, ...),
`objectives[]`, `techniques[]`, `risk_matrix[]`, `runs[]`, `defense_summary`, `defense_validation`,
`static_audit[]`, `recommendations[]`, `limitations[]`, `integrity`.
