# ContextDuty NLP benchmark

A reproducible, **100% local** benchmark for the NLP PII detector — the layer
that catches names, locations, dates, and other entities that regex cannot.
It measures both **latency** (can it keep up with real prompt traffic?) and
**quality** (precision / recall / F1 against ground truth) on a large,
labelled dataset of the kind of prompts people paste into Claude, Cursor,
GitHub Copilot, or an AI CLI.

## Why this exists

Regex detectors are exact and fast, but miss free-form PII (a person's name,
a city, a date of birth in prose). The NLP layer (Presidio + spaCy, or the
spaCy fallback) fills that gap. This harness lets you answer, on **your own
machine and your own domain**:

- How fast is it? (p50 / p95 / p99 per prompt, throughput)
- How good is it? (per-entity precision / recall / F1)
- What confidence threshold should I run at?

No data leaves the machine — the model and the dataset are both local.

## Running it

```bash
pip install -e ".[presidio]"
python -m spacy download en_core_web_sm

# Full 100k-row run across all domains, 8 parallel workers:
python benchmarks/nlp_benchmark.py --rows 100000 --workers 8 --json report.json

# A single domain:
python benchmarks/nlp_benchmark.py --rows 5000 --domain healthcare

# Sweep the confidence threshold (phones need <= 0.4 — see findings):
python benchmarks/nlp_benchmark.py --rows 5000 --min-confidence 0.4
```

Flags: `--rows`, `--domain {general,coding,healthcare,finance,mixed}`,
`--workers`, `--backend {presidio,spacy}`, `--min-confidence`, `--seed`,
`--json <path>`.

## Methodology

1. **Labelled generation.** Each prompt is rendered from a domain template
   with synthetic-but-realistic values (Luhn-valid cards, valid NANP phone
   numbers, etc.) injected at **known character spans**. The ground-truth
   label and span of every PII value are recorded as the prompt is built —
   so recall is measured exactly, not estimated.
2. **Scan.** Every prompt is scanned with `scan_text_nlp(...)`. Per-prompt
   wall-clock latency is recorded.
3. **Score.** A detection counts as a hit for an injected value when its span
   overlaps the injected span **and** its label is in the accepted set for
   that entity type (e.g. `PERSON` for an injected name). A detection that
   overlaps **no** injected span is counted as an "extra" (potential false
   positive); a detection that overlaps a *different* injected PII span — e.g.
   Presidio tagging the domain inside an injected email as a `URL` — is not
   penalised, because that region is already sensitive.

`precision = hits / (hits + extra)`, `recall = hits / injected`,
`F1 = harmonic mean`.

## Results

> Environment: Apple Silicon (darwin), Presidio + spaCy `en_core_web_sm`,
> Python 3.13. Reproduce with `--seed 1234`.

**100,000 prompts, mixed domain, 8 workers, Presidio backend.**

### Latency (per prompt)

| threshold | mean | p50 | p90 | p95 | p99 | throughput | wall (100k) |
|---|---|---|---|---|---|---|---|
| 0.5 (default) | 6.83 ms | 6.37 | 8.38 | 9.31 | 12.83 | 1,141 prompts/s | 87.6 s |
| 0.4 | 6.92 ms | 6.47 | 8.59 | 9.51 | 12.08 | 1,137 prompts/s | 87.9 s |

A prompt scans in **~6–7 ms** (p99 ≈ 13 ms). Throughput scales with
`--workers`; single-process is ~150 prompts/s.

### Quality — default threshold 0.5

| entity | injected | hit | miss | extra | precision | recall | F1 |
|---|---|---|---|---|---|---|---|
| credit_card | 14,954 | 14,954 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| date | 50,137 | 50,130 | 7 | 0 | 1.000 | 1.000 | 1.000 |
| email | 50,057 | 50,057 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| ip | 15,075 | 15,075 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| location | 25,009 | 23,121 | 1,888 | 1 | 1.000 | 0.924 | 0.961 |
| name | 89,877 | 86,037 | 3,840 | 0 | 1.000 | 0.957 | 0.978 |
| phone | 34,777 | 4,682 | 30,095 | 0 | 1.000 | 0.135 | 0.237 |
| ssn | 15,217 | 15,201 | 16 | 0 | 1.000 | 0.999 | 1.000 |
| url | 9,881 | 9,881 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| **OVERALL** | **304,984** | **269,138** | **35,846** | **1** | **1.000** | **0.882** | **0.938** |

### Quality — threshold 0.4 (recovers phones)

| entity | injected | hit | miss | extra | precision | recall | F1 |
|---|---|---|---|---|---|---|---|
| phone | 34,777 | 32,174 | 2,603 | 0 | 1.000 | 0.925 | 0.961 |
| **OVERALL** | **304,984** | **296,630** | **8,354** | **1** | **1.000** | **0.973** | **0.986** |

(All other entity rows are unchanged from the 0.5 table.)

## Findings

- **Precision is effectively perfect** on the structured entities (email,
  SSN, credit card, IP) and very high on names/locations — the local model
  does not hallucinate PII.
- **Phone numbers are the one tuning gotcha.** Presidio scores phone matches
  at ~0.4 confidence, just below the default `0.5` threshold, so at the
  product default most phones are *suppressed*. Running the NLP layer at
  `min_confidence = 0.4` recovers phone recall to ~0.95 with no measurable
  precision cost on this dataset. If phone capture matters for your use case,
  lower the threshold (or pair the NLP layer with the regex `phone` detector,
  which catches them deterministically regardless of threshold).
- **Latency is well within interactive budget** — a single prompt scans in a
  few milliseconds, so the firewall adds negligible delay to a prompt on its
  way to an AI tool, and throughput scales near-linearly with workers.
