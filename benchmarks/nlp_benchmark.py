#!/usr/bin/env python3
"""Local NLP detection benchmark for ContextDuty.

Generates a large, *labelled* dataset of realistic prompts — the kind users
paste into Claude / Cursor / GitHub Copilot / an AI CLI — with known PII
injected at known positions, then runs the local NLP scanner over them and
reports:

  * Latency   — per-prompt p50 / p90 / p95 / p99, mean, and throughput
  * Quality   — per-entity-type precision / recall / F1 against ground truth

Everything runs 100% locally (Presidio + spaCy, or the spaCy fallback). No
data leaves the machine.

Usage:
    python benchmarks/nlp_benchmark.py --rows 100000
    python benchmarks/nlp_benchmark.py --rows 5000 --domain healthcare
    python benchmarks/nlp_benchmark.py --rows 100000 --workers 8 --json out.json

Domains (prompt style):
    general   — chat / Q&A prompts (default)
    coding    — "fix this function", config snippets (Cursor/Copilot style)
    healthcare— clinical notes, patient messages
    finance   — banking / payment support prompts
    mixed     — even blend of all of the above
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Ground-truth entity types -> Presidio/NLP labels that count as a hit.
# A detection counts for an injected entity if it overlaps the injected span
# AND its label is in the accepted set for that entity type.
# ---------------------------------------------------------------------------
ACCEPTED_LABELS: dict[str, set[str]] = {
    "name": {"PERSON"},
    "email": {"EMAIL_ADDRESS"},
    "phone": {"PHONE_NUMBER"},
    "ssn": {"US_SSN"},
    "credit_card": {"CREDIT_CARD"},
    "location": {"LOCATION", "GPE"},
    "ip": {"IP_ADDRESS"},
    "url": {"URL"},
    "date": {"DATE_TIME", "DATE"},
}

# ---------------------------------------------------------------------------
# Synthetic-but-realistic value generators (no external deps).
# ---------------------------------------------------------------------------
_FIRST = [
    "James",
    "Maria",
    "Wei",
    "Priya",
    "Omar",
    "Sofia",
    "Liam",
    "Aisha",
    "Noah",
    "Yuki",
    "Carlos",
    "Fatima",
    "Ethan",
    "Mei",
    "Ravi",
    "Elena",
]
_LAST = [
    "Smith",
    "Garcia",
    "Chen",
    "Patel",
    "Khan",
    "Rossi",
    "Murphy",
    "Kim",
    "Okafor",
    "Tanaka",
    "Silva",
    "Nguyen",
    "Cohen",
    "Ali",
    "Ivanov",
    "Dubois",
]
_CITIES = [
    "Seattle",
    "Toronto",
    "Mumbai",
    "Berlin",
    "Austin",
    "Lagos",
    "Osaka",
    "São Paulo",
    "Dublin",
    "Singapore",
    "Denver",
    "Nairobi",
]
_DOMAINS = ["example.com", "corp.io", "mail.net", "acme.co", "test.org"]


def _name(rng: random.Random) -> str:
    return f"{rng.choice(_FIRST)} {rng.choice(_LAST)}"


def _email(rng: random.Random) -> str:
    return f"{rng.choice(_FIRST).lower()}.{rng.choice(_LAST).lower()}@{rng.choice(_DOMAINS)}"


def _phone(rng: random.Random) -> str:
    # Valid NANP structure: area & exchange start 2-9, avoid N11 codes.
    def _nxx() -> str:
        first = rng.randint(2, 9)
        mid = rng.randint(0, 9)
        last = rng.randint(0, 9)
        if mid == 1 and last == 1:  # avoid X11
            last = 2
        return f"{first}{mid}{last}"

    return f"+1 ({_nxx()}) {_nxx()}-{rng.randint(1000, 9999)}"


def _ssn(rng: random.Random) -> str:
    return f"{rng.randint(100, 899)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}"


def _credit_card(rng: random.Random) -> str:
    # Luhn-valid 16-digit Visa (starts 4) — Presidio's CC recognizer checks Luhn.
    digits = [4] + [rng.randint(0, 9) for _ in range(14)]
    # Compute Luhn check digit.
    total = 0
    for i, d in enumerate(reversed(digits)):
        # position of check digit will be index 0 from the right of the full
        # 16-digit number, so the 15 known digits sit at odd positions here.
        if i % 2 == 0:
            d2 = d * 2
            total += d2 - 9 if d2 > 9 else d2
        else:
            total += d
    check = (10 - (total % 10)) % 10
    return "".join(str(d) for d in digits) + str(check)


def _location(rng: random.Random) -> str:
    return rng.choice(_CITIES)


def _ip(rng: random.Random) -> str:
    return ".".join(
        str(n)
        for n in (
            rng.randint(1, 254),
            rng.randint(0, 255),
            rng.randint(0, 255),
            rng.randint(1, 254),
        )
    )  # noqa: E501


def _url(rng: random.Random) -> str:
    return f"https://{rng.choice(_DOMAINS)}/u/{rng.randint(1000, 9999)}"


def _date(rng: random.Random) -> str:
    months = ["January", "February", "March", "April", "May", "June"]
    return f"{rng.choice(months)} {rng.randint(1, 28)}, 20{rng.randint(10, 24)}"


_GENERATORS = {
    "name": _name,
    "email": _email,
    "phone": _phone,
    "ssn": _ssn,
    "credit_card": _credit_card,
    "location": _location,
    "ip": _ip,
    "url": _url,
    "date": _date,
}

# ---------------------------------------------------------------------------
# Prompt templates per domain. {slots} are filled with labelled values.
# ---------------------------------------------------------------------------
TEMPLATES: dict[str, list[str]] = {
    "general": [
        "Hi, my name is {name} and I live in {location}. Can you help me draft an email?",
        "Please reply to {email} and let them know the meeting moved to {date}.",
        "Call me back at {phone} — I'm {name} from the {location} office.",
        "My colleague {name} ({email}) asked about the report due {date}.",
        "Can you summarize this thread for {name}? Their number is {phone}.",
    ],
    "coding": [
        "Fix this: `DB_HOST={ip}` keeps failing. Reach me at {email} if you need logs.",
        "# TODO(by {name}): rotate the key before {date}\nconnect('{ip}')",
        "Our webhook posts to {url}; owner is {name} <{email}>.",
        "Deploy notes from {name}: prod IP is {ip}, ping {phone} on call.",
        "Refactor the client to call {url} — assigned to {name} ({email}).",
    ],
    "healthcare": [
        "Patient {name}, DOB {date}, SSN {ssn}, called from {phone} about test results.",
        "Please fax {name}'s records to the {location} clinic; contact {email}.",
        "{name} (SSN {ssn}) has an appointment on {date} at the {location} branch.",
        "Discharge summary for {name}: follow up {date}, reachable at {phone}.",
        "Insurance query for {name}, email {email}, regarding claim filed {date}.",
    ],
    "finance": [
        "I'm {name}; my card {credit_card} was declined. Call me at {phone}.",
        "Transfer dispute for {name} ({email}) — card ending {credit_card}, on {date}.",
        "Account holder {name}, SSN {ssn}, requests a statement sent to {email}.",
        "Fraud alert: charge from {location} on {date} on card {credit_card} for {name}.",
        "Wire confirmation for {name}: contact {phone}, notify {email} by {date}.",
    ],
}


@dataclass
class LabeledPrompt:
    text: str
    # spans: list of (entity_type, start, end)
    spans: list[tuple[str, int, int]] = field(default_factory=list)


def build_prompt(rng: random.Random, domain: str) -> LabeledPrompt:
    """Render one template with labelled values and record exact spans."""
    pool = TEMPLATES[domain] if domain != "mixed" else TEMPLATES[rng.choice(list(TEMPLATES))]
    template = rng.choice(pool)

    # Fill slots left-to-right, tracking the final character spans.
    out: list[str] = []
    spans: list[tuple[str, int, int]] = []
    i = 0
    cursor = 0
    while i < len(template):
        ch = template[i]
        if ch == "{":
            j = template.index("}", i)
            slot = template[i + 1 : j]
            value = _GENERATORS[slot](rng)
            spans.append((slot, cursor, cursor + len(value)))
            out.append(value)
            cursor += len(value)
            i = j + 1
        else:
            out.append(ch)
            cursor += 1
            i += 1
    return LabeledPrompt(text="".join(out), spans=spans)


def generate_dataset(n: int, domain: str, seed: int) -> list[LabeledPrompt]:
    rng = random.Random(seed)
    return [build_prompt(rng, domain) for _ in range(n)]


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
def _overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start < b_end and b_start < a_end


@dataclass
class Counts:
    tp: int = 0  # injected entity that was detected with an accepted label
    fn: int = 0  # injected entity that was missed
    # findings that matched no injected span (potential false positives)
    unmatched_findings: int = 0


def score_prompt(prompt: LabeledPrompt, findings: list[tuple[str, int, int]], per_type: dict):
    """findings: list of (entity_label, start, end). Updates per_type counts."""
    matched_finding_idx: set[int] = set()

    for etype, s_start, s_end in prompt.spans:
        accepted = ACCEPTED_LABELS.get(etype, set())
        hit = False
        for idx, (label, f_start, f_end) in enumerate(findings):
            if label in accepted and _overlaps(s_start, s_end, f_start, f_end):
                hit = True
                matched_finding_idx.add(idx)
                break
        c = per_type.setdefault(etype, Counts())
        if hit:
            c.tp += 1
        else:
            c.fn += 1

    # A finding is a true "extra" (potential false positive) only if it
    # overlaps NO injected span at all. A finding that overlaps a known-PII
    # span (e.g. Presidio tagging the domain inside an injected email as a
    # URL) is not penalised — that region is already sensitive.
    tracked = {lbl for labels in ACCEPTED_LABELS.values() for lbl in labels}
    for idx, (label, f_start, f_end) in enumerate(findings):
        if idx in matched_finding_idx or label not in tracked:
            continue
        if any(_overlaps(f_start, f_end, s_start, s_end) for _, s_start, s_end in prompt.spans):
            continue  # overlaps some injected PII — not a false positive
        for etype, accepted in ACCEPTED_LABELS.items():
            if label in accepted:
                per_type.setdefault(etype, Counts()).unmatched_findings += 1
                break


# ---------------------------------------------------------------------------
# Worker — runs in each process. Returns (latencies, per_type_counts).
# ---------------------------------------------------------------------------
def _scan_chunk(args):
    chunk, backend, min_conf = args
    # Import inside the worker so each process initialises its own analyzer.
    from contextduty.nlp._scanner import scan_text_nlp, set_backend

    if backend:
        set_backend(backend)

    latencies: list[float] = []
    per_type: dict[str, Counts] = {}

    for text, spans in chunk:
        t0 = time.perf_counter()
        result = scan_text_nlp(text, min_confidence=min_conf, extract_segments=False)
        latencies.append((time.perf_counter() - t0) * 1000.0)  # ms

        findings = [(f.entity_label, f.start, f.end) for f in result.findings]
        score_prompt(LabeledPrompt(text=text, spans=spans), findings, per_type)

    return latencies, {k: (v.tp, v.fn, v.unmatched_findings) for k, v in per_type.items()}


def _chunks(seq, n):
    k, m = divmod(len(seq), n)
    out = []
    start = 0
    for i in range(n):
        size = k + (1 if i < m else 0)
        out.append(seq[start : start + size])
        start += size
    return [c for c in out if c]


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--rows", type=int, default=100_000, help="number of prompts (default 100000)")
    ap.add_argument("--domain", default="mixed", choices=list(TEMPLATES) + ["mixed"])
    ap.add_argument("--workers", type=int, default=1, help="parallel worker processes")
    ap.add_argument(
        "--backend", default=None, choices=["presidio", "spacy"], help="force a backend"
    )
    ap.add_argument("--min-confidence", type=float, default=0.5)
    ap.add_argument("--seed", type=int, default=1234)
    ap.add_argument("--json", default=None, help="write full report to this JSON path")
    args = ap.parse_args()

    from contextduty.nlp._scanner import get_backend, set_backend

    if args.backend:
        set_backend(args.backend)
    backend = get_backend()

    print("ContextDuty NLP benchmark", file=sys.stderr)
    print(f"  backend     : {backend}", file=sys.stderr)
    print(f"  rows        : {args.rows:,}", file=sys.stderr)
    print(f"  domain      : {args.domain}", file=sys.stderr)
    print(f"  workers     : {args.workers}", file=sys.stderr)
    print(f"  min_conf    : {args.min_confidence}", file=sys.stderr)
    print("  generating dataset…", file=sys.stderr)

    dataset = generate_dataset(args.rows, args.domain, args.seed)
    payload = [(p.text, p.spans) for p in dataset]

    print("  scanning…", file=sys.stderr)
    wall0 = time.perf_counter()

    all_latencies: list[float] = []
    agg: dict[str, Counts] = {}

    if args.workers <= 1:
        latencies, counts = _scan_chunk((payload, args.backend, args.min_confidence))
        all_latencies = latencies
        for k, (tp, fn, uf) in counts.items():
            c = agg.setdefault(k, Counts())
            c.tp += tp
            c.fn += fn
            c.unmatched_findings += uf
    else:
        chunks = _chunks(payload, args.workers)
        work = [(c, args.backend, args.min_confidence) for c in chunks]
        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            for latencies, counts in pool.map(_scan_chunk, work):
                all_latencies.extend(latencies)
                for k, (tp, fn, uf) in counts.items():
                    c = agg.setdefault(k, Counts())
                    c.tp += tp
                    c.fn += fn
                    c.unmatched_findings += uf

    wall = time.perf_counter() - wall0

    # ---- Latency ----
    lat = {
        "mean_ms": round(statistics.fmean(all_latencies), 3),
        "p50_ms": round(percentile(all_latencies, 50), 3),
        "p90_ms": round(percentile(all_latencies, 90), 3),
        "p95_ms": round(percentile(all_latencies, 95), 3),
        "p99_ms": round(percentile(all_latencies, 99), 3),
        "max_ms": round(max(all_latencies), 3),
        "wall_s": round(wall, 2),
        "throughput_rps": round(len(all_latencies) / wall, 1) if wall else 0.0,
    }

    # ---- Quality ----
    quality = {}
    tot_tp = tot_fn = tot_uf = 0
    for etype in sorted(agg):
        c = agg[etype]
        tot_tp += c.tp
        tot_fn += c.fn
        tot_uf += c.unmatched_findings
        recall = c.tp / (c.tp + c.fn) if (c.tp + c.fn) else 0.0
        precision = c.tp / (c.tp + c.unmatched_findings) if (c.tp + c.unmatched_findings) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        quality[etype] = {
            "injected": c.tp + c.fn,
            "detected": c.tp,
            "missed": c.fn,
            "extra_findings": c.unmatched_findings,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }
    overall_recall = tot_tp / (tot_tp + tot_fn) if (tot_tp + tot_fn) else 0.0
    overall_prec = tot_tp / (tot_tp + tot_uf) if (tot_tp + tot_uf) else 0.0
    overall_f1 = (
        2 * overall_prec * overall_recall / (overall_prec + overall_recall)
        if (overall_prec + overall_recall)
        else 0.0
    )

    # ---- Report ----
    print("\n" + "=" * 64)
    print(f"  LATENCY  (backend={backend}, rows={len(all_latencies):,})")
    print("=" * 64)
    print(
        f"  mean {lat['mean_ms']:.2f} ms | p50 {lat['p50_ms']:.2f} | p90 {lat['p90_ms']:.2f} "
        f"| p95 {lat['p95_ms']:.2f} | p99 {lat['p99_ms']:.2f} | max {lat['max_ms']:.2f}"
    )
    print(f"  wall {lat['wall_s']:.1f}s | throughput {lat['throughput_rps']:.1f} prompts/sec")

    print("\n" + "=" * 64)
    print("  QUALITY  (per entity type)")
    print("=" * 64)
    print(
        f"  {'entity':<14}{'inj':>7}{'hit':>7}{'miss':>7}{'extra':>7}{'prec':>8}{'rec':>8}{'f1':>8}"
    )
    print("  " + "-" * 60)
    for etype, q in quality.items():
        print(
            f"  {etype:<14}{q['injected']:>7}{q['detected']:>7}{q['missed']:>7}"
            f"{q['extra_findings']:>7}{q['precision']:>8.3f}{q['recall']:>8.3f}{q['f1']:>8.3f}"
        )
    print("  " + "-" * 60)
    print(
        f"  {'OVERALL':<14}{tot_tp + tot_fn:>7}{tot_tp:>7}{tot_fn:>7}{tot_uf:>7}"
        f"{overall_prec:>8.3f}{overall_recall:>8.3f}{overall_f1:>8.3f}"
    )
    print()

    if args.json:
        report = {
            "config": {
                "backend": backend,
                "rows": args.rows,
                "domain": args.domain,
                "workers": args.workers,
                "min_confidence": args.min_confidence,
            },
            "latency": lat,
            "quality": quality,
            "overall": {
                "precision": round(overall_prec, 4),
                "recall": round(overall_recall, 4),
                "f1": round(overall_f1, 4),
            },
        }
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  full report → {args.json}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
