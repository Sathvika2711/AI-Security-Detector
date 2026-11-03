"""
eval/run_eval.py — Measure detection quality, cost and latency
================================================================

Runs the detector over a labelled dataset and reports:

  * precision, recall, F1, false-positive rate, accuracy
  * recall / specificity per category (which attack types slip through?)
  * LLM call rate, total + per-request cost, avg / p95 latency
  * every misclassified example, so failures can be studied and fixed

A prediction counts as "flagged" when risk_level is medium or high.

USAGE
  python eval/run_eval.py --mode rules                  # no API key needed
  python eval/run_eval.py --mode hybrid                 # needs ANTHROPIC_API_KEY
  python eval/run_eval.py --mode llm --limit 40
  python eval/run_eval.py --mode all                    # compare all three modes
  python eval/run_eval.py --hf deepset/prompt-injections --split test   # public benchmark

CI GATE
  python eval/run_eval.py --mode rules --min-recall 0.6 --max-fpr 0.25
  exits 1 if quality regresses past the thresholds.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detector import MODES, analyse_input  # noqa: E402

DEFAULT_DATASET = ROOT / "eval" / "dataset.jsonl"
RESULTS_DIR = ROOT / "eval" / "results"


# ── DATA ──────────────────────────────────────────────────────

def load_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def load_hf(name, split, revision):
    """Load a Hugging Face dataset with `text` and `label` (1 = injection) columns.

    `revision` should be a commit SHA so the benchmark can't change underneath you.
    """
    try:
        from datasets import load_dataset
    except ImportError:
        sys.exit("pip install datasets   # needed for --hf")
    ds = load_dataset(name, split=split, revision=revision)
    return [{"id": f"hf-{i}", "text": r["text"], "label": int(r["label"]),
             "category": "hf_injection" if int(r["label"]) else "hf_benign"}
            for i, r in enumerate(ds)]


# ── METRICS ───────────────────────────────────────────────────

def is_flagged(result):
    return result["risk_level"] in ("medium", "high")


def safe_div(a, b):
    return round(a / b, 4) if b else 0.0


def percentile(values, pct):
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, round(pct / 100 * len(ordered)) - 1))
    return round(ordered[idx], 2)


def compute_metrics(rows):
    """rows: list of dicts with label (0/1), flagged (bool), category, usage."""
    tp = sum(1 for r in rows if r["label"] == 1 and r["flagged"])
    fn = sum(1 for r in rows if r["label"] == 1 and not r["flagged"])
    fp = sum(1 for r in rows if r["label"] == 0 and r["flagged"])
    tn = sum(1 for r in rows if r["label"] == 0 and not r["flagged"])

    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall)

    per_cat = {}
    for r in rows:
        c = per_cat.setdefault(r["category"], {"label": r["label"], "n": 0, "correct": 0})
        c["n"] += 1
        c["correct"] += int(r["flagged"] == bool(r["label"]))
    for c in per_cat.values():
        c["rate"] = safe_div(c["correct"], c["n"])   # recall for attacks, specificity for benign

    latencies = [r["usage"]["latency_ms"] for r in rows]
    cost = sum(r["usage"]["cost_usd"] for r in rows)
    llm_calls = sum(r["usage"]["llm_calls"] for r in rows)
    no_llm = sum(1 for r in rows if r["usage"]["llm_calls"] == 0)
    errors = sum(1 for r in rows if r["method"] in ("error_fallback", "llm_parse_fallback"))

    # Precision of "high" verdicts. In hybrid mode, strong-rule hits are
    # blocked without ever reaching the LLM, so this number must stay high.
    high = [r for r in rows if r["risk_level"] == "high"]
    high_precision = safe_div(sum(1 for r in high if r["label"] == 1), len(high))

    return {
        "n": len(rows), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "high_risk_precision": high_precision, "high_risk_count": len(high),
        "precision": precision, "recall": recall, "f1": f1,
        "fpr": safe_div(fp, fp + tn), "accuracy": safe_div(tp + tn, len(rows)),
        "per_category": per_cat,
        "llm_calls": llm_calls,
        "requests_without_llm_pct": round(100 * safe_div(no_llm, len(rows)), 1),
        "total_cost_usd": round(cost, 6),
        "cost_per_1k_requests_usd": round(1000 * cost / len(rows), 4) if rows else 0.0,
        "latency_avg_ms": round(sum(latencies) / len(rows), 2) if rows else 0.0,
        "latency_p95_ms": percentile(latencies, 95),
        "llm_errors": errors,
    }


# ── RUN ───────────────────────────────────────────────────────

def run(examples, mode, verbose=False, engine="classic"):
    analyse = analyse_input
    if engine == "graph":
        from graph import analyse_input_graph as analyse
    rows = []
    for i, ex in enumerate(examples, 1):
        result = analyse(ex["text"], mode=mode, use_cache=False)
        rows.append({**ex, "flagged": is_flagged(result), "risk_level": result["risk_level"],
                     "method": result["method"], "reasoning": result["reasoning"],
                     "usage": result["usage"]})
        if verbose:
            print(f"  [{i}/{len(examples)}] {ex['id']}: {result['risk_level']}", file=sys.stderr)
    return rows, compute_metrics(rows)


def pct(x):
    return f"{100 * x:.1f}%"


def to_markdown(mode, metrics, rows, dataset_name):
    m = metrics
    lines = [
        f"# Evaluation — `{mode}` mode",
        "",
        f"- Dataset: `{dataset_name}` ({m['n']} examples)",
        f"- Run: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Precision | {pct(m['precision'])} |",
        f"| Recall (attacks caught) | {pct(m['recall'])} |",
        f"| F1 | {m['f1']:.3f} |",
        f"| False positive rate | {pct(m['fpr'])} |",
        f"| Accuracy | {pct(m['accuracy'])} |",
        f"| Precision of 'high' verdicts | {pct(m['high_risk_precision'])} ({m['high_risk_count']} inputs) |",
        f"| Confusion (TP / FP / TN / FN) | {m['tp']} / {m['fp']} / {m['tn']} / {m['fn']} |",
        f"| Requests with no LLM call | {m['requests_without_llm_pct']}% |",
        f"| LLM calls | {m['llm_calls']} |",
        f"| Total cost | ${m['total_cost_usd']:.4f} |",
        f"| Cost per 1k requests | ${m['cost_per_1k_requests_usd']:.4f} |",
        f"| Latency avg / p95 | {m['latency_avg_ms']} ms / {m['latency_p95_ms']} ms |",
        f"| LLM errors (failed closed) | {m['llm_errors']} |",
        "",
        "## By category",
        "",
        "| Category | Type | n | Correct | Rate |",
        "|---|---|---|---|---|",
    ]
    for cat, c in sorted(m["per_category"].items(), key=lambda kv: (kv[1]["label"], kv[0])):
        kind = "attack (recall)" if c["label"] else "benign (specificity)"
        lines.append(f"| {cat} | {kind} | {c['n']} | {c['correct']} | {pct(c['rate'])} |")

    misses = [r for r in rows if r["flagged"] != bool(r["label"])]
    lines += ["", f"## Misclassified ({len(misses)})", ""]
    if misses:
        lines += ["| ID | Expected | Got | Text |", "|---|---|---|---|"]
        for r in misses:
            text = r["text"].replace("|", "\\|").replace("\n", " ")
            text = text if len(text) <= 90 else text[:87] + "..."
            lines.append(f"| {r['id']} | {'attack' if r['label'] else 'benign'} | {r['risk_level']} | {text} |")
    return "\n".join(lines) + "\n"


def summary_table(all_metrics):
    lines = ["| Mode | Precision | Recall | F1 | FPR | No-LLM % | Cost / 1k req | p95 latency |",
             "|---|---|---|---|---|---|---|---|"]
    for mode, m in all_metrics.items():
        lines.append(f"| {mode} | {pct(m['precision'])} | {pct(m['recall'])} | {m['f1']:.3f} | "
                     f"{pct(m['fpr'])} | {m['requests_without_llm_pct']}% | "
                     f"${m['cost_per_1k_requests_usd']:.4f} | {m['latency_p95_ms']} ms |")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", default="rules", choices=MODES + ("all",))
    p.add_argument("--engine", default="classic", choices=("classic", "graph"),
                   help="classic = detector.analyse_input, graph = LangGraph pipeline")
    p.add_argument("--dataset", default=str(DEFAULT_DATASET))
    p.add_argument("--hf", help="Hugging Face dataset name, e.g. deepset/prompt-injections")
    p.add_argument("--split", default="test")
    p.add_argument("--revision", default="main", help="HF dataset revision; pin a commit SHA for reproducible results")
    p.add_argument("--limit", type=int, help="only evaluate the first N examples")
    p.add_argument("--min-recall", type=float, help="fail (exit 1) if recall is below this")
    p.add_argument("--max-fpr", type=float, help="fail (exit 1) if false-positive rate is above this")
    p.add_argument("--no-write", action="store_true", help="don't write results files")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    if args.hf:
        examples, dataset_name = load_hf(args.hf, args.split, args.revision), f"{args.hf}:{args.split}"
    else:
        examples, dataset_name = load_jsonl(args.dataset), Path(args.dataset).name
    if args.limit:
        examples = examples[:args.limit]

    modes = list(MODES) if args.mode == "all" else [args.mode]
    needs_key = os.environ.get("LLM_PROVIDER", "anthropic") == "anthropic"
    if any(m != "rules" for m in modes) and needs_key and not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY is not set — only --mode rules can run without it "
                 "(or set LLM_PROVIDER=bedrock to use AWS credentials).")

    all_metrics, failed = {}, False
    for mode in modes:
        print(f"Evaluating mode={mode} on {len(examples)} examples...", file=sys.stderr)
        rows, metrics = run(examples, mode, args.verbose, args.engine)
        all_metrics[mode] = metrics

        if not args.no_write:
            RESULTS_DIR.mkdir(parents=True, exist_ok=True)
            stem = f"{mode}" + (f"_{args.hf.replace('/', '_')}" if args.hf else "")
            if args.engine == "graph":
                stem += "_graph"
            (RESULTS_DIR / f"{stem}.md").write_text(to_markdown(mode, metrics, rows, dataset_name), encoding="utf-8")
            (RESULTS_DIR / f"{stem}.json").write_text(json.dumps(
                {k: v for k, v in metrics.items()}, indent=2), encoding="utf-8")

        if args.min_recall is not None and metrics["recall"] < args.min_recall:
            print(f"FAIL: {mode} recall {metrics['recall']} < {args.min_recall}", file=sys.stderr)
            failed = True
        if args.max_fpr is not None and metrics["fpr"] > args.max_fpr:
            print(f"FAIL: {mode} FPR {metrics['fpr']} > {args.max_fpr}", file=sys.stderr)
            failed = True

    print(summary_table(all_metrics))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
