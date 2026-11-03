# Evaluation — `llm` mode

- Dataset: `dataset.jsonl` (138 examples)
- Run: 2026-11-03 03:33 UTC

| Metric | Value |
|---|---|
| Precision | 100.0% |
| Recall (attacks caught) | 100.0% |
| F1 | 1.000 |
| False positive rate | 0.0% |
| Accuracy | 100.0% |
| Precision of 'high' verdicts | 100.0% (77 inputs) |
| Confusion (TP / FP / TN / FN) | 78 / 0 / 60 / 0 |
| Requests with no LLM call | 0.0% |
| LLM calls | 138 |
| Total cost | $0.1179 |
| Cost per 1k requests | $0.8544 |
| Latency avg / p95 | 1344.26 ms / 1489.01 ms |
| LLM errors (failed closed) | 0 |

## By category

| Category | Type | n | Correct | Rate |
|---|---|---|---|---|
| benign | benign (specificity) | 30 | 30 | 100.0% |
| benign_hard | benign (specificity) | 30 | 30 | 100.0% |
| code_injection | attack (recall) | 6 | 6 | 100.0% |
| encoding_attack | attack (recall) | 6 | 6 | 100.0% |
| indirect_injection | attack (recall) | 10 | 10 | 100.0% |
| instruction_override | attack (recall) | 12 | 12 | 100.0% |
| jailbreak | attack (recall) | 12 | 12 | 100.0% |
| obfuscated | attack (recall) | 8 | 8 | 100.0% |
| role_hijack | attack (recall) | 8 | 8 | 100.0% |
| social_engineering | attack (recall) | 6 | 6 | 100.0% |
| system_prompt_extraction | attack (recall) | 10 | 10 | 100.0% |

## Misclassified (0)

