# AgentShield - Report Contributions (Aditya Shenoy)

My written contributions to the final report, covering the dataset, red-team, and
evaluation-data track. Each file below is a self-contained section that maps to a
part of the team's final report; paste them into the corresponding section.

## Files -> final-report section

| File | Feeds final-report section |
| --- | --- |
| [`dataset_documentation.md`](dataset_documentation.md) | Dataset (composition, schema, labels, PII policy) |
| [`redteam_method.md`](redteam_method.md) | Methodology - red-team attack generation |
| [`failure_analysis.md`](failure_analysis.md) | Evaluation - failure analysis / limitations |
| [`demo_scenarios.md`](demo_scenarios.md) | Demo - selected scenarios (the "it works" story) |
| [`firewall_vs_label.md`](firewall_vs_label.md) | Appendix - raw firewall-vs-label data supporting the failure analysis |
| [`contribution_summary.md`](contribution_summary.md) | Milestone / task split (my contribution) |
| [`demo_scenarios_selected.json`](demo_scenarios_selected.json) | Demo input file (runnable scenarios) |

## How the sections connect

The dataset documentation describes *what* the corpus is; the red-team method
describes *how* the adversarial half was generated; the failure analysis reports
*what that corpus found* and how the current policy now handles it; and the demo
scenarios show all three decision paths. `firewall_vs_label.md` is the
reproducible raw data underpinning the analysis.

## Provenance

All numbers were reconciled against `data/corpus_report.py` and
`data/quality_report.py` (M7-S2 Step 6): 85 report-corpus examples, 35 benign /
50 malicious, 85/85 firewall agreement. The full stored evaluation covers 94
scenarios including demo and sample examples. All content is
synthetic (`*.example` domains, `<synthetic-...-placeholder>` tokens).
