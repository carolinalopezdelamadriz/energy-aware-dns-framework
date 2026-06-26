# Sample results for supervisor review

Curated outputs from `results/run_20260626/analysis/` (5 sites: BBC, Wikipedia,
GitHub, Python.org, IETF).

Attach these files to the update email:

| File | Description |
| --- | --- |
| `resumen_experimento.md` | Summary tables (DNS, web, resource origin) |
| `dns_bytes.png` | DNS vs DoH vs DoQ average bytes (log scale) |
| `web_trafico.png` | PCAP vs CDP comparison per site |
| `origen_recursos.png` | CDP bytes by origin class |
| `dashboard.png` | Combined overview figure |

Regenerate after re-running analysis:

```bash
python3 src/main.py --mode analyze --run-dir results/run_20260626
cp results/run_20260626/analysis/summary.md docs/email_tutora/resumen_experimento.md
cp results/run_20260626/analysis/fig_dns_avg_bytes.png docs/email_tutora/dns_bytes.png
cp results/run_20260626/analysis/fig_web_traffic_comparison.png docs/email_tutora/web_trafico.png
cp results/run_20260626/analysis/fig_web_origin_bytes.png docs/email_tutora/origen_recursos.png
cp results/run_20260626/analysis/fig_dashboard.png docs/email_tutora/dashboard.png
```
