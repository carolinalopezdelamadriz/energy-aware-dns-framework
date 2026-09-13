# Analysis summary

Run directory: `results/20260709_001914`

Compact overview of protocol overhead, captured web traffic and estimated carbon footprint.

## DNS protocol comparison

| Protocol | Samples | Median bytes (IQR) | Avg bytes | Median CO₂ (kg) | Overhead vs DNS (median) | Avg bursts | Avg burst bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DNS | 100 | 1.1 KB (IQR 1.0 KB–1.1 KB) | 1.1 KB | 1.843349e-08 | 1.0× | 9.9 | 122 B |
| DOH | 100 | 38.0 KB (IQR 37.9 KB–38.2 KB) | 38.1 KB | 6.505485e-07 | 35.3× | 54.2 | 721 B |
| DOQ | 100 | 41.4 KB (IQR 41.3 KB–42.7 KB) | 51.6 KB | 7.071764e-07 | 38.4× | 49.3 | 1.0 KB |

Median is the headline statistic (a handful of extreme captures shouldn't move the reported "typical" cost the way they can move a mean); avg is kept alongside for reference, full avg/median/min/max/IQR in `dns_protocol_summary.csv`.

Burst = maximal run of consecutive packets in the same direction (website-fingerprinting literature definition). Even where DoH/DoQ encrypt the query content, the burst-size sequence on the wire stays observable — see `fig_burst_patterns.png` and the per-visit `dns_*_bursts.json` files for the full sequence per domain.

### Paired protocol comparison (Wilcoxon signed-rank)

| Comparison | Site pairs | p-value | Effect size (rank-biserial r) |
| --- | ---: | ---: | ---: |
| DNS vs DOH | 100 | 3.89e-18 | -1.00 |
| DOH vs DOQ | 100 | 3.90e-18 | -1.00 |

Paired by site (same site measured under both protocols in this run), which is the right test here since bytes for the same domain under different protocols aren't independent samples. r close to ±1 means almost every site moved in the same direction; r near 0 would mean the protocols aren't consistently different site-by-site.

### Overhead breakdown (handshake / control / payload)

| Protocol | Handshake | Control | Payload | Handshake share |
| --- | ---: | ---: | ---: | ---: |
| DNS | 0 B | 422 B | 684 B | 0.0% |
| DOH | 29.1 KB | 4.0 KB | 5.0 KB | 76.5% |
| DOQ | 48.6 KB | 0 B | 3.0 KB | 94.3% |

Decrypted from the pcap with the saved TLS/QUIC session keys (see `overhead_breakdown.py`), not just a total. DoQ's "payload" bucket mixes real response data with a small, undistinguished share of 1-RTT ACKs — see the module docstring for why that finer split isn't reliable here — and coalesced QUIC datagrams (handshake + 1-RTT packet in one UDP frame) are counted entirely as handshake.

## Web traffic by category

Excludes 31 flagged sites (see "Data quality" section below). Median overhead is shown instead of the mean because a handful of extreme values per category can otherwise dominate an average computed from only ~10 sites — see `web_category_summary.csv` for the full avg/median/min/max breakdown.

| Category | Sites | Median PCAP bytes | Median CDP bytes | Median overhead % | Median CO₂ (kg) | Avg CO₂ (kg) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Banking | 29 | 2.2 MB | 1.4 MB | 43.1% | 3.928453e-05 | 2.092539e-04 |
| Ecommerce | 20 | 4.1 MB | 3.1 MB | 58.5% | 7.264331e-05 | 9.070327e-05 |
| Education | 30 | 4.3 MB | 3.1 MB | 82.3% | 7.614569e-05 | 1.402061e-04 |
| Health | 29 | 2.4 MB | 1.7 MB | 43.2% | 4.280161e-05 | 8.046729e-05 |
| News | 24 | 3.7 MB | 2.6 MB | 45.8% | 6.508507e-05 | 2.878858e-04 |
| Public Admin | 23 | 3.0 MB | 2.3 MB | 30.9% | 5.279974e-05 | 4.824935e-05 |
| Social Media | 30 | 3.3 MB | 2.6 MB | 31.6% | 5.823899e-05 | 1.389964e-04 |
| Standards | 27 | 898.4 KB | 658.6 KB | 53.3% | 1.536017e-05 | 7.530286e-05 |
| Streaming | 30 | 7.5 MB | 4.1 MB | 101.3% | 1.317326e-04 | 1.963044e-04 |
| Technology | 27 | 5.5 MB | 2.3 MB | 58.2% | 9.547553e-05 | 1.665692e-04 |

## DNS cost of privacy as a share of page weight

Bridges the two halves of this framework into one number: for each page, the number of distinct domains its resources needed resolved × this run's own measured DoH-vs-classic-DNS bytes overhead per resolution, as a percentage of that page's own PCAP bytes. Answers the research question directly instead of leaving the DNS-side and web-side results to be compared by eye.

### Cold-start (no connection reuse)

| Category | Sites | Median domains resolved | Median DNS privacy cost (% of page) |
| --- | ---: | ---: | ---: |
| Banking | 29 | 5 | 1.590% |
| Ecommerce | 20 | 7 | 1.137% |
| Education | 30 | 6 | 1.048% |
| Health | 29 | 8 | 1.608% |
| News | 24 | 32 | 3.533% |
| Public Admin | 23 | 4 | 1.230% |
| Social Media | 30 | 4 | 0.964% |
| Standards | 27 | 2 | 1.653% |
| Streaming | 30 | 10 | 1.121% |
| Technology | 27 | 14 | 2.644% |

### Amortized (connection reused)

No data for this mode in this run.

Per-site detail: `dns_privacy_cost_by_site.csv`. Uses a single run-wide median per-resolution overhead (not a per-domain figure) - this run's own handshake/control/payload breakdown above already shows that cost is dominated by protocol/connection overhead, not by which specific domain is being resolved, so one representative figure applied per domain is more defensible than it would first appear.

## Highest overhead sites (top 10)

| Site | Category | Overhead % | PCAP bytes | CDP bytes |
| --- | --- | ---: | ---: | ---: |
| netflix | Streaming | 878.7% | 24.6 MB | 2.5 MB |
| coursera | Education | 850.7% | 16.9 MB | 1.8 MB |
| edx | Education | 816.8% | 46.6 MB | 5.1 MB |
| icann | Standards | 808.2% | 342.5 KB | 37.7 KB |
| edx | Education | 795.6% | 45.5 MB | 5.1 MB |
| wired | Technology | 748.5% | 63.7 MB | 7.5 MB |
| aliexpress | Ecommerce | 720.9% | 28.1 MB | 3.4 MB |
| techcrunch | Technology | 694.8% | 21.0 MB | 2.6 MB |
| spotify | Streaming | 673.8% | 35.3 MB | 4.6 MB |
| eff | Standards | 651.8% | 23.0 MB | 3.1 MB |

## Highest carbon footprint sites (top 10)

| Site | Category | CO₂ (kg) | PCAP bytes |
| --- | --- | ---: | ---: |
| santander | Banking | 1.393853e-03 | 79.6 MB |
| santander | Banking | 1.364387e-03 | 77.9 MB |
| santander | Banking | 1.283289e-03 | 73.3 MB |
| wired | Technology | 1.115114e-03 | 63.7 MB |
| apnews | News | 9.346066e-04 | 53.4 MB |
| apnews | News | 9.345470e-04 | 53.4 MB |
| cnn | News | 8.634170e-04 | 49.3 MB |
| edx | Education | 8.154911e-04 | 46.6 MB |
| edx | Education | 7.966664e-04 | 45.5 MB |
| apnews | News | 7.937754e-04 | 45.3 MB |

Full per-site detail (including flagged sites): `web_site_summary.csv`.

## Data quality — sites excluded from category stats and plots

31 of 300 site visits (10%) were excluded from the tables and plots above, by likely cause: 12 likely bot-blocked or failed to load (CDP payload under 29.3 KB with an extreme PCAP/CDP ratio), 0 with direct evidence of capture contamination (port-scoping failed for that visit, or background noise large relative to that visit's own PCAP), and 19 statistically extreme outliers with no identified cause. See docs/apuntes_personales/ISSUES_LOG.md, Issues 5/7/10/14.

| Site | Category | Reason | Overhead % | PCAP bytes | CDP bytes |
| --- | --- | --- | ---: | ---: | ---: |
| reuters | News | Likely bot-blocked / failed load | 3001.9% | 563.0 KB | 18.2 KB |
| reuters | News | Likely bot-blocked / failed load | 1974.2% | 359.8 KB | 17.3 KB |
| reuters | News | Likely bot-blocked / failed load | 2210.6% | 400.8 KB | 17.3 KB |
| elpais | News | Likely bot-blocked / failed load | 3456.1% | 606.2 KB | 17.0 KB |
| elpais | News | Likely bot-blocked / failed load | 2080.6% | 354.0 KB | 16.2 KB |
| elpais | News | Likely bot-blocked / failed load | 2431.0% | 411.0 KB | 16.2 KB |
| etsy | Ecommerce | Likely bot-blocked / failed load | 2968.2% | 527.9 KB | 17.2 KB |
| etsy | Ecommerce | Likely bot-blocked / failed load | 1592.1% | 277.0 KB | 16.4 KB |
| etsy | Ecommerce | Likely bot-blocked / failed load | 1540.4% | 268.8 KB | 16.4 KB |
| hackernews | Technology | Likely bot-blocked / failed load | 2931.3% | 342.4 KB | 11.3 KB |
| hackernews | Technology | Likely bot-blocked / failed load | 2778.2% | 325.1 KB | 11.3 KB |
| hackernews | Technology | Likely bot-blocked / failed load | 2725.9% | 319.2 KB | 11.3 KB |
| ing_es | Banking | Statistically extreme (cause unclear) | 1415.4% | 27.5 MB | 1.8 MB |
| boe | Public Admin | Statistically extreme (cause unclear) | 5343.3% | 41.4 MB | 779.5 KB |
| boe | Public Admin | Statistically extreme (cause unclear) | 5341.8% | 41.4 MB | 779.5 KB |
| boe | Public Admin | Statistically extreme (cause unclear) | 5344.3% | 41.4 MB | 779.5 KB |
| usa_gov | Public Admin | Statistically extreme (cause unclear) | 1348.5% | 17.4 MB | 1.2 MB |
| canada_gov | Public Admin | Statistically extreme (cause unclear) | 5517.3% | 41.6 MB | 758.9 KB |
| canada_gov | Public Admin | Statistically extreme (cause unclear) | 5519.9% | 41.7 MB | 758.9 KB |
| canada_gov | Public Admin | Statistically extreme (cause unclear) | 5512.6% | 41.6 MB | 759.6 KB |
| amazon | Ecommerce | Statistically extreme (cause unclear) | 1032.3% | 46.2 MB | 4.1 MB |
| aliexpress | Ecommerce | Statistically extreme (cause unclear) | 1217.1% | 45.0 MB | 3.4 MB |
| aliexpress | Ecommerce | Statistically extreme (cause unclear) | 1003.9% | 37.8 MB | 3.4 MB |
| otto_de | Ecommerce | Statistically extreme (cause unclear) | 1140.5% | 40.3 MB | 3.2 MB |
| otto_de | Ecommerce | Statistically extreme (cause unclear) | 1067.7% | 37.6 MB | 3.2 MB |
| mediamarkt | Ecommerce | Statistically extreme (cause unclear) | 1299.4% | 41.9 MB | 3.0 MB |
| mediamarkt | Ecommerce | Statistically extreme (cause unclear) | 1381.4% | 44.3 MB | 3.0 MB |
| clevelandclinic | Health | Statistically extreme (cause unclear) | 2516.4% | 44.9 MB | 1.7 MB |
| ecma | Standards | Statistically extreme (cause unclear) | 2418.7% | 43.3 MB | 1.7 MB |
| ecma | Standards | Statistically extreme (cause unclear) | 2417.6% | 43.3 MB | 1.7 MB |
| ecma | Standards | Statistically extreme (cause unclear) | 2419.7% | 43.3 MB | 1.7 MB |

Full detail: `web_flagged_sites.csv`. Consider re-running these sites once the underlying cause (bot detection / background network noise) is addressed.

## Resource origin profile

| Origin class | Sites | Total CDP bytes | Share of CDP |
| --- | ---: | ---: | ---: |
| First party | 92 | 605.7 MB | 57.5% |
| Third party | 81 | 392.7 MB | 37.2% |
| Trackers & ads (high-confidence lower bound) | 52 | 55.9 MB | 5.3% |

The tracker/ads figure is a high-confidence subset match (`TRACKER_DOMAINS`/`TRACKER_KEYWORDS` in `browser.py`, precision chosen over recall - see ISSUES_LOG.md Issue 16), not an exhaustive tracker list - treat it as a lower bound on real tracking traffic, not a complete count.

## Generated figures

- `fig_dns_avg_bytes.png`
- `fig_dns_co2_by_protocol.png`
- `fig_overhead_breakdown.png`
- `fig_burst_patterns.png`
- `fig_web_overhead_scatter.png`
- `fig_web_bytes_by_category.png`
- `fig_web_overhead_by_category.png`
- `fig_web_origin_bytes.png`
- `fig_cfp_by_category.png`
- `fig_dashboard.png`
