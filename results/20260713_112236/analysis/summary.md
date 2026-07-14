# Analysis summary

Run directory: `results/20260713_112236`

Compact overview of protocol overhead, captured web traffic and estimated carbon footprint.

## DNS protocol comparison

| Protocol | Samples | Median bytes (IQR) | Avg bytes | Median CO₂ (kg) | Overhead vs DNS (median) | Avg bursts | Avg burst bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DNS | 10 | 1.0 KB (IQR 1.0 KB–1.1 KB) | 1.1 KB | 1.755690e-08 | 1.0× | 10.0 | 108 B |
| DOH | 10 | 38.0 KB (IQR 38.0 KB–38.1 KB) | 38.1 KB | 6.501645e-07 | 37.0× | 54.6 | 716 B |
| DOQ | 10 | 41.2 KB (IQR 41.2 KB–41.4 KB) | 47.6 KB | 7.052646e-07 | 40.2× | 46.0 | 1.0 KB |

Median is the headline statistic (a handful of extreme captures shouldn't move the reported "typical" cost the way they can move a mean); avg is kept alongside for reference, full avg/median/min/max/IQR in `dns_protocol_summary.csv`.

Burst = maximal run of consecutive packets in the same direction (website-fingerprinting literature definition). Even where DoH/DoQ encrypt the query content, the burst-size sequence on the wire stays observable — see `fig_burst_patterns.png` and the per-visit `dns_*_bursts.json` files for the full sequence per domain.

### Cost per single query

| Protocol | Median bytes/query | Median energy/query (kWh) | Median CO₂/query (kg) |
| --- | ---: | ---: | ---: |
| DNS | 210 B | 1.241e-08 | 3.511e-09 |
| DOH | 7.6 KB | 4.595e-07 | 1.300e-07 |
| DOQ | 8.2 KB | 4.984e-07 | 1.411e-07 |

Same measurements as the table above, divided by each experiment's own `repetitions` count - the cost of a single resolution instead of a batch of 5. The ×ratios don't change either way (same repetitions count for all three protocols in a given run), only these absolute per-query figures do. At this scale CO₂ is a tiny fraction of a gram per query - the % of page weight table below is the more communicable framing of the same result.

### Paired protocol comparison (Wilcoxon signed-rank)

| Comparison | Site pairs | p-value | Effect size (rank-biserial r) |
| --- | ---: | ---: | ---: |
| DNS vs DOH | 10 | 1.95e-03 | -1.00 |
| DOH vs DOQ | 10 | 1.95e-03 | -1.00 |

Paired by site (same site measured under both protocols in this run), which is the right test here since bytes for the same domain under different protocols aren't independent samples. r close to ±1 means almost every site moved in the same direction; r near 0 would mean the protocols aren't consistently different site-by-site.

### Overhead breakdown (handshake / control / payload)

| Protocol | Handshake | Control | Payload | Handshake share |
| --- | ---: | ---: | ---: | ---: |
| DNS | 0 B | 420 B | 664 B | 0.0% |
| DOH | 29.2 KB | 4.0 KB | 4.8 KB | 76.8% |
| DOQ | 44.7 KB | 0 B | 2.9 KB | 93.9% |

Decrypted from the pcap with the saved TLS/QUIC session keys (see `overhead_breakdown.py`), not just a total. DoQ's "payload" bucket mixes real response data with a small, undistinguished share of 1-RTT ACKs — see the module docstring for why that finer split isn't reliable here — and coalesced QUIC datagrams (handshake + 1-RTT packet in one UDP frame) are counted entirely as handshake.

## Web traffic by category

Excludes 1 flagged sites (see "Data quality" section below). Median overhead is shown instead of the mean because a handful of extreme values per category can otherwise dominate an average computed from only ~10 sites — see `web_category_summary.csv` for the full avg/median/min/max breakdown.

| Category | Sites | Median PCAP bytes | Median CDP bytes | Median overhead % | Median CO₂ (kg) | Avg CO₂ (kg) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Banking | 1 | 72.4 MB | 39.0 MB | 85.5% | 1.266774e-03 | 1.266774e-03 |
| Ecommerce | 1 | 6.2 MB | 4.6 MB | 34.6% | 1.078612e-04 | 1.078612e-04 |
| Health | 1 | 2.5 MB | 1.7 MB | 44.3% | 4.319486e-05 | 4.319486e-05 |
| News | 1 | 3.2 MB | 1.9 MB | 66.0% | 5.532467e-05 | 5.532467e-05 |
| Public Admin | 1 | 2.4 MB | 1.9 MB | 25.5% | 4.133499e-05 | 4.133499e-05 |
| Social Media | 1 | 3.3 MB | 2.6 MB | 26.3% | 5.829988e-05 | 5.829988e-05 |
| Standards | 1 | 1.3 MB | 947.1 KB | 37.2% | 2.221564e-05 | 2.221564e-05 |
| Streaming | 1 | 4.2 MB | 3.4 MB | 20.7% | 7.288616e-05 | 7.288616e-05 |
| Technology | 1 | 5.5 MB | 3.9 MB | 41.2% | 9.668550e-05 | 9.668550e-05 |

## DNS cost of privacy as a share of page weight

Bridges the two halves of this framework into one number: for each page, the number of distinct domains its resources needed resolved × this run's own measured DoH-vs-classic-DNS bytes overhead per resolution, as a percentage of that page's own PCAP bytes. Answers the research question directly instead of leaving the DNS-side and web-side results to be compared by eye.

### Cold-start (no connection reuse)

| Category | Sites | Median domains resolved | Median DNS privacy cost (% of page) |
| --- | ---: | ---: | ---: |
| Banking | 1 | 4 | 0.040% |
| Ecommerce | 1 | 7 | 0.821% |
| Health | 1 | 13 | 3.808% |
| News | 1 | 17 | 3.888% |
| Public Admin | 1 | 4 | 1.224% |
| Social Media | 1 | 5 | 1.085% |
| Standards | 1 | 3 | 1.709% |
| Streaming | 1 | 6 | 1.042% |
| Technology | 1 | 4 | 0.523% |

### Amortized (connection reused)

No data for this mode in this run.

Per-site detail: `dns_privacy_cost_by_site.csv`. Uses a single run-wide median per-resolution overhead (not a per-domain figure) - this run's own handshake/control/payload breakdown above already shows that cost is dominated by protocol/connection overhead, not by which specific domain is being resolved, so one representative figure applied per domain is more defensible than it would first appear.

## Highest overhead sites (top 9)

| Site | Category | Overhead % | PCAP bytes | CDP bytes |
| --- | --- | ---: | ---: | ---: |
| santander | Banking | 85.5% | 72.4 MB | 39.0 MB |
| bbc | News | 66.0% | 3.2 MB | 1.9 MB |
| webmd | Health | 44.3% | 2.5 MB | 1.7 MB |
| github | Technology | 41.2% | 5.5 MB | 3.9 MB |
| ietf | Standards | 37.2% | 1.3 MB | 947.1 KB |
| amazon | Ecommerce | 34.6% | 6.2 MB | 4.6 MB |
| twitter | Social Media | 26.3% | 3.3 MB | 2.6 MB |
| ine | Public Admin | 25.5% | 2.4 MB | 1.9 MB |
| youtube | Streaming | 20.7% | 4.2 MB | 3.4 MB |

## Highest carbon footprint sites (top 9)

| Site | Category | CO₂ (kg) | PCAP bytes |
| --- | --- | ---: | ---: |
| santander | Banking | 1.266774e-03 | 72.4 MB |
| amazon | Ecommerce | 1.078612e-04 | 6.2 MB |
| github | Technology | 9.668550e-05 | 5.5 MB |
| youtube | Streaming | 7.288616e-05 | 4.2 MB |
| twitter | Social Media | 5.829988e-05 | 3.3 MB |
| bbc | News | 5.532467e-05 | 3.2 MB |
| webmd | Health | 4.319486e-05 | 2.5 MB |
| ine | Public Admin | 4.133499e-05 | 2.4 MB |
| ietf | Standards | 2.221564e-05 | 1.3 MB |

Full per-site detail (including flagged sites): `web_site_summary.csv`.

## Data quality — sites excluded from category stats and plots

1 of 10 site visits (10%) were excluded from the tables and plots above, by likely cause: 0 likely bot-blocked or failed to load (CDP payload under 29.3 KB with an extreme PCAP/CDP ratio), 0 with direct evidence of capture contamination (port-scoping failed for that visit, or background noise large relative to that visit's own PCAP), and 1 statistically extreme outliers with no identified cause. See docs/apuntes_personales/ISSUES_LOG.md, Issues 5/7/10/14.

| Site | Category | Reason | Overhead % | PCAP bytes | CDP bytes |
| --- | --- | --- | ---: | ---: | ---: |
| wikipedia | Education | Statistically extreme (cause unclear) | 284.9% | 311.9 KB | 81.0 KB |

Full detail: `web_flagged_sites.csv`. Consider re-running these sites once the underlying cause (bot detection / background network noise) is addressed.

## Resource origin profile

| Origin class | Sites | Total CDP bytes | Share of CDP |
| --- | ---: | ---: | ---: |
| First party | 9 | 45.2 MB | 75.3% |
| Third party | 8 | 14.2 MB | 23.6% |
| Trackers & ads (high-confidence lower bound) | 4 | 639.9 KB | 1.0% |

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
