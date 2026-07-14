# Analysis summary

Run directory: `results/20260713_112236`

## Run configuration

- Date: 2026-07-13
- Resolver: Quad9
- Websites tested: 10
- Protocols: DNS, DOH, DOQ
- DNS mode: Cold start
- Repetitions per website: 5 (DNS), 1 (web)
- Capture: Selenium + CDP + tcpdump
- Framework version: not recorded for this run
- Total runtime: 6min 53s
- Avg time per website: 41s

## Run status

✓ DNS captures completed
✓ Web captures completed
✓ TLS/QUIC keys exported
✓ Traffic decryption completed
✓ CO2 estimation completed

Warnings:
- 1 website excluded from web statistics due to capture/data-quality problems (see Data quality assessment).

## Automatic observations

- DOQ introduced the highest overhead vs classic DNS (40x median bytes).
- Most DOH/DOQ traffic is connection setup (handshake), not the query itself.
- Banking generated the highest traffic per page.

## Methodological notes

- Median values are reported to reduce the impact of outliers; averages are kept for reference.
- Wilcoxon signed-rank test checks whether protocol differences are consistent across websites, not just different on average.
- CO2 estimation is based on captured bytes (see `cfp.py` for the energy/grid model).
- Excluded websites are removed only from category-level statistics, not from per-site detail files.
- DNS privacy cost applies one typical overhead value to every domain a page resolves, since the overhead comes mostly from the connection itself, not from which domain is being resolved.
- Packet bursts are consecutive packets sent in the same direction; kept for future website fingerprinting analysis, not analyzed as an attack here.

## DNS protocol comparison

### Traffic overhead

| Protocol | Samples | Median bytes | Mean bytes | Min | Max | Std dev | Overhead vs DNS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DNS | 10 | 1.0 KB | 1.1 KB | 1015 B | 1.2 KB | 71 B | 1.0× |
| DOH | 10 | 38.0 KB | 38.1 KB | 37.9 KB | 38.4 KB | 153 B | 37.0× |
| DOQ | 10 | 41.2 KB | 47.6 KB | 41.2 KB | 104.4 KB | 19.9 KB | 40.2× |

### Query cost

| Protocol | Median bytes/query | Median energy/query (kWh) | Median CO₂/query (kg) |
| --- | ---: | ---: | ---: |
| DNS | 210 B | 1.241e-08 | 3.511e-09 |
| DOH | 7.6 KB | 4.595e-07 | 1.300e-07 |
| DOQ | 8.2 KB | 4.984e-07 | 1.411e-07 |

### Statistical validation

| Comparison | Site pairs | p-value | Effect size (rank-biserial r) |
| --- | ---: | ---: | ---: |
| DNS vs DOH | 10 | 1.95e-03 | -1.00 |
| DOH vs DOQ | 10 | 1.95e-03 | -1.00 |

### Traffic composition

| Protocol | Handshake | Control | Payload | Handshake share |
| --- | ---: | ---: | ---: | ---: |
| DNS | 0 B | 420 B | 664 B | 0.0% |
| DOH | 29.2 KB | 4.0 KB | 4.8 KB | 76.8% |
| DOQ | 44.7 KB | 0 B | 2.9 KB | 93.9% |

| Protocol | Avg bursts | Avg burst bytes |
| --- | ---: | ---: |
| DNS | 10.0 | 108 B |
| DOH | 54.6 | 716 B |
| DOQ | 46.0 | 1.0 KB |

DoQ's payload figure includes a small amount of connection-maintenance traffic and should be interpreted as approximate.

## Web traffic analysis

### Traffic by category

| Category | Sites | Median PCAP bytes | Median CDP bytes | Median overhead % | Median CO₂ (kg) |
| --- | ---: | ---: | ---: | ---: | ---: |
| Banking | 1 | 72.4 MB | 39.0 MB | 85.5% | 1.266774e-03 |
| Ecommerce | 1 | 6.2 MB | 4.6 MB | 34.6% | 1.078612e-04 |
| Health | 1 | 2.5 MB | 1.7 MB | 44.3% | 4.319486e-05 |
| News | 1 | 3.2 MB | 1.9 MB | 66.0% | 5.532467e-05 |
| Public Admin | 1 | 2.4 MB | 1.9 MB | 25.5% | 4.133499e-05 |
| Social Media | 1 | 3.3 MB | 2.6 MB | 26.3% | 5.829988e-05 |
| Standards | 1 | 1.3 MB | 947.1 KB | 37.2% | 2.221564e-05 |
| Streaming | 1 | 4.2 MB | 3.4 MB | 20.7% | 7.288616e-05 |
| Technology | 1 | 5.5 MB | 3.9 MB | 41.2% | 9.668550e-05 |

### DNS privacy cost relative to page size

**Cold-start (no connection reuse)**

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

**Amortized (connection reused)**

No data for this mode in this run.

### Top overhead cases

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

Full per-site detail (including flagged sites): `web_site_summary.csv`.

## Carbon estimation

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

## Data quality assessment

| Metric | Count |
| --- | ---: |
| Total websites | 10 |
| Successful captures | 9 |
| Bot-blocked / failed to load | 0 |
| Capture contamination | 0 |
| Statistical outliers | 1 |

| Site | Category | Reason | Overhead % | PCAP bytes | CDP bytes |
| --- | --- | --- | ---: | ---: | ---: |
| wikipedia | Education | Statistically extreme (cause unclear) | 284.9% | 311.9 KB | 81.0 KB |

Full detail: `web_flagged_sites.csv`. Worth re-running these sites later.

## Resource origin analysis

| Origin class | Sites | Total CDP bytes | Share of CDP |
| --- | ---: | ---: | ---: |
| First party | 9 | 45.2 MB | 75.3% |
| Third party | 8 | 14.2 MB | 23.6% |
| Trackers & ads (high-confidence lower bound) | 4 | 639.9 KB | 1.0% |

Tracker/ads traffic is a lower bound, not an exhaustive count.

## Generated files

- `dns_protocol_summary.csv`
- `web_site_summary.csv`
- `web_category_summary.csv`
- `web_flagged_sites.csv`
- `web_origin_summary.csv`
- `web_origin_resources.csv`
- `dns_privacy_cost_by_site.csv`
- `dns_privacy_cost_by_category_cold_start.csv`
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
