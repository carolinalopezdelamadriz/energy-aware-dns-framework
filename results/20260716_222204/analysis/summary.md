# Analysis summary

Run directory: `results/20260716_222204`

## Run configuration

- Date: 2026-07-16
- Resolver: Quad9
- Websites tested: 10
- Protocols: DNS, DOH, DOQ
- DNS mode: Cold start
- Repetitions per website: 5 (DNS), 1 (web)
- Capture: Selenium + CDP + tcpdump
- Framework version: dd4a23b
- Total runtime: 8min 33s
- Avg time per website: 51s

## Run status

✓ DNS captures completed
✓ Web captures completed
✓ TLS/QUIC keys exported
✓ Traffic decryption completed
✓ CO2 estimation completed

Warnings:
- 1 website excluded from web statistics due to capture/data-quality problems (see Data quality assessment).

## Automatic observations

- DOQ introduced the highest overhead vs classic DNS (42x median bytes).
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
| DNS | 10 | 1.0 KB | 1.1 KB | 1015 B | 1.2 KB | 77 B | 1.0× |
| DOH | 10 | 42.1 KB | 41.8 KB | 38.7 KB | 44.8 KB | 2.0 KB | 41.0× |
| DOQ | 10 | 43.0 KB | 45.5 KB | 41.4 KB | 71.0 KB | 9.0 KB | 41.8× |

### Query cost

| Protocol | Median bytes/query | Median energy/query (kWh) | Median CO₂/query (kg) |
| --- | ---: | ---: | ---: |
| DNS | 210 B | 1.241e-08 | 3.511e-09 |
| DOH | 8.4 KB | 5.082e-07 | 1.438e-07 |
| DOQ | 8.6 KB | 5.192e-07 | 1.469e-07 |

### Statistical validation

| Comparison | Site pairs | p-value | Effect size (rank-biserial r) |
| --- | ---: | ---: | ---: |
| DNS vs DOH | 10 | 1.95e-03 | -1.00 |
| DOH vs DOQ | 10 | 2.32e-01 | -0.45 |

### Traffic composition

| Protocol | Handshake | Control | Payload | Handshake share |
| --- | ---: | ---: | ---: | ---: |
| DNS | 0 B | 420 B | 669 B | 0.0% |
| DOH | 31.8 KB | 4.7 KB | 5.3 KB | 76.1% |
| DOQ | 42.5 KB | 0 B | 3.0 KB | 93.4% |

| Protocol | Avg bursts | Avg burst bytes |
| --- | ---: | ---: |
| DNS | 10.0 | 109 B |
| DOH | 65.0 | 662 B |
| DOQ | 44.2 | 1.0 KB |

DoQ's payload figure includes a small amount of connection-maintenance traffic and should be interpreted as approximate.

## Web traffic analysis

### Traffic by category

| Category | Sites | Median PCAP bytes | Median CDP bytes | Median overhead % | Median CO₂ (kg) |
| --- | ---: | ---: | ---: | ---: | ---: |
| Banking | 1 | 72.5 MB | 39.2 MB | 84.7% | 1.269528e-03 |
| Ecommerce | 1 | 6.0 MB | 4.3 MB | 39.6% | 1.053759e-04 |
| Health | 1 | 2.5 MB | 1.7 MB | 45.6% | 4.350854e-05 |
| News | 1 | 2.6 MB | 1.9 MB | 38.7% | 4.626992e-05 |
| Public Admin | 1 | 2.6 MB | 2.0 MB | 29.0% | 4.596482e-05 |
| Social Media | 1 | 3.2 MB | 2.5 MB | 30.7% | 5.665342e-05 |
| Standards | 1 | 1.3 MB | 944.4 KB | 44.0% | 2.325485e-05 |
| Streaming | 1 | 4.2 MB | 3.5 MB | 20.0% | 7.274377e-05 |
| Technology | 1 | 5.6 MB | 3.9 MB | 41.7% | 9.719916e-05 |

### DNS privacy cost relative to page size

**Cold-start (no connection reuse)**

| Category | Sites | Median domains resolved | Median DNS privacy cost (% of page) |
| --- | ---: | ---: | ---: |
| Banking | 1 | 4 | 0.044% |
| Ecommerce | 1 | 8 | 1.065% |
| Health | 1 | 13 | 4.192% |
| News | 1 | 17 | 5.155% |
| Public Admin | 1 | 4 | 1.221% |
| Social Media | 1 | 5 | 1.238% |
| Standards | 1 | 3 | 1.810% |
| Streaming | 1 | 6 | 1.157% |
| Technology | 1 | 4 | 0.577% |

**Amortized (connection reused)**

No data for this mode in this run.

### Top overhead cases

| Site | Category | Overhead % | PCAP bytes | CDP bytes |
| --- | --- | ---: | ---: | ---: |
| santander | Banking | 84.7% | 72.5 MB | 39.2 MB |
| webmd | Health | 45.6% | 2.5 MB | 1.7 MB |
| ietf | Standards | 44.0% | 1.3 MB | 944.4 KB |
| github | Technology | 41.7% | 5.6 MB | 3.9 MB |
| amazon | Ecommerce | 39.6% | 6.0 MB | 4.3 MB |
| bbc | News | 38.7% | 2.6 MB | 1.9 MB |
| twitter | Social Media | 30.7% | 3.2 MB | 2.5 MB |
| ine | Public Admin | 29.0% | 2.6 MB | 2.0 MB |
| youtube | Streaming | 20.0% | 4.2 MB | 3.5 MB |

Full per-site detail (including flagged sites): `web_site_summary.csv`.

## Carbon estimation

| Site | Category | CO₂ (kg) | PCAP bytes |
| --- | --- | ---: | ---: |
| santander | Banking | 1.269528e-03 | 72.5 MB |
| amazon | Ecommerce | 1.053759e-04 | 6.0 MB |
| github | Technology | 9.719916e-05 | 5.6 MB |
| youtube | Streaming | 7.274377e-05 | 4.2 MB |
| twitter | Social Media | 5.665342e-05 | 3.2 MB |
| bbc | News | 4.626992e-05 | 2.6 MB |
| ine | Public Admin | 4.596482e-05 | 2.6 MB |
| webmd | Health | 4.350854e-05 | 2.5 MB |
| ietf | Standards | 2.325485e-05 | 1.3 MB |

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
| wikipedia | Education | Statistically extreme (cause unclear) | 334.7% | 343.2 KB | 79.0 KB |

Full detail: `web_flagged_sites.csv`. Worth re-running these sites later.

## Resource origin analysis

| Origin class | Sites | Total CDP bytes | Share of CDP |
| --- | ---: | ---: | ---: |
| First party | 9 | 45.6 MB | 75.9% |
| Third party | 8 | 13.8 MB | 23.0% |
| Trackers & ads (high-confidence lower bound) | 4 | 645.3 KB | 1.1% |

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
