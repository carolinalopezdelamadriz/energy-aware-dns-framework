# Analysis summary

Run directory: `results/20260725_002327`

## Run configuration

- Date: 2026-07-25
- Resolver: Quad9
- Websites tested: 100
- Protocols: DNS, DoH, DoQ
- DNS mode: both
- Repetitions per website: 5 (DNS), 3 (web)
- Capture: Selenium + CDP + tcpdump
- Framework version: 133bc87
- Total runtime: 3h 28min
- Avg time per website: 2min 5s

## Run status

✓ DNS captures completed
✓ Web captures completed
✓ TLS/QUIC keys exported
✓ Traffic decryption completed
✓ CO2 estimation completed

Warnings:
- 8 DNS queries timed out.
- 3 DNS experiment(s) excluded from the protocol comparison/tests because every repetition failed (see DNS protocol comparison > Data quality).
- 40 websites excluded from web statistics due to capture/data-quality problems (see Data quality assessment).

## Automatic observations

- DoQ introduced the highest overhead vs classic DNS (40x median bytes).
- Most DoH/DoQ traffic is connection setup (handshake), not the query itself.
- Streaming generated the highest traffic per page.

## Methodological notes

- Median values are reported to reduce the impact of outliers; averages are kept for reference.
- Wilcoxon signed-rank test checks whether protocol differences are consistent across websites, not just different on average.
- CO2 estimation is based on captured bytes (see `cfp.py` for the energy/grid model).
- Excluded websites are removed only from category-level statistics, not from per-site detail files.
- DNS privacy cost applies one typical overhead value to every domain a page resolves, since the overhead comes mostly from the connection itself, not from which domain is being resolved.
- Packet bursts are consecutive packets sent in the same direction; kept for future website fingerprinting analysis, not analyzed as an attack here.

## DNS protocol comparison

### Cold-start (no connection reuse)

#### Traffic overhead

| Protocol | Samples | Median bytes | Mean bytes | Min | Max | Std dev | Overhead vs DNS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DNS | 100 | 1.1 KB | 1.1 KB | 818 B | 1.6 KB | 99 B | 1.0× |
| DoH | 100 | 42.3 KB | 43.0 KB | 38.7 KB | 65.2 KB | 3.8 KB | 39.3× |
| DoQ | 99 | 43.2 KB | 45.3 KB | 42.8 KB | 53.7 KB | 3.0 KB | 40.1× |

#### Query cost

| Protocol | Median bytes/query | Median energy/query (kWh) | Median CO₂/query (kg) |
| --- | ---: | ---: | ---: |
| DNS | 220 B | 1.300e-08 | 3.680e-09 |
| DoH | 8.5 KB | 5.110e-07 | 1.446e-07 |
| DoQ | 8.6 KB | 5.215e-07 | 1.476e-07 |

#### Statistical validation

| Comparison | Site pairs | p-value | Effect size (rank-biserial r) |
| --- | ---: | ---: | ---: |
| DNS vs DoH | 100 | 3.90e-18 | -1.00 |
| DoH vs DoQ | 99 | 1.53e-07 | -0.61 |

#### Traffic composition

| Protocol | Handshake | Control | Payload | Handshake share |
| --- | ---: | ---: | ---: | ---: |
| DNS | 0 B | 422 B | 684 B | 0.0% |
| DoH | 33.5 KB | 4.4 KB | 5.1 KB | 77.9% |
| DoQ | 42.4 KB | 0 B | 2.9 KB | 93.5% |

| Protocol | Avg bursts | Avg burst bytes |
| --- | ---: | ---: |
| DNS | 9.9 | 122 B |
| DoH | 57.1 | 774 B |
| DoQ | 40.8 | 1.1 KB |

DoQ's payload figure includes a small amount of connection-maintenance traffic and should be interpreted as approximate.

### Amortized (connection reused)

#### Traffic overhead

| Protocol | Samples | Median bytes | Mean bytes | Min | Max | Std dev | Overhead vs DNS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DNS | 100 | 1.1 KB | 1.1 KB | 820 B | 1.6 KB | 99 B | 1.0× |
| DoH | 100 | 9.8 KB | 11.0 KB | 9.4 KB | 19.1 KB | 1.8 KB | 9.1× |
| DoQ | 98 | 10.1 KB | 10.7 KB | 9.9 KB | 15.4 KB | 1.7 KB | 9.4× |

#### Query cost

| Protocol | Median bytes/query | Median energy/query (kWh) | Median CO₂/query (kg) |
| --- | ---: | ---: | ---: |
| DNS | 220 B | 1.300e-08 | 3.678e-09 |
| DoH | 2.0 KB | 1.189e-07 | 3.366e-08 |
| DoQ | 2.0 KB | 1.219e-07 | 3.450e-08 |

#### Statistical validation

| Comparison | Site pairs | p-value | Effect size (rank-biserial r) |
| --- | ---: | ---: | ---: |
| DNS vs DoH | 100 | 3.89e-18 | -1.00 |
| DoH vs DoQ | 98 | 1.95e-01 | 0.15 |

#### Traffic composition

| Protocol | Handshake | Control | Payload | Handshake share |
| --- | ---: | ---: | ---: | ---: |
| DNS | 0 B | 422 B | 685 B | 0.0% |
| DoH | 7.2 KB | 1.3 KB | 2.5 KB | 65.7% |
| DoQ | 8.6 KB | 0 B | 2.1 KB | 80.7% |

| Protocol | Avg bursts | Avg burst bytes |
| --- | ---: | ---: |
| DNS | 9.9 | 122 B |
| DoH | 21.0 | 536 B |
| DoQ | 17.1 | 639 B |

DoQ's payload figure includes a small amount of connection-maintenance traffic and should be interpreted as approximate.

### Data quality

3 experiment(s) had every repetition fail and are excluded from the table/tests above - the bytes still shown come from failed connection attempts, not a successful resolution.

| Site | Protocol | Failed / Repetitions | Bytes (excluded) |
| --- | --- | ---: | ---: |
| aliexpress | DoQ | 1/5 | 10.4 KB |
| medlineplus | DoQ | 5/5 | 97.3 KB |
| medlineplus | DoQ | 2/5 | 9.9 KB |

Full detail: `dns_flagged_experiments.csv` (rows stay in `dns_results.csv` too).

## Web traffic analysis

### Traffic by category

| Category | Sites | Median PCAP bytes | Median CDP bytes | Median overhead % | Median CO₂ (kg) |
| --- | ---: | ---: | ---: | ---: | ---: |
| Banking | 27 | 3.1 MB | 2.0 MB | 37.3% | 5.409609e-05 |
| Ecommerce | 24 | 4.4 MB | 3.2 MB | 34.2% | 7.642120e-05 |
| Education | 24 | 3.9 MB | 3.3 MB | 26.6% | 6.871100e-05 |
| Health | 24 | 3.8 MB | 2.1 MB | 34.1% | 6.681869e-05 |
| News | 24 | 5.7 MB | 4.2 MB | 41.4% | 1.002502e-04 |
| Public Admin | 30 | 2.2 MB | 1.6 MB | 33.3% | 3.788897e-05 |
| Social Media | 30 | 3.6 MB | 3.1 MB | 34.4% | 6.231372e-05 |
| Standards | 24 | 2.1 MB | 1.3 MB | 27.0% | 3.603673e-05 |
| Streaming | 26 | 6.8 MB | 4.3 MB | 30.1% | 1.195896e-04 |
| Technology | 27 | 3.0 MB | 2.1 MB | 41.0% | 5.263273e-05 |

### DNS privacy cost relative to page size

**Cold-start (no connection reuse)**

| Category | Sites | Median domains resolved | Median DNS privacy cost (% of page) |
| --- | ---: | ---: | ---: |
| Banking | 27 | 5 | 1.791% |
| Ecommerce | 24 | 8 | 1.285% |
| Education | 24 | 6 | 1.472% |
| Health | 24 | 10 | 2.513% |
| News | 24 | 30 | 4.994% |
| Public Admin | 30 | 4 | 1.446% |
| Social Media | 30 | 6 | 0.963% |
| Standards | 24 | 3 | 1.718% |
| Streaming | 26 | 11 | 1.706% |
| Technology | 27 | 12 | 5.046% |

**Amortized (connection reused)**

| Category | Sites | Median domains resolved | Median DNS privacy cost (% of page) |
| --- | ---: | ---: | ---: |
| Banking | 27 | 5 | 0.381% |
| Ecommerce | 24 | 8 | 0.273% |
| Education | 24 | 6 | 0.313% |
| Health | 24 | 10 | 0.535% |
| News | 24 | 30 | 1.062% |
| Public Admin | 30 | 4 | 0.308% |
| Social Media | 30 | 6 | 0.205% |
| Standards | 24 | 3 | 0.365% |
| Streaming | 26 | 11 | 0.363% |
| Technology | 27 | 12 | 1.073% |

### Top overhead cases

| Site | Category | Overhead % | PCAP bytes | CDP bytes |
| --- | --- | ---: | ---: | ---: |
| twitch | Streaming | 184.9% | 8.4 MB | 2.9 MB |
| linkedin | Social Media | 171.7% | 1.7 MB | 650.9 KB |
| amazon_es | Ecommerce | 169.4% | 7.9 MB | 5.9 MB |
| twitch | Streaming | 168.2% | 7.7 MB | 2.9 MB |
| gov_uk | Public Admin | 168.1% | 508.1 KB | 189.5 KB |
| amazon_es | Ecommerce | 167.5% | 7.7 MB | 5.8 MB |
| gov_uk | Public Admin | 158.6% | 490.1 KB | 189.5 KB |
| amazon_es | Ecommerce | 158.0% | 7.5 MB | 6.0 MB |
| gov_uk | Public Admin | 155.8% | 484.8 KB | 189.5 KB |
| clevelandclinic | Health | 154.2% | 4.6 MB | 1.8 MB |

Full per-site detail (including flagged sites): `web_site_summary.csv`.

## Carbon estimation

| Site | Category | CO₂ (kg) | PCAP bytes |
| --- | --- | ---: | ---: |
| santander | Banking | 1.015486e-03 | 58.0 MB |
| santander | Banking | 1.010094e-03 | 57.7 MB |
| santander | Banking | 1.002796e-03 | 57.3 MB |
| tiktok | Social Media | 3.879877e-04 | 22.2 MB |
| discord | Social Media | 3.513656e-04 | 20.1 MB |
| tiktok | Social Media | 3.511341e-04 | 20.1 MB |
| discord | Social Media | 3.510555e-04 | 20.1 MB |
| discord | Social Media | 3.507725e-04 | 20.0 MB |
| tiktok | Social Media | 3.079219e-04 | 17.6 MB |
| cnn | News | 2.720236e-04 | 15.5 MB |

## Data quality assessment

| Metric | Count |
| --- | ---: |
| Total websites | 300 |
| Successful captures | 260 |
| Bot-blocked / failed to load | 15 |
| Capture contamination | 0 |
| Statistical outliers | 25 |

| Site | Category | Reason | Overhead % | PCAP bytes | CDP bytes |
| --- | --- | --- | ---: | ---: | ---: |
| reuters | News | Likely bot-blocked / failed load | 8441.9% | 633.1 KB | 7.4 KB |
| reuters | News | Likely bot-blocked / failed load | 1829.7% | 334.7 KB | 17.3 KB |
| reuters | News | Likely bot-blocked / failed load | 2128.4% | 386.5 KB | 17.3 KB |
| elpais | News | Likely bot-blocked / failed load | 10894.2% | 705.1 KB | 6.4 KB |
| elpais | News | Likely bot-blocked / failed load | 2710.8% | 459.2 KB | 16.3 KB |
| elpais | News | Likely bot-blocked / failed load | 1995.4% | 342.4 KB | 16.3 KB |
| etsy | Ecommerce | Likely bot-blocked / failed load | 8011.4% | 524.1 KB | 6.5 KB |
| etsy | Ecommerce | Likely bot-blocked / failed load | 1629.5% | 283.1 KB | 16.4 KB |
| etsy | Ecommerce | Likely bot-blocked / failed load | 1735.9% | 300.5 KB | 16.4 KB |
| hackernews | Technology | Likely bot-blocked / failed load | 2788.3% | 331.2 KB | 11.5 KB |
| hackernews | Technology | Likely bot-blocked / failed load | 2541.3% | 302.8 KB | 11.5 KB |
| hackernews | Technology | Likely bot-blocked / failed load | 2864.8% | 339.9 KB | 11.5 KB |
| imdb | Streaming | Likely bot-blocked / failed load | 11202.0% | 252.2 KB | 2.2 KB |
| imdb | Streaming | Likely bot-blocked / failed load | 15469.6% | 283.4 KB | 1.8 KB |
| imdb | Streaming | Likely bot-blocked / failed load | 13466.3% | 302.7 KB | 2.2 KB |
| bankinter | Banking | Statistically extreme (cause unclear) | 658.8% | 1.0 MB | 140.4 KB |
| bankinter | Banking | Statistically extreme (cause unclear) | 698.4% | 1.1 MB | 135.7 KB |
| bankinter | Banking | Statistically extreme (cause unclear) | 635.8% | 1.0 MB | 141.4 KB |
| wikipedia | Education | Statistically extreme (cause unclear) | 260.4% | 285.2 KB | 79.1 KB |
| wikipedia | Education | Statistically extreme (cause unclear) | 340.1% | 348.2 KB | 79.1 KB |
| wikipedia | Education | Statistically extreme (cause unclear) | 244.8% | 272.8 KB | 79.1 KB |
| stanford | Education | Statistically extreme (cause unclear) | 461.7% | 10.2 MB | 2.8 MB |
| stanford | Education | Statistically extreme (cause unclear) | 366.3% | 8.4 MB | 2.9 MB |
| stanford | Education | Statistically extreme (cause unclear) | 507.6% | 11.0 MB | 2.5 MB |
| pccomponentes | Ecommerce | Statistically extreme (cause unclear) | 732.1% | 1.0 MB | 125.9 KB |
| pccomponentes | Ecommerce | Statistically extreme (cause unclear) | 750.0% | 1.0 MB | 123.8 KB |
| pccomponentes | Ecommerce | Statistically extreme (cause unclear) | 648.0% | 934.6 KB | 124.9 KB |
| twitch | Streaming | Statistically extreme (cause unclear) | 187.4% | 8.5 MB | 2.9 MB |
| nih | Health | Statistically extreme (cause unclear) | 676.5% | 1.1 MB | 140.1 KB |
| nih | Health | Statistically extreme (cause unclear) | 681.3% | 1.1 MB | 141.4 KB |
| nih | Health | Statistically extreme (cause unclear) | 692.3% | 1.1 MB | 141.2 KB |
| medscape | Health | Statistically extreme (cause unclear) | 635.8% | 1.0 MB | 142.9 KB |
| medscape | Health | Statistically extreme (cause unclear) | 649.8% | 1.0 MB | 141.1 KB |
| medscape | Health | Statistically extreme (cause unclear) | 659.4% | 1.0 MB | 141.5 KB |
| iso | Standards | Statistically extreme (cause unclear) | 670.0% | 1.1 MB | 141.7 KB |
| iso | Standards | Statistically extreme (cause unclear) | 620.2% | 1.0 MB | 142.5 KB |
| iso | Standards | Statistically extreme (cause unclear) | 625.6% | 1.0 MB | 143.1 KB |
| icann | Standards | Statistically extreme (cause unclear) | 679.8% | 292.5 KB | 37.5 KB |
| icann | Standards | Statistically extreme (cause unclear) | 637.1% | 277.3 KB | 37.6 KB |
| icann | Standards | Statistically extreme (cause unclear) | 797.8% | 339.5 KB | 37.8 KB |

Full detail: `web_flagged_sites.csv`. Worth re-running these sites later.

## Resource origin analysis

| Origin class | Sites | Total CDP bytes | Share of CDP |
| --- | ---: | ---: | ---: |
| First party | 86 | 550.5 MB | 53.9% |
| Third party | 75 | 411.3 MB | 40.3% |
| Trackers & ads (high-confidence lower bound) | 54 | 58.8 MB | 5.8% |

Tracker/ads traffic is a lower bound, not an exhaustive count.

## Resource type analysis

| Resource type | Sites | Total CDP bytes | Share of CDP |
| --- | ---: | ---: | ---: |
| Image | 85 | 365.0 MB | 35.8% |
| Script | 86 | 331.4 MB | 32.5% |
| Media | 13 | 162.3 MB | 15.9% |
| Font | 81 | 57.2 MB | 5.6% |
| Stylesheet | 85 | 29.8 MB | 2.9% |
| Fetch | 61 | 29.2 MB | 2.9% |
| Document | 87 | 19.9 MB | 1.9% |
| XHR | 69 | 17.3 MB | 1.7% |
| Other | 87 | 8.0 MB | 0.8% |
| Ping | 29 | 198.9 KB | 0.0% |
| Manifest | 22 | 145.1 KB | 0.0% |
| Preflight | 34 | 0 B | 0.0% |

Which kind of content drives page weight, complementing who served it (origin, above).

## Generated files

- `dns_protocol_summary.csv`
- `dns_flagged_experiments.csv`
- `web_site_summary.csv`
- `web_category_summary.csv`
- `web_flagged_sites.csv`
- `web_origin_summary.csv`
- `web_origin_resources.csv`
- `web_resource_type_summary.csv`
- `web_resource_type_resources.csv`
- `dns_privacy_cost_by_site.csv`
- `dns_privacy_cost_by_category_cold_start.csv`
- `dns_privacy_cost_by_category_amortized.csv`
- `dns_protocol_summary_amortized.csv`
- `fig_dns_bytes_by_protocol.png`
- `fig_dns_co2_by_protocol.png`
- `fig_overhead_breakdown.png`
- `fig_connection_reuse_comparison.png`
- `fig_burst_patterns.png`
- `fig_web_overhead_scatter.png`
- `fig_web_bytes_by_category.png`
- `fig_web_overhead_by_category.png`
- `fig_web_origin_bytes.png`
- `fig_web_resource_types.png`
- `fig_cfp_by_category.png`
