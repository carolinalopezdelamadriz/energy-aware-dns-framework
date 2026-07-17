# Analysis summary

Run directory: `results/20260717_004628`

## Run configuration

- Date: 2026-07-17
- Resolver: Quad9
- Websites tested: 100
- Protocols: DNS, DOH, DOQ
- DNS mode: Cold start
- Repetitions per website: 5 (DNS), 1 (web)
- Capture: Selenium + CDP + tcpdump
- Framework version: 76c1f7a
- Total runtime: 1h 24min
- Avg time per website: 50s

## Run status

✓ DNS captures completed
✓ Web captures completed
✓ TLS/QUIC keys exported
✓ Traffic decryption completed
✓ CO2 estimation completed

Warnings:
- 5 DNS queries timed out.
- 13 websites excluded from web statistics due to capture/data-quality problems (see Data quality assessment).

## Automatic observations

- DOH introduced the highest overhead vs classic DNS (38x median bytes).
- Most DOH/DOQ traffic is connection setup (handshake), not the query itself.
- Streaming generated the highest traffic per page.

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
| DNS | 100 | 1.1 KB | 1.1 KB | 818 B | 1.9 KB | 118 B | 1.0× |
| DOH | 100 | 41.6 KB | 42.1 KB | 37.8 KB | 60.1 KB | 3.7 KB | 38.4× |
| DOQ | 100 | 41.4 KB | 46.0 KB | 41.0 KB | 93.9 KB | 13.1 KB | 38.2× |

### Query cost

| Protocol | Median bytes/query | Median energy/query (kWh) | Median CO₂/query (kg) |
| --- | ---: | ---: | ---: |
| DNS | 222 B | 1.308e-08 | 3.702e-09 |
| DOH | 8.3 KB | 5.029e-07 | 1.423e-07 |
| DOQ | 8.3 KB | 5.002e-07 | 1.415e-07 |

### Statistical validation

| Comparison | Site pairs | p-value | Effect size (rank-biserial r) |
| --- | ---: | ---: | ---: |
| DNS vs DOH | 100 | 3.90e-18 | -1.00 |
| DOH vs DOQ | 100 | 8.50e-02 | -0.20 |

### Traffic composition

| Protocol | Handshake | Control | Payload | Handshake share |
| --- | ---: | ---: | ---: | ---: |
| DNS | 0 B | 424 B | 687 B | 0.0% |
| DOH | 32.5 KB | 4.5 KB | 5.1 KB | 77.2% |
| DOQ | 43.0 KB | 0 B | 3.0 KB | 93.5% |

| Protocol | Avg bursts | Avg burst bytes |
| --- | ---: | ---: |
| DNS | 9.9 | 122 B |
| DOH | 60.2 | 722 B |
| DOQ | 43.5 | 1.1 KB |

DoQ's payload figure includes a small amount of connection-maintenance traffic and should be interpreted as approximate.

## Web traffic analysis

### Traffic by category

| Category | Sites | Median PCAP bytes | Median CDP bytes | Median overhead % | Median CO₂ (kg) |
| --- | ---: | ---: | ---: | ---: | ---: |
| Banking | 9 | 3.2 MB | 2.0 MB | 38.1% | 5.544678e-05 |
| Ecommerce | 8 | 4.4 MB | 3.1 MB | 35.6% | 7.703196e-05 |
| Education | 8 | 3.5 MB | 2.9 MB | 24.9% | 6.212512e-05 |
| Health | 8 | 3.8 MB | 2.1 MB | 31.6% | 6.579994e-05 |
| News | 8 | 6.3 MB | 2.8 MB | 47.1% | 1.110783e-04 |
| Public Admin | 10 | 2.1 MB | 1.6 MB | 33.1% | 3.730763e-05 |
| Social Media | 10 | 3.1 MB | 2.4 MB | 32.2% | 5.349880e-05 |
| Standards | 8 | 2.3 MB | 1.5 MB | 35.4% | 3.989986e-05 |
| Streaming | 9 | 6.9 MB | 4.2 MB | 32.5% | 1.214928e-04 |
| Technology | 9 | 2.5 MB | 1.9 MB | 37.6% | 4.458987e-05 |

### DNS privacy cost relative to page size

**Cold-start (no connection reuse)**

| Category | Sites | Median domains resolved | Median DNS privacy cost (% of page) |
| --- | ---: | ---: | ---: |
| Banking | 9 | 5 | 1.768% |
| Ecommerce | 8 | 8 | 1.486% |
| Education | 8 | 6 | 1.506% |
| Health | 8 | 10 | 2.527% |
| News | 8 | 32 | 4.957% |
| Public Admin | 10 | 4 | 1.464% |
| Social Media | 10 | 6 | 0.990% |
| Standards | 8 | 3 | 1.696% |
| Streaming | 9 | 11 | 1.449% |
| Technology | 9 | 12 | 3.730% |

**Amortized (connection reused)**

No data for this mode in this run.

### Top overhead cases

| Site | Category | Overhead % | PCAP bytes | CDP bytes |
| --- | --- | ---: | ---: | ---: |
| lavanguardia | News | 188.6% | 9.2 MB | 3.2 MB |
| twitch | Streaming | 181.3% | 8.1 MB | 2.9 MB |
| amazon | Ecommerce | 167.2% | 7.7 MB | 5.1 MB |
| gov_uk | Public Admin | 153.9% | 485.5 KB | 191.2 KB |
| clevelandclinic | Health | 153.8% | 4.6 MB | 1.8 MB |
| linkedin | Social Media | 119.1% | 1.4 MB | 649.8 KB |
| uc3m | Education | 116.8% | 12.0 MB | 5.5 MB |
| paypal | Banking | 109.4% | 2.2 MB | 1.1 MB |
| disneyplus | Streaming | 107.4% | 5.7 MB | 2.7 MB |
| reddit | Social Media | 101.3% | 397.1 KB | 197.3 KB |

Full per-site detail (including flagged sites): `web_site_summary.csv`.

## Carbon estimation

| Site | Category | CO₂ (kg) | PCAP bytes |
| --- | --- | ---: | ---: |
| santander | Banking | 1.280528e-03 | 73.1 MB |
| cnn | News | 4.372236e-04 | 25.0 MB |
| stackoverflow | Technology | 4.340400e-04 | 24.8 MB |
| discord | Social Media | 3.509411e-04 | 20.0 MB |
| tiktok | Social Media | 3.118528e-04 | 17.8 MB |
| rtve | Streaming | 2.678812e-04 | 15.3 MB |
| sanidad | Health | 2.178798e-04 | 12.4 MB |
| uc3m | Education | 2.095216e-04 | 12.0 MB |
| wired | Technology | 1.982953e-04 | 11.3 MB |
| apnews | News | 1.844884e-04 | 10.5 MB |

## Data quality assessment

| Metric | Count |
| --- | ---: |
| Total websites | 100 |
| Successful captures | 87 |
| Bot-blocked / failed to load | 5 |
| Capture contamination | 0 |
| Statistical outliers | 8 |

| Site | Category | Reason | Overhead % | PCAP bytes | CDP bytes |
| --- | --- | --- | ---: | ---: | ---: |
| reuters | News | Likely bot-blocked / failed load | 2841.4% | 534.0 KB | 18.2 KB |
| elpais | News | Likely bot-blocked / failed load | 3744.6% | 655.4 KB | 17.0 KB |
| etsy | Ecommerce | Likely bot-blocked / failed load | 3472.3% | 614.3 KB | 17.2 KB |
| hackernews | Technology | Likely bot-blocked / failed load | 2793.7% | 323.6 KB | 11.2 KB |
| imdb | Streaming | Likely bot-blocked / failed load | 13277.1% | 242.7 KB | 1.8 KB |
| bankinter | Banking | Statistically extreme (cause unclear) | 644.8% | 1.1 MB | 144.9 KB |
| wikipedia | Education | Statistically extreme (cause unclear) | 263.3% | 286.3 KB | 78.8 KB |
| stanford | Education | Statistically extreme (cause unclear) | 353.0% | 7.5 MB | 1.7 MB |
| pccomponentes | Ecommerce | Statistically extreme (cause unclear) | 683.2% | 1.0 MB | 131.7 KB |
| nih | Health | Statistically extreme (cause unclear) | 636.0% | 1.1 MB | 150.5 KB |
| medscape | Health | Statistically extreme (cause unclear) | 599.8% | 1.0 MB | 151.8 KB |
| iso | Standards | Statistically extreme (cause unclear) | 592.3% | 1.0 MB | 151.2 KB |
| icann | Standards | Statistically extreme (cause unclear) | 804.3% | 341.3 KB | 37.7 KB |

Full detail: `web_flagged_sites.csv`. Worth re-running these sites later.

## Resource origin analysis

| Origin class | Sites | Total CDP bytes | Share of CDP |
| --- | ---: | ---: | ---: |
| First party | 84 | 208.8 MB | 58.2% |
| Third party | 73 | 130.8 MB | 36.4% |
| Trackers & ads (high-confidence lower bound) | 54 | 19.5 MB | 5.4% |

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
