# Experiment analysis summary

Run directory: `results/run_20260626`

Compact preview of the final analysis phase: protocol overhead, web payload, network overhead and carbon footprint.

## DNS protocol comparison

| Protocol | Samples | Avg bytes | Avg CO₂ (kg) | Overhead vs DNS |
| --- | ---: | ---: | ---: | ---: |
| DNS | 5 | 688 (688 B) | 7.642222e-12 | 1.0× |
| DOH | 5 | 31653 (30.9 KB) | 3.517022e-10 | 46.0× |
| DOQ | 5 | 40682 (39.7 KB) | 4.520244e-10 | 59.1× |

## Web traffic by site

| Site | Category | PCAP bytes | CDP bytes | PCAP/CDP ratio |
| --- | --- | ---: | ---: | ---: |
| bbc | news | 7.4 MB | 2.4 MB | 3.10× |
| github | developer | 1.3 MB | 3.8 MB | 0.34× |
| ietf | standards | 1.3 MB | 946.2 KB | 1.40× |
| python | developer | 4.0 MB | 499.5 KB | 8.22× |
| wikipedia | knowledge | 3.5 MB | 99.8 KB | 36.16× |

## Resource origin profile

| Origin class | Samples | Avg bytes | Share of CDP bytes |
| --- | ---: | ---: | ---: |
| first_party | 5 | 329.2 KB | 55.9% |
| third_party | 3 | 2.0 MB | 68.7% |
| tracker_or_ads | 3 | 76.7 KB | 4.9% |

## Generated figures

- `fig_dns_avg_bytes.png`
- `fig_web_traffic_comparison.png`
- `fig_web_origin_bytes.png`
- `fig_dashboard.png`
