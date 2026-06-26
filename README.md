# Energy-Aware DNS Framework

Framework for measuring the network overhead and Digital Carbon Footprint (CFP) of web navigation and encrypted DNS protocols.

TFG title: **Framework-Based Energy-Aware Analysis of encrypted DNS: The Carbon Cost of Privacy**

## Objectives

- Measure protocol overhead for classic DNS, DNS over HTTPS (DoH) and DNS over QUIC (DoQ).
- Capture full web browsing traffic using `tcpdump`.
- Profile web resources using Selenium and Chrome DevTools Protocol (CDP).
- Convert traffic volume into energy consumption and CO2e emissions.
- Persist reproducible experiment outputs for later analysis and thesis figures.

## Requirements

- Python 3.9+
- Chrome and ChromeDriver compatible with Selenium
- `tcpdump`
- `kdig` with QUIC support for DoQ experiments
- Python dependencies from `requirements.txt`

```bash
pip install -r requirements.txt
```

DoQ requires `aioquic`. Verify the Python environment before running experiments:

```bash
python3 src/main.py --mode check --interface en0
```

To test which DoQ resolvers work from the current network:

```bash
python3 src/main.py --mode check --interface en0 --check-doq --doq-resolver quad9
```

`tcpdump` may require administrator permissions depending on the operating system.

## Usage

Run the full experiment:

```bash
python src/main.py
```

Run only DNS protocol comparison:

```bash
python src/main.py --mode dns --domain bbc.com --repetitions 5
```

On macOS, select the active interface explicitly. For Wi-Fi this is usually `en0`:

```bash
python src/main.py --mode dns --protocols dns doh --domain bbc.com --repetitions 5 --interface en0
```

If `tcpdump` reports permission errors, run the experiment with elevated permissions:

```bash
sudo -E python src/main.py --mode dns --protocols dns doh --domain bbc.com --repetitions 5 --interface en0
```

Run only web traffic profiling:

```bash
python src/main.py --mode web --url https://www.bbc.com
```

Select DNS protocols:

```bash
python src/main.py --mode dns --protocols dns doh
```

## Repository layout

```text
energy-aware-dns-framework/
├── src/                         # Framework source code
├── data/
│   └── sites_sample.csv         # 5-site sample list
├── results/
│   ├── run_20260626/            # Reference sample run (tracked in git)
│   └── archive/                 # Local-only runs (not committed)
├── README.md
└── requirements.txt
```

New batch experiments create timestamped folders under `results/`. PCAP files are
ignored by git (large); CSV, JSON profiles and analysis figures from the sample run
are kept for reproducibility.

## Batch experiment (sample run)

A validated 5-site sample run is available at `results/run_20260626/`. To reproduce
or extend it, use batch mode with the sample site list:

Check the local environment first:

```bash
python3 src/main.py --mode check --interface en0
```

```bash
sudo -E python3 src/main.py \
  --mode batch \
  --sites-file data/sites_sample.csv \
  --protocols dns doh doq \
  --repetitions 5 \
  --web-repetitions 1 \
  --interface en0 \
  --doq-resolver quad9
```

This creates a timestamped folder under `results/`, for example:

```text
results/20260626_103000/
  manifest.json
  dns_results.csv
  web_results.csv
  web_profile_<timestamp>.json
  dns_<protocol>_<timestamp>.pcap
  web_<timestamp>.pcap
```

Then generate the analysis layer:

```bash
python3 src/main.py --mode analyze --run-dir results/20260626_103000
```

The analysis step creates:

```text
results/<run_id>/analysis/
  summary.md
  dns_protocol_summary.csv
  web_category_summary.csv
  web_origin_summary.csv
  web_origin_resources.csv
  fig_dns_avg_bytes.png
  fig_web_traffic_comparison.png
  fig_web_origin_bytes.png
  fig_dashboard.png
```

Regenerate figures for the reference sample run:

```bash
python3 src/main.py --mode analyze --run-dir results/run_20260626
```

This compares protocol bytes and CFP, CDP payload against PCAP traffic, and gives
an initial breakdown of web resources by origin class.

Use `--skip-web` to validate only DNS protocol captures, or `--skip-dns` to validate
only Selenium/CDP web captures.

DoQ support depends on local network access to UDP/853 and resolver support. The
framework uses one fixed DoQ resolver per run, `quad9` by default, because trying
several resolvers inside the same capture pollutes the PCAP with failed handshakes
and retransmissions. Use `--check-doq` first and then pass the resolver that works
with `--doq-resolver`.

## CFP model

The current CFP model is intentionally simple and configurable:

```text
E[J] = bytes * energy_per_byte_j
E[kWh] = E[J] / 3.6e6
CO2[kgCO2e] = E[kWh] * co2_per_kwh
```

## Author
Carolina López De La Madriz | Double Degree in Data Science and Engineering and Telecommunication Technologies Engineering
