import csv
import platform
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

from results import ensure_output_dir, write_json


def _default_domain_from_url(url):
    parsed = urlparse(url)
    return parsed.netloc.replace("www.", "", 1)


def load_sites(sites_file):
    sites = []
    with open(sites_file, newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        for index, row in enumerate(reader, start=1):
            url = row.get("url", "").strip()
            if not url:
                raise ValueError(f"Missing url in row {index} of {sites_file}")

            domain = row.get("domain", "").strip() or _default_domain_from_url(url)
            label = row.get("label", "").strip() or domain
            category = row.get("category", "").strip() or "uncategorized"

            sites.append(
                {
                    "label": label,
                    "category": category,
                    "domain": domain,
                    "url": url,
                }
            )

    if not sites:
        raise ValueError(f"No sites found in {sites_file}")

    return sites


def build_run_id():
    return time.strftime("%Y%m%d_%H%M%S")


def write_manifest(output_dir, config, sites):
    manifest = {
        "run_id": Path(output_dir).name,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "python": sys.version,
        "platform": platform.platform(),
        "config": config,
        "sites": sites,
    }
    write_json(Path(output_dir) / "manifest.json", manifest)


def run_batch_experiment(
    sites_file,
    protocols,
    dns_repetitions,
    web_repetitions,
    output_dir,
    interface=None,
    use_cdp=True,
    skip_dns=False,
    skip_web=False,
    doq_resolver="quad9",
):
    sites = load_sites(sites_file)
    run_id = build_run_id()
    run_output_dir = ensure_output_dir(Path(output_dir) / run_id)

    config = {
        "sites_file": str(sites_file),
        "protocols": protocols,
        "dns_repetitions": dns_repetitions,
        "web_repetitions": web_repetitions,
        "interface": interface,
        "use_cdp": use_cdp,
        "skip_dns": skip_dns,
        "skip_web": skip_web,
        "doq_resolver": doq_resolver,
    }
    write_manifest(run_output_dir, config, sites)

    print(f"\n=== BATCH EXPERIMENT: {run_id} ===")
    print(f"Sites: {len(sites)}")
    print(f"Output: {run_output_dir}")

    for site_index, site in enumerate(sites, start=1):
        print(
            f"\n--- Site {site_index}/{len(sites)}: "
            f"{site['label']} ({site['domain']}) ---"
        )

        if not skip_dns:
            from dns_experiment import run_dns_experiment

            for protocol in protocols:
                run_dns_experiment(
                    site["domain"],
                    protocol,
                    repetitions=dns_repetitions,
                    output_dir=run_output_dir,
                    interface=interface,
                    site_label=site["label"],
                    category=site["category"],
                    doq_resolver=doq_resolver,
                )

        if not skip_web:
            from web_experiment import run_web_experiment

            for run_index in range(1, web_repetitions + 1):
                print(f"\nWeb repetition {run_index}/{web_repetitions}")
                run_web_experiment(
                    site["url"],
                    use_cdp=use_cdp,
                    output_dir=run_output_dir,
                    interface=interface,
                    site_label=site["label"],
                    category=site["category"],
                )

    print(f"\nBatch finished. Results written to: {run_output_dir}")
    return run_output_dir
