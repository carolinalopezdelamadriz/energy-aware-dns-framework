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
    with open(sites_file, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for index, row in enumerate(reader, start=1):
            url = row.get("url", "").strip()
            if not url:
                raise ValueError(f"Missing url in row {index} of {sites_file}")

            domain = row.get("domain", "").strip() or _default_domain_from_url(url)
            label = row.get("label", "").strip() or domain
            category = row.get("category", "").strip() or "uncategorized"

            sites.append({
                "label": label,
                "category": category,
                "domain": domain,
                "url": url,
            })

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
    headless=False,
    fresh_profile=False,
    site_delay=5,
):
    sites = load_sites(sites_file)
    run_id = build_run_id()
    run_output_dir = ensure_output_dir(Path(output_dir) / run_id)

    config = {
        "sites_file": str(sites_file),
        "protocols": list(protocols),
        "dns_repetitions": dns_repetitions,
        "web_repetitions": web_repetitions,
        "interface": interface,
        "use_cdp": use_cdp,
        "skip_dns": skip_dns,
        "skip_web": skip_web,
        "doq_resolver": doq_resolver,
        "headless": headless,
        "fresh_profile": fresh_profile,
        "site_delay": site_delay,
    }
    write_manifest(run_output_dir, config, sites)

    print(f"\n=== BATCH EXPERIMENT: {run_id} ===")
    print(f"Sites: {len(sites)}  |  Output: {run_output_dir}")
    if headless:
        print("Headless mode enabled")

    failed_sites = []

    for site_index, site in enumerate(sites, start=1):
        print(f"\n[{site_index}/{len(sites)}] {site['label']} ({site['domain']}) — {site['category']}")

        try:
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
                    if web_repetitions > 1:
                        print(f"  Web visit {run_index}/{web_repetitions}")
                    run_web_experiment(
                        site["url"],
                        use_cdp=use_cdp,
                        output_dir=run_output_dir,
                        interface=interface,
                        site_label=site["label"],
                        category=site["category"],
                        headless=headless,
                        fresh_profile=fresh_profile,
                    )

        except Exception as exc:
            print(f"  ERROR in {site['label']}: {exc}")
            failed_sites.append({"label": site["label"], "error": str(exc)})

        # pause between sites to avoid overloading the network or the machine
        if site_index < len(sites) and site_delay > 0:
            time.sleep(site_delay)

    print(f"\nBatch completed. Results in: {run_output_dir}")

    if failed_sites:
        print(f"\nSites with errors ({len(failed_sites)}):")
        for entry in failed_sites:
            print(f"  - {entry['label']}: {entry['error']}")

    return run_output_dir
