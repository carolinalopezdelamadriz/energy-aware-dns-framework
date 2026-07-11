import argparse


def parse_args():
    parser = argparse.ArgumentParser(
        description="Runner for the framework's DNS and web experiments"
    )
    parser.add_argument(
        "--mode",
        choices=("all", "dns", "web", "batch", "analyze", "check"),
        default="all",
        help="Type of experiment to run",
    )
    parser.add_argument("--domain", default="bbc.com", help="Domain for the DNS tests")
    parser.add_argument(
        "--url",
        default="https://www.bbc.com",
        help="URL for the web browsing test",
    )
    parser.add_argument(
        "--protocols",
        nargs="+",
        choices=("dns", "doh", "doq"),
        default=("dns", "doh", "doq"),
        help="DNS protocols to compare",
    )
    parser.add_argument(
        "--doq-resolver",
        choices=("quad9", "cloudflare", "google"),
        default="quad9",
        help="DoQ resolver. Fixed to one to avoid contaminating the PCAPs with failed handshakes.",
    )
    parser.add_argument(
        "--repetitions",
        type=int,
        default=5,
        help="Number of DNS queries per protocol",
    )
    parser.add_argument(
        "--output-dir",
        default="results",
        help="Directory where PCAP, CSV and JSON profiles are saved",
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="Network interface for tcpdump",
    )
    parser.add_argument(
        "--no-cdp",
        action="store_true",
        help="Disable resource profiling via Selenium/CDP",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Open Chrome in headless mode (for the batch experiment)",
    )
    parser.add_argument(
        "--fresh-profile",
        action="store_true",
        help="Use a temporary Chrome profile per visit (avoids cache and service worker contamination)",
    )
    parser.add_argument(
        "--sites-file",
        default="data/sites_sample.csv",
        help="CSV with columns label, category, domain, url for batch mode",
    )
    parser.add_argument(
        "--run-dir",
        default=None,
        help="Results folder to analyze (analyze mode)",
    )
    parser.add_argument(
        "--web-repetitions",
        type=int,
        default=1,
        help="Number of web visits per site in batch mode",
    )
    parser.add_argument(
        "--skip-dns",
        action="store_true",
        help="Skip DNS experiments in batch mode",
    )
    parser.add_argument(
        "--skip-web",
        action="store_true",
        help="Skip web experiments in batch mode",
    )
    parser.add_argument(
        "--site-delay",
        type=int,
        default=5,
        help="Seconds to pause between sites in batch mode (default: 5)",
    )
    parser.add_argument(
        "--check-doq",
        action="store_true",
        help="In check mode, verify DoQ connectivity with the chosen resolver",
    )
    parser.add_argument(
        "--connection-mode",
        choices=("cold_start", "amortized", "both"),
        default="cold_start",
        help=(
            "cold_start: fresh connection per DNS query (worst case, no reuse). "
            "amortized: one connection reused for all repetitions in a protocol "
            "(handshake cost paid once). both: run each protocol once in each mode."
        ),
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if args.mode == "check":
        from env_check import run_environment_check

        run_environment_check(
            interface=args.interface,
            check_doq=args.check_doq,
            doq_resolver=args.doq_resolver,
        )
        return

    if args.mode == "batch":
        from batch_experiment import run_batch_experiment

        run_batch_experiment(
            sites_file=args.sites_file,
            protocols=args.protocols,
            dns_repetitions=args.repetitions,
            web_repetitions=args.web_repetitions,
            output_dir=args.output_dir,
            interface=args.interface,
            use_cdp=not args.no_cdp,
            skip_dns=args.skip_dns,
            skip_web=args.skip_web,
            doq_resolver=args.doq_resolver,
            headless=args.headless,
            fresh_profile=args.fresh_profile,
            site_delay=args.site_delay,
            connection_mode=args.connection_mode,
        )
        return

    if args.mode == "analyze":
        from run_analysis import analyze_run

        analyze_run(args.run_dir or args.output_dir)
        return

    if args.mode in ("all", "dns"):
        from dns_experiment import CONNECTION_MODES, run_dns_experiment

        print("\n=== DNS EXPERIMENTS ===")
        for proto in args.protocols:
            for reuse_connection in CONNECTION_MODES[args.connection_mode]:
                run_dns_experiment(
                    args.domain,
                    proto,
                    repetitions=args.repetitions,
                    output_dir=args.output_dir,
                    interface=args.interface,
                    doq_resolver=args.doq_resolver,
                    reuse_connection=reuse_connection,
                )

    if args.mode in ("all", "web"):
        from web_experiment import run_web_experiment

        print("\n=== WEB EXPERIMENT ===")
        run_web_experiment(
            args.url,
            use_cdp=not args.no_cdp,
            output_dir=args.output_dir,
            interface=args.interface,
            headless=args.headless,
            fresh_profile=args.fresh_profile,
        )


if __name__ == "__main__":
    main()
