import argparse


def parse_args():
    parser = argparse.ArgumentParser(
        description="Energy-aware DNS and web traffic experiment runner"
    )
    parser.add_argument(
        "--mode",
        choices=("all", "dns", "web", "batch", "analyze", "check"),
        default="all",
        help="Experiment family to run",
    )
    parser.add_argument("--domain", default="bbc.com", help="Domain for DNS tests")
    parser.add_argument(
        "--url",
        default="https://www.bbc.com",
        help="Website URL for the web traffic test",
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
        help="DoQ resolver used for measurements. Use one fixed resolver to avoid polluted PCAPs.",
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
        help="Directory for pcaps, CSV summaries and JSON profiles",
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="Network interface used by tcpdump, for example en0 on macOS",
    )
    parser.add_argument(
        "--no-cdp",
        action="store_true",
        help="Disable Selenium/CDP resource profiling for the web experiment",
    )
    parser.add_argument(
        "--sites-file",
        default="data/sites_sample.csv",
        help="CSV file with label, domain and url columns for batch mode",
    )
    parser.add_argument(
        "--run-dir",
        default=None,
        help="Existing result run directory to analyze, for example results/20260626_103000",
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
        "--check-doq",
        action="store_true",
        help="In check mode, test DoQ connectivity against the known resolvers",
    )
    return parser.parse_args()


def main():
    """
      Experimentos DNS para DNS clásico, DoH y DoQ
    """

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
        )
        return

    if args.mode == "analyze":
        from run_analysis import analyze_run

        analyze_run(args.run_dir or args.output_dir)
        return

    if args.mode in ("all", "dns"):
        from dns_experiment import run_dns_experiment

        print("\n=== DNS EXPERIMENTS ===")
        for proto in args.protocols:
            run_dns_experiment(
                args.domain,
                proto,
                repetitions=args.repetitions,
                output_dir=args.output_dir,
                interface=args.interface,
                doq_resolver=args.doq_resolver,
            )

    if args.mode in ("all", "web"):
        from web_experiment import run_web_experiment

        print("\n=== WEB EXPERIMENT ===")
        run_web_experiment(
            args.url,
            use_cdp=not args.no_cdp,
            output_dir=args.output_dir,
            interface=args.interface,
        )


if __name__ == "__main__":
    main()
