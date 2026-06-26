import argparse


def parse_args():
    parser = argparse.ArgumentParser(
        description="Runner para los experimentos DNS y web del framework"
    )
    parser.add_argument(
        "--mode",
        choices=("all", "dns", "web", "batch", "analyze", "check"),
        default="all",
        help="Tipo de experimento a ejecutar",
    )
    parser.add_argument("--domain", default="bbc.com", help="Dominio para las pruebas DNS")
    parser.add_argument(
        "--url",
        default="https://www.bbc.com",
        help="URL para la prueba de navegación web",
    )
    parser.add_argument(
        "--protocols",
        nargs="+",
        choices=("dns", "doh", "doq"),
        default=("dns", "doh", "doq"),
        help="Protocolos DNS que se quieren comparar",
    )
    parser.add_argument(
        "--doq-resolver",
        choices=("quad9", "cloudflare", "google"),
        default="quad9",
        help="Resolver DoQ usado en la medición. Conviene fijar uno para no ensuciar los PCAP.",
    )
    parser.add_argument(
        "--repetitions",
        type=int,
        default=5,
        help="Número de consultas DNS por protocolo",
    )
    parser.add_argument(
        "--output-dir",
        default="results",
        help="Directorio donde se guardan PCAP, CSV y perfiles JSON",
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="Interfaz de red usada por tcpdump, por ejemplo en0 en macOS",
    )
    parser.add_argument(
        "--no-cdp",
        action="store_true",
        help="Desactiva el perfilado de recursos con Selenium/CDP",
    )
    parser.add_argument(
        "--sites-file",
        default="data/sites_sample.csv",
        help="CSV con columnas label, domain y url para el modo batch",
    )
    parser.add_argument(
        "--run-dir",
        default=None,
        help="Carpeta de resultados que se quiere analizar, por ejemplo results/20260626_103000",
    )
    parser.add_argument(
        "--web-repetitions",
        type=int,
        default=1,
        help="Número de visitas web por sitio en modo batch",
    )
    parser.add_argument(
        "--skip-dns",
        action="store_true",
        help="Saltar los experimentos DNS en modo batch",
    )
    parser.add_argument(
        "--skip-web",
        action="store_true",
        help="Saltar los experimentos web en modo batch",
    )
    parser.add_argument(
        "--check-doq",
        action="store_true",
        help="En modo check, comprueba conectividad DoQ con el resolver elegido",
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
