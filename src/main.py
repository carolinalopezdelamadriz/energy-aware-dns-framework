from dns_experiment import run_dns_experiment
from web_experiment import run_web_experiment


def main():
    """
      - Experimentos DNS para DNS clásico, DoH y DoQ.
      - Un experimento de navegación web con perfilado CDP.
    """

    domain = "bbc.com"
    url = "https://www.bbc.com"

    print("\n=== DNS EXPERIMENTS ===")
    for proto in ("dns", "doh", "doq"):
        run_dns_experiment(domain, proto)

    print("\n=== WEB EXPERIMENT ===")
    run_web_experiment(url, use_cdp=True)


if __name__ == "__main__":
    main()
