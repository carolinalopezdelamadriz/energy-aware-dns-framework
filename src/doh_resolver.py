import requests


DOH_RESOLVER_NAME = "quad9"
DOH_RESOLVER_HOST = "dns.quad9.net"
DOH_RESOLVER_URL = f"https://{DOH_RESOLVER_HOST}/dns-query"
DOH_FALLBACK_IPS = ["9.9.9.9", "149.112.112.112"]


def resolve_doh(domain):

    headers = {
        "accept": "application/dns-json"
    }

    params = {
        "name": domain,
        "type": "A"
    }

    try:

        response = requests.get(
            DOH_RESOLVER_URL,
            headers=headers,
            params=params,
            timeout=5,
        )

        data = response.json()

        results = []

        if "Answer" in data:
            for ans in data["Answer"]:
                results.append(ans["data"])

        return results

    except Exception:
        return []
