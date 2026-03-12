import requests

def resolve_doh(domain):

    url = "https://cloudflare-dns.com/dns-query"

    headers = {
        "accept": "application/dns-json"
    }

    params = {
        "name": domain,
        "type": "A"
    }

    try:

        response = requests.get(url, headers=headers, params=params, timeout=5)

        data = response.json()

        results = []

        if "Answer" in data:
            for ans in data["Answer"]:
                results.append(ans["data"])

        return results

    except Exception:
        return []