import httpx

def resolve_doh(domain):

    url = "https://cloudflare-dns.com/dns-query"

    params = {
        "name": domain,
        "type": "A"
    }

    headers = {
        "accept": "application/dns-json"
    }

    response = httpx.get(url, params=params, headers=headers)

    return response.json()