import dns.resolver # pip install dnspython

def resolve_classic(domain):
    resolver = dns.resolver.Resolver()
    answer = resolver.resolve(domain, "A")

    results = []
    for rdata in answer:
        results.append(rdata.to_text())

    return results