import dns.resolver


def classic_dns_query(domain):
    resolver = dns.resolver.Resolver()
    answer = resolver.resolve(domain, "A")

    print(f"DNS response for {domain}:")
    for rdata in answer:
        print(rdata)