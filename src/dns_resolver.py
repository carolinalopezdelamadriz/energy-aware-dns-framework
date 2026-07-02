import dns.exception
import dns.resolver


CLASSIC_DNS_RESOLVER = "9.9.9.9"


def resolve_classic(domain):

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [CLASSIC_DNS_RESOLVER]
    resolver.port = 53

    try:
        answer = resolver.resolve(domain, "A", tcp=False)

        results = []
        for rdata in answer:
            results.append(rdata.to_text())

        return results

    except dns.resolver.NXDOMAIN:
        # domain does not exist, but the query was already sent
        return []

    except dns.exception.DNSException:
        return []
