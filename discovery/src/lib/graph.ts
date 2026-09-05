export interface EnrichedAddress {
  ip: string;
  version: 4 | 6;
  ptr: string[];
  asn: string | null;
  as_name: string | null;
  as_domain: string | null;
  country_code: string | null;
  country: string | null;
  continent_code: string | null;
}

export interface EnrichedRow {
  domain: string;
  addresses: EnrichedAddress[];
  errors: string[];
}

export interface GraphDomain {
  domain: string;
  addresses: EnrichedAddress[];
}

export interface GraphIp extends EnrichedAddress {
  domains: string[];
}

export interface GraphAsn {
  asn: string;
  as_name: string;
  as_domain: string;
  country_code: string;
  ips: string[];
  domains: string[];
}

export interface CountryCount {
  cc: string;
  n: number;
}

export interface Graph {
  domains: GraphDomain[];
  ips: GraphIp[];
  asns: GraphAsn[];
  countries: CountryCount[];
}

export function buildGraph(rows: readonly EnrichedRow[]): Graph {
  const domains = new Map<string, GraphDomain>();
  const ips = new Map<string, GraphIp & { _domains: Set<string> }>();
  const asns = new Map<string, GraphAsn & { _ips: Set<string>; _domains: Set<string> }>();
  const countries = new Map<string, number>();

  for (const r of rows) {
    domains.set(r.domain, { domain: r.domain, addresses: r.addresses });
    for (const a of r.addresses) {
      let ip = ips.get(a.ip);
      if (!ip) {
        ip = { ...a, domains: [], _domains: new Set() };
        ips.set(a.ip, ip);
      }
      ip._domains.add(r.domain);
      if (a.asn) {
        let asn = asns.get(a.asn);
        if (!asn) {
          asn = {
            asn: a.asn,
            as_name: a.as_name ?? '',
            as_domain: a.as_domain ?? '',
            country_code: a.country_code ?? '',
            ips: [],
            domains: [],
            _ips: new Set(),
            _domains: new Set(),
          };
          asns.set(a.asn, asn);
        }
        asn._ips.add(a.ip);
        asn._domains.add(r.domain);
      }
      if (a.country_code) {
        countries.set(a.country_code, (countries.get(a.country_code) ?? 0) + 1);
      }
    }
  }

  return {
    domains: [...domains.values()],
    ips: [...ips.values()].map(({ _domains, ...rest }) => ({
      ...rest,
      domains: [..._domains],
    })),
    asns: [...asns.values()].map(({ _ips, _domains, ...rest }) => ({
      ...rest,
      ips: [..._ips],
      domains: [..._domains],
    })),
    countries: [...countries.entries()]
      .map(([cc, n]) => ({ cc, n }))
      .sort((a, b) => b.n - a.n),
  };
}
