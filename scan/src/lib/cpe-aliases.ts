// cpe-aliases: the server-side allowlist that maps product names seen in
// evidence (Server: header tokens, httpx tech labels, nmap product strings)
// to the NVD `[vendor, product]` pairs stored in nvd.db. A name that is not
// listed here never reaches the matcher: the allowlist is what keeps the
// false-positive rate bounded. Every pair was checked to have rows in a full
// nvd.db mirror.

export type CpePair = readonly [vendor: string, product: string];

export interface AliasEntry {
  /** Label used in finding titles. */
  display: string;
  pairs: readonly CpePair[];
  /** Lowercase names, matched after dropping every non-alphanumeric character. */
  names: readonly string[];
}

export const ALIASES: readonly AliasEntry[] = [
  { display: 'Apache httpd', pairs: [['apache', 'http_server']],
    names: ['apache', 'apache httpd', 'apache http server', 'httpd'] },
  { display: 'nginx', pairs: [['f5', 'nginx'], ['nginx', 'nginx']],
    names: ['nginx'] },
  { display: 'PHP', pairs: [['php', 'php']], names: ['php'] },
  { display: 'OpenSSL', pairs: [['openssl', 'openssl']], names: ['openssl'] },
  { display: 'IIS',
    pairs: [['microsoft', 'internet_information_services'], ['microsoft', 'internet_information_server']],
    names: ['microsoft-iis', 'microsoft iis', 'iis', 'microsoft iis httpd', 'iis httpd'] },
  { display: 'OpenSSH', pairs: [['openbsd', 'openssh']], names: ['openssh'] },
  { display: 'BIND', pairs: [['isc', 'bind']], names: ['bind', 'isc bind', 'isc-bind'] },
  { display: 'Exim', pairs: [['exim', 'exim']], names: ['exim', 'exim smtpd'] },
  { display: 'PowerDNS',
    pairs: [['powerdns', 'authoritative_server'], ['powerdns', 'recursor'], ['powerdns', 'powerdns']],
    names: ['powerdns'] },
  { display: 'Varnish',
    pairs: [['varnish-cache', 'varnish'], ['varnish_cache_project', 'varnish_cache'], ['varnish-software', 'varnish_cache']],
    names: ['varnish', 'varnish cache', 'varnish http cache'] },
  { display: 'Tomcat', pairs: [['apache', 'tomcat']],
    names: ['tomcat', 'apache tomcat', 'apache tomcat coyote jsp engine'] },
  { display: 'lighttpd', pairs: [['lighttpd', 'lighttpd']], names: ['lighttpd'] },
  { display: 'LiteSpeed', pairs: [['litespeedtech', 'litespeed_web_server']],
    names: ['litespeed', 'litespeed web server'] },
  { display: 'WordPress', pairs: [['wordpress', 'wordpress']], names: ['wordpress'] },
  { display: 'Drupal', pairs: [['drupal', 'drupal']], names: ['drupal'] },
  { display: 'Joomla', pairs: [['joomla', 'joomla!'], ['joomla', 'joomla']], names: ['joomla', 'joomla!'] },
];

const key = (s: string): string => s.toLowerCase().replace(/[^a-z0-9]/g, '');

const INDEX: ReadonlyMap<string, AliasEntry> = new Map(
  ALIASES.flatMap((e) => e.names.map((n) => [key(n), e] as const)),
);

/** The allowlisted entry for a product name, or null when it is not one we match. */
export function resolveAlias(name: string): AliasEntry | null {
  return INDEX.get(key(name)) ?? null;
}
