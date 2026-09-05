import { XMLParser } from 'fast-xml-parser';

export interface NmapScriptCve {
  id: string;          // e.g. "CVE-2017-15710" or "PRION:CVE-..." for vulners
  cvss?: number;       // CVSS v2 base score when reported
  type?: string;       // 'cve' | 'exploit' | ...
  is_exploit?: boolean;
}

export interface NmapScript {
  id: string;          // 'vulners' | 'http-title' | ...
  output?: string;
  cves?: NmapScriptCve[];   // only populated for scripts that emit structured CVE data (vulners)
}

export interface NmapPort {
  port: number;
  protocol: string;
  state: string;
  service?: string;
  product?: string;
  version?: string;
  tunnel?: string;
  extrainfo?: string;
  scripts?: NmapScript[];
}

export interface NmapHost {
  ip: string;
  hostnames: string[];
  ports: NmapPort[];
}

function asArray<T>(x: T | T[] | undefined): T[] {
  if (x === undefined) return [];
  return Array.isArray(x) ? x : [x];
}

interface RawScriptTableElem { '@_key'?: string; '#text'?: string | number }
interface RawScriptTable { '@_key'?: string; table?: RawScriptTable | RawScriptTable[]; elem?: RawScriptTableElem | RawScriptTableElem[] }
interface RawScript {
  '@_id'?: string;
  '@_output'?: string;
  table?: RawScriptTable | RawScriptTable[];
  elem?: RawScriptTableElem | RawScriptTableElem[];
}

interface RawPort {
  '@_protocol'?: string;
  '@_portid'?: string | number;
  state?: { '@_state'?: string };
  service?: {
    '@_name'?: string;
    '@_product'?: string;
    '@_version'?: string;
    '@_tunnel'?: string;
    '@_extrainfo'?: string;
  };
  script?: RawScript | RawScript[];
}

// vulners.nse output structure: top-level tables keyed by CPE, each containing
// nested tables per CVE with elems { id, cvss, type, is_exploit }. Walk the
// tree and flatten into a NmapScriptCve[]. Silently skips malformed entries.
function extractVulnersCves(script: RawScript): NmapScriptCve[] {
  const cves: NmapScriptCve[] = [];
  const walk = (t: RawScriptTable): void => {
    // Leaf CVE table: elem[] with keys id/cvss/type
    const elems = asArray(t.elem);
    if (elems.length) {
      const kv: Record<string, string> = {};
      for (const e of elems) {
        if (e['@_key'] && e['#text'] !== undefined) kv[e['@_key']] = String(e['#text']);
      }
      if (kv['id']) {
        const c: NmapScriptCve = { id: kv['id']! };
        if (kv['cvss']) c.cvss = parseFloat(kv['cvss']);
        if (kv['type']) c.type = kv['type'];
        if (kv['is_exploit']) c.is_exploit = kv['is_exploit'] === 'true';
        cves.push(c);
      }
    }
    for (const nested of asArray(t.table)) walk(nested);
  };
  for (const t of asArray(script.table)) walk(t);
  return cves;
}

function parseScripts(port: RawPort): NmapScript[] {
  const raw = asArray(port.script);
  const out: NmapScript[] = [];
  for (const s of raw) {
    if (!s['@_id']) continue;
    const script: NmapScript = { id: s['@_id'] };
    if (s['@_output']) script.output = s['@_output'];
    if (s['@_id'] === 'vulners') {
      const cves = extractVulnersCves(s);
      if (cves.length) script.cves = cves;
    }
    out.push(script);
  }
  return out;
}

interface RawHost {
  status?: { '@_state'?: string };
  address?: { '@_addr'?: string; '@_addrtype'?: string } | { '@_addr'?: string; '@_addrtype'?: string }[];
  hostnames?: { hostname?: { '@_name'?: string } | { '@_name'?: string }[] };
  ports?: { port?: RawPort | RawPort[] };
}

export function parseNmapXml(xml: string): NmapHost[] {
  if (!xml.trim()) return [];
  const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_' });
  let doc: { nmaprun?: { host?: RawHost | RawHost[] } };
  try {
    doc = parser.parse(xml);
  } catch {
    return [];
  }
  const hosts = asArray(doc.nmaprun?.host);
  const out: NmapHost[] = [];
  for (const h of hosts) {
    if (h.status?.['@_state'] !== 'up') continue;
    const addresses = asArray(h.address);
    const ipv4 = addresses.find((a) => a['@_addrtype'] === 'ipv4')?.['@_addr'];
    const ipv6 = addresses.find((a) => a['@_addrtype'] === 'ipv6')?.['@_addr'];
    const ip = ipv4 ?? ipv6 ?? '';
    const hostnames = asArray(h.hostnames?.hostname)
      .map((hn) => hn['@_name'])
      .filter((n): n is string => typeof n === 'string');
    const ports: NmapPort[] = [];
    for (const p of asArray(h.ports?.port)) {
      if (p.state?.['@_state'] !== 'open') continue;
      const portNum = Number(p['@_portid']);
      if (!Number.isFinite(portNum)) continue;
      const port: NmapPort = {
        port: portNum,
        protocol: String(p['@_protocol'] ?? 'tcp'),
        state: 'open',
      };
      if (p.service?.['@_name']) port.service = p.service['@_name'];
      if (p.service?.['@_product']) port.product = p.service['@_product'];
      if (p.service?.['@_version']) port.version = p.service['@_version'];
      if (p.service?.['@_tunnel']) port.tunnel = p.service['@_tunnel'];
      if (p.service?.['@_extrainfo']) port.extrainfo = p.service['@_extrainfo'];
      const scripts = parseScripts(p);
      if (scripts.length) port.scripts = scripts;
      ports.push(port);
    }
    out.push({ ip, hostnames, ports });
  }
  return out;
}
