import { describe, it, expect } from 'vitest';
import { parseNmapXml, vulnersCoveredTargets, type NmapHost } from '../src/lib/nmap-parse.js';

const FIXTURE = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV" start="1700000000">
  <host>
    <status state="up"/>
    <address addr="84.206.128.147" addrtype="ipv4"/>
    <hostnames><hostname name="gitlab.dtr.gov.hu" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" ostype="Linux"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.24.0" tunnel="ssl"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="closed"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
  </host>
</nmaprun>`;

describe('parseNmapXml', () => {
  it('extracts up hosts with open ports', () => {
    const r = parseNmapXml(FIXTURE);
    expect(r).toHaveLength(1);
    const h = r[0]!;
    expect(h.ip).toBe('84.206.128.147');
    expect(h.hostnames).toEqual(['gitlab.dtr.gov.hu']);
    expect(h.ports).toHaveLength(3);
  });

  it('captures port + service details', () => {
    const h = parseNmapXml(FIXTURE)[0]!;
    const ssh = h.ports.find((p) => p.port === 22)!;
    expect(ssh.protocol).toBe('tcp');
    expect(ssh.state).toBe('open');
    expect(ssh.service).toBe('ssh');
    expect(ssh.product).toBe('OpenSSH');
    expect(ssh.version).toBe('8.9p1');
  });

  it('marks tls-tunneled ports', () => {
    const h = parseNmapXml(FIXTURE)[0]!;
    const https = h.ports.find((p) => p.port === 443)!;
    expect(https.tunnel).toBe('ssl');
  });

  it('excludes closed ports by default', () => {
    const h = parseNmapXml(FIXTURE)[0]!;
    expect(h.ports.some((p) => p.port === 8080)).toBe(false);
  });

  it('excludes down hosts', () => {
    expect(parseNmapXml(FIXTURE).some((h) => h.ip === '10.0.0.1')).toBe(false);
  });

  it('gracefully returns [] on garbage input', () => {
    expect(parseNmapXml('not xml')).toEqual([]);
    expect(parseNmapXml('')).toEqual([]);
  });
});

const host = (over: Partial<NmapHost> = {}): NmapHost => ({
  ip: '192.0.2.10',
  hostnames: ['www.example.test'],
  ports: [{ port: 80, protocol: 'tcp', state: 'open', service: 'http', product: 'nginx', version: '1.24.0' }],
  ...over,
});
const withCve = (h: NmapHost): NmapHost => ({
  ...h,
  ports: h.ports.map((p) => ({ ...p, scripts: [{ id: 'vulners', cves: [{ id: 'CVE-2024-0001', cvss: 7.5 }] }] })),
});
const ON = { vulners: true, exitCode: 0 };

describe('parseNmapXml host timeout', () => {
  it('flags a host nmap gave up on', () => {
    const xml = `<nmaprun><host starttime="1" endtime="2" timedout="true"><status state="up"/>
      <address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host>
      <host><status state="up"/><address addr="198.51.100.7" addrtype="ipv4"/></host></nmaprun>`;
    const [a, b] = parseNmapXml(xml);
    expect(a!.timedOut).toBe(true);
    expect(b!.timedOut).toBeUndefined();
  });
});

describe('vulnersCoveredTargets', () => {
  it('covers a host whose versioned port produced vulners CVEs', () => {
    expect(vulnersCoveredTargets([withCve(host())], ON)).toEqual(['www.example.test']);
  });

  it('uses the ip when the host has no hostname', () => {
    expect(vulnersCoveredTargets([withCve(host({ hostnames: [] }))], ON)).toEqual(['192.0.2.10']);
  });

  it('does not cover a host with no open port', () => {
    expect(vulnersCoveredTargets([host({ ports: [] })], ON)).toEqual([]);
  });

  it('covers nothing on a non-zero exit', () => {
    expect(vulnersCoveredTargets([withCve(host())], { vulners: true, exitCode: 1 })).toEqual([]);
  });

  it('covers nothing when vulners was off', () => {
    expect(vulnersCoveredTargets([withCve(host())], { vulners: false, exitCode: 0 })).toEqual([]);
  });

  it('does not cover versioned ports when the run produced no vulners CVE anywhere', () => {
    expect(vulnersCoveredTargets([host()], ON)).toEqual([]);
  });

  it('covers a host whose ports have a product but no version', () => {
    const h = host({ ports: [{ port: 80, protocol: 'tcp', state: 'open', product: 'nginx' }] });
    expect(vulnersCoveredTargets([h], ON)).toEqual(['www.example.test']);
  });

  it('does not cover a host nmap timed out on', () => {
    const h = withCve(host({ timedOut: true }));
    const other = withCve(host({ ip: '198.51.100.7', hostnames: ['api.example.test'] }));
    expect(vulnersCoveredTargets([h, other], ON)).toEqual(['api.example.test']);
  });

  it('a CVE on another host lifts the silent-failure guard for every host', () => {
    const quiet = host({ ip: '203.0.113.5', hostnames: ['old.example.test'] });
    expect(vulnersCoveredTargets([withCve(host()), quiet], ON)).toEqual(['www.example.test', 'old.example.test']);
  });
});
