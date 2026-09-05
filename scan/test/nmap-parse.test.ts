import { describe, it, expect } from 'vitest';
import { parseNmapXml } from '../src/lib/nmap-parse.js';

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
