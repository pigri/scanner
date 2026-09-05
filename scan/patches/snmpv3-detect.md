# snmpv3-detect false-positive fix

**Upstream:** `nuclei-templates/javascript/udp/detection/snmpv3-detect.yaml`
**Reason:** the shipped template's DSL matcher is `success == true`, which only
checks the JavaScript executed without throwing. Silent-UDP timeouts (typical
of firewalled `udp/161`) satisfy that condition and the fallback path in
`getVendor(msgHex)` returns the sentinel string `"Enterprise: unknown"` — so
every non-responding host is reported as a positive SNMPv3 detection.

Observed impact on gen0sec estate: **18 false-positive rows** across 18 hosts,
all extracting the identical `"Enterprise: unknown"` string. Verified negative
by four independent probes (nmap `-sU` reported `161/udp closed` on every host;
snmpstatus -v3, snmpget -v2c, and raw netcat of the exact template payload
all returned zero bytes).

## Fix

Two changes in the template:

1. `getVendor(msgHex)` returns empty string `""` unless the response is
   structurally a valid SNMPv3 message: non-empty AND at least 60 hex chars
   (30 bytes minimum for a valid SNMPv3 discovery) AND starts with `30`
   (ASN.1 SEQUENCE) AND contains the version=3 marker `020103`. When known
   vendor prefixes miss and only a bare `8000…0201` engine-ID pattern
   matches, require at least 4 hex chars between the prefix and terminator.

2. Matcher changes from `success == true` to
   `success == true && len(response) > 0` — so the empty-string signal from
   the fixed JS becomes a real "not detected" outcome.

The `# digest:` line at the bottom is removed so `nuclei -update-templates`
doesn't refuse to load the modified template due to a bad SHA.

## Applying

`scripts/apply-snmpv3-detect-fix.sh` — idempotent, re-applies the fix in place
whenever `nuclei -update-templates` overwrites the file. Wired into
`deploy/nuclei-update-templates.service` so the fix survives every nightly
template refresh.
