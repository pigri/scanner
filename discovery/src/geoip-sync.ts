#!/usr/bin/env -S node --loader tsx
import { syncMmdb, mmdbBuildDate, MMDB_URL } from './lib/mmdb.js';

function usage(): void {
  console.error(`geoip-sync — refresh the ipinfo_lite MMDB from the fixed release URL

Usage: npm run geoip-sync -- [--mmdb <path>]

  --mmdb <path>   File to refresh (default: ipinfo_lite.mmdb)

Exits 0 on success, 1 on failure. A failed run keeps the existing file.`);
}

async function main(): Promise<void> {
  let mmdb = 'ipinfo_lite.mmdb';
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--mmdb') {
      const v = argv[++i];
      if (!v) {
        usage();
        process.exit(1);
      }
      mmdb = v;
    } else if (a === '-h' || a === '--help') {
      usage();
      return;
    } else {
      console.error(`unknown argument: ${a}`);
      usage();
      process.exit(1);
    }
  }

  console.error(`downloading ${MMDB_URL}`);
  const r = await syncMmdb({ file: mmdb });
  if (!r.ok) {
    console.error(`geoip-sync failed: ${r.error}; kept the existing ${mmdb}`);
    process.exit(1);
  }
  const built = await mmdbBuildDate(mmdb);
  console.error(
    `saved ${mmdb} (${(r.bytes / 1024 / 1024).toFixed(1)} MiB, built ${built.toISOString()})`,
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
