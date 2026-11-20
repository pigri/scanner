import { normalizeHost, parseHttpxRow } from './httpx-parse.js';

// URLs of the WordPress hosts of `batch` found in httpx JSONL outputs, deduped
// in first-seen order. A host outside the batch is dropped even when WordPress.
export function wpTargetsFromHttpx(texts: string[], batch: string[]): string[] {
  const inBatch = new Set(batch.map(normalizeHost));
  const seen = new Set<string>();
  for (const text of texts) {
    for (const line of text.split('\n')) {
      const row = parseHttpxRow(line);
      if (!row || !row.url || !inBatch.has(row.target)) continue;
      const isWp = Array.isArray(row.tech) && row.tech.some((t) => typeof t === 'string' && t.toLowerCase().includes('wordpress'));
      if (isWp) seen.add(row.url);
    }
  }
  return [...seen];
}
