// Minimal Axiom HTTP ingest client. Emission is best-effort: it must never
// fail the caller, so missing config and non-2xx responses are logged and
// swallowed. The core ingest() takes explicit args (testable without env);
// ingestFromEnv() is the thin wrapper that reads the environment.
//
// Env (read by ingestFromEnv only):
//   AXIOM_INGEST_TOKEN   ingest token (unset -> warn + no-op)
//   AXIOM_DATASET        dataset name (unset -> warn + no-op)
//   AXIOM_URL            API base (default: https://api.axiom.co)

export const DEFAULT_AXIOM_URL = 'https://api.axiom.co';

export interface AxiomConfig {
  dataset: string;
  token: string;
  url?: string;
}

export type AxiomEvent = Record<string, unknown>;

export async function ingest(events: AxiomEvent[], cfg: AxiomConfig): Promise<void> {
  if (!events.length) return;
  const base = (cfg.url ?? DEFAULT_AXIOM_URL).replace(/\/+$/, '');
  const endpoint = `${base}/v1/datasets/${encodeURIComponent(cfg.dataset)}/ingest`;
  // Axiom takes _time from the event; default to now when the caller omitted it.
  const now = new Date().toISOString();
  const body = events.map((e) => ({ _time: now, ...e }));
  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${cfg.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      console.error(`warn: axiom ingest returned HTTP ${res.status}`);
    }
  } catch (err) {
    console.error(`warn: axiom ingest failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

export async function ingestFromEnv(events: AxiomEvent[]): Promise<void> {
  const token = process.env.AXIOM_INGEST_TOKEN;
  const dataset = process.env.AXIOM_DATASET;
  if (!token || !dataset) {
    console.error('warn: AXIOM_INGEST_TOKEN or AXIOM_DATASET unset — skipping axiom emission');
    return;
  }
  await ingest(events, { token, dataset, url: process.env.AXIOM_URL || DEFAULT_AXIOM_URL });
}
