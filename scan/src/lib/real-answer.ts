/**
 * A blanket block says nothing about the app behind it: 401/403, a rate limit,
 * a server error, or a Cloudflare challenge (`cf-mitigated`).
 */
export function isBlockedAnswer(status: number, mitigated: boolean): boolean {
  return mitigated || status === 401 || status === 403 || status === 429 || status >= 500;
}
