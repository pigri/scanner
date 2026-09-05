export function decodeDdgUrl(href: string): string {
  try {
    const u = new URL(href, 'https://duckduckgo.com');
    if (u.pathname === '/l/' && u.searchParams.get('uddg')) {
      return decodeURIComponent(u.searchParams.get('uddg')!);
    }
    return href;
  } catch {
    return href;
  }
}

export function hostOf(href: string): string | null {
  try {
    return new URL(href).hostname;
  } catch {
    return null;
  }
}

export type DomainFilter = (host: string | null | undefined) => string | null;

export function makeDomainFilter(
  suffix: string | null,
  exclude: readonly string[]
): DomainFilter {
  const s = suffix ? suffix.toLowerCase().replace(/^\./, '') : null;
  const dotSuffix = s ? `.${s}` : null;
  const excludeSet = new Set(exclude.map((e) => e.toLowerCase()));
  return (host) => {
    if (!host) return null;
    const h = host.replace(/^www\./i, '').toLowerCase();
    if (s && h !== s && (!dotSuffix || !h.endsWith(dotSuffix))) return null;
    for (const ex of excludeSet) {
      if (h === ex || h.endsWith(`.${ex}`)) return null;
    }
    return h;
  };
}
