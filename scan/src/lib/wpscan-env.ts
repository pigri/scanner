// wpscan turns its vuln API on whenever WPSCAN_API_TOKEN is in its environment,
// even with an empty value, and then aborts on the API's 401. A blank token
// therefore has to be absent from the child's environment, not just unused.
export function wpscanEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out = { ...env };
  if (!out['WPSCAN_API_TOKEN']?.trim()) delete out['WPSCAN_API_TOKEN'];
  return out;
}
