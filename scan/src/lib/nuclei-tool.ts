/** `findings.tool` and `runs.tool` of a nuclei run with --from-urls. */
export const NUCLEI_URL_TOOL = 'nuclei-url';

/** The tool name the risk dedupe compares: both nuclei passes scan the bare host, so a match both report is one finding. */
export function riskToolKey(tool: string): string {
  return tool === NUCLEI_URL_TOOL ? 'nuclei' : tool;
}

/** SQL list of the tools riskToolKey folds into 'nuclei'. */
export const NUCLEI_FAMILY_SQL = `('nuclei','${NUCLEI_URL_TOOL}')`;

/** SQL twin of riskToolKey over a column or expression. */
export function riskToolKeySql(col: string): string {
  return `CASE WHEN ${col} = '${NUCLEI_URL_TOOL}' THEN 'nuclei' ELSE ${col} END`;
}
