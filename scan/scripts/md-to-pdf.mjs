#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { resolve, basename } from 'node:path';
import { pathToFileURL } from 'node:url';

const [, , mdArg, outArg] = process.argv;
if (!mdArg) {
  console.error('usage: md-to-pdf.mjs <input.md> [output.pdf]');
  process.exit(2);
}
const mdPath = resolve(mdArg);
const outPath = resolve(outArg ?? mdPath.replace(/\.md$/, '.pdf'));

const mdItUrl = pathToFileURL('/home/pigri/.npm/_npx/05eeecd92f4e18e0/node_modules/markdown-it/index.mjs').href;
const { default: MarkdownIt } = await import(mdItUrl);
const puppeteer = (await import('puppeteer-core')).default;

const md = new MarkdownIt({ html: false, linkify: true, typographer: true, breaks: false });
const body = md.render(readFileSync(mdPath, 'utf8'));
const title = basename(mdPath, '.md');

const css = `
  :root { color-scheme: light; }
  html, body { margin: 0; padding: 0; background: #fff; color: #111; }
  body { font: 10.5pt/1.45 -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; padding: 32px 40px 48px; }
  h1 { font-size: 20pt; margin: 0 0 6pt; border-bottom: 2px solid #2b2b2b; padding-bottom: 6pt; }
  h2 { font-size: 14pt; margin: 22pt 0 6pt; color: #1f2a44; border-bottom: 1px solid #d0d5dd; padding-bottom: 3pt; }
  h3 { font-size: 11.5pt; margin: 16pt 0 4pt; color: #1f2a44; }
  h4 { font-size: 10.5pt; margin: 12pt 0 4pt; color: #333; }
  p  { margin: 0 0 6pt; }
  ul, ol { margin: 0 0 8pt 20pt; padding: 0; }
  li { margin: 2pt 0; }
  code { font: 9.5pt/1.4 "SFMono-Regular", ui-monospace, "Cascadia Mono", "Menlo", "Consolas", monospace; background: #f2f4f7; padding: 1pt 3pt; border-radius: 3px; }
  pre  { background: #0f172a; color: #e5e7eb; padding: 8pt 10pt; border-radius: 4px; overflow-x: auto; font: 9pt/1.4 "SFMono-Regular", ui-monospace, monospace; page-break-inside: avoid; }
  pre code { background: transparent; padding: 0; color: inherit; font: inherit; }
  table { border-collapse: collapse; width: 100%; margin: 6pt 0 10pt; font-size: 9.5pt; page-break-inside: avoid; }
  th, td { border: 1px solid #d0d5dd; padding: 4pt 6pt; text-align: left; vertical-align: top; }
  th { background: #f2f4f7; font-weight: 600; }
  tr:nth-child(even) td { background: #fafbfc; }
  blockquote { border-left: 3px solid #cbd5e1; margin: 4pt 0 8pt; padding: 2pt 8pt; color: #475569; background: #f8fafc; }
  hr { border: 0; border-top: 1px solid #e2e8f0; margin: 12pt 0; }
  a { color: #0b57d0; text-decoration: none; }
  .footer { position: fixed; left: 40px; right: 40px; bottom: 12pt; font-size: 8pt; color: #6b7280; display: flex; justify-content: space-between; }
`;

const html = `<!doctype html>
<html><head><meta charset="utf-8"><title>${title}</title><style>${css}</style></head>
<body>${body}</body></html>`;

const chromePath = '/home/pigri/.cache/puppeteer/chrome/linux-152.0.7977.42/chrome-linux64/chrome';
const browser = await puppeteer.launch({
  executablePath: chromePath,
  headless: 'shell',
  args: ['--no-sandbox', '--disable-dev-shm-usage'],
});
try {
  const page = await browser.newPage();
  await page.setContent(html, { waitUntil: 'load' });
  await page.pdf({
    path: outPath,
    format: 'A4',
    printBackground: true,
    margin: { top: '18mm', bottom: '18mm', left: '15mm', right: '15mm' },
    displayHeaderFooter: true,
    headerTemplate: `<div style="font-size:8pt;color:#6b7280;width:100%;padding:0 15mm;">${title}</div>`,
    footerTemplate: `<div style="font-size:8pt;color:#6b7280;width:100%;padding:0 15mm;display:flex;justify-content:space-between;"><span>gen0sec / scan</span><span>Page <span class="pageNumber"></span> / <span class="totalPages"></span></span></div>`,
  });
  console.log(outPath);
} finally {
  await browser.close();
}
