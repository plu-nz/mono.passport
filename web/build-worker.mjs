import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';

const root = dirname(fileURLToPath(import.meta.url));
const html = await readFile(join(root, 'index.html'), 'utf8');
const login = await readFile(join(root, 'login.html'), 'utf8');
// The test login page runs one inline script, allowed by its hash; the form
// still cannot be submitted anywhere (form-action 'none').
const loginScript = login.match(/<script>([\s\S]*?)<\/script>/)[1];
const loginScriptHash = createHash('sha256').update(loginScript).digest('base64');
const baseCsp = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const pages = {
  '/': { body: html, csp: baseCsp },
  '/login': { body: login, csp: `${baseCsp}; script-src 'sha256-${loginScriptHash}'` },
};
const source = `const pages = ${JSON.stringify(pages)};

export default {
  async fetch(request) {
    const { pathname } = new URL(request.url);
    if (pathname === '/install.sh') {
      return Response.redirect('https://raw.githubusercontent.com/plu-nz/mono.passport/main/scripts/install.sh', 302);
    }
    const page = pages[pathname];
    if (!page) return new Response('Page not found', { status: 404 });
    return new Response(request.method === 'HEAD' ? null : page.body, {
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'public, max-age=300',
        'content-security-policy': page.csp,
        'referrer-policy': 'strict-origin-when-cross-origin',
        'x-content-type-options': 'nosniff',
      },
    });
  },
};
`;
await mkdir(join(root, 'dist'), { recursive: true });
await writeFile(join(root, 'dist', 'worker.js'), source);
