// Small fetch wrapper shared by the real connectors: JSON in/out, timeouts, and retry on 429 / 5xx
// (honouring Retry-After). Errors carry the HTTP status and a short body excerpt for the UI.
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class HttpError extends Error {
  constructor(status, message, body) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

export async function fetchJson(url, { method = 'GET', headers = {}, body, form, timeoutMs = 30000, retries = 2 } = {}) {
  for (let attempt = 0; ; attempt++) {
    let res;
    try {
      res = await fetch(url, {
        method,
        headers: {
          Accept: 'application/json',
          ...(body ? { 'Content-Type': 'application/json' } : {}),
          ...(form ? { 'Content-Type': 'application/x-www-form-urlencoded' } : {}),
          ...headers,
        },
        body: body ? JSON.stringify(body) : form ? new URLSearchParams(form).toString() : undefined,
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (e) {
      if (attempt < retries) { await sleep(1000 * (attempt + 1)); continue; }
      throw new HttpError(0, `${method} ${new URL(url).host} failed: ${e.cause?.code || e.message}`);
    }
    if ((res.status === 429 || res.status >= 500) && attempt < retries) {
      const wait = Number(res.headers.get('retry-after')) * 1000 || 1500 * (attempt + 1);
      await sleep(Math.min(wait, 20000));
      continue;
    }
    const text = await res.text();
    if (!res.ok) throw new HttpError(res.status, `${method} ${new URL(url).pathname} → HTTP ${res.status}`, text.slice(0, 300));
    try { return text ? JSON.parse(text) : {}; } catch { throw new HttpError(res.status, `Response from ${new URL(url).pathname} was not JSON`, text.slice(0, 300)); }
  }
}

export const basicAuth = (user, pass) => `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;
