/**
 * Hardened SSRF guard — the single shared implementation for every web_fetch
 * surface (ar-tools `tools`, `web-fetch`, `web-fetch-cartridge`,
 * `web-fetch-server`, `web-fetch-server-cartridge`, `web-fetch-internal`).
 *
 * Hoisted from packages/web-fetch-server/src/ssrf.ts (PR #455), which was the
 * strongest of the forked copies; the weaker forks re-export from here.
 *
 * Layers, in order of cost:
 *  1. `isPrivateUrl` / `isPrivateIp` — synchronous, literal inspection of the
 *     URL host. Catches IP literals (v4 + v6, including IPv4-mapped IPv6 and
 *     integer encodings — the WHATWG URL parser normalises decimal/hex/octal
 *     and short-form IPv4 to dotted-quad before we see the hostname) and known
 *     internal hostnames (localhost, the cloud metadata server). Cheap; run it
 *     everywhere a user- or LLM-supplied URL enters.
 *  2. `assertUrlAllowed` — layer 1 plus DNS resolution: every resolved IP is
 *     re-checked. This closes DNS-based SSRF ("public hostname that resolves
 *     to 169.254.169.254").
 *  3. Guarded fetches — both follow redirects manually, re-validating every
 *     hop (literal + DNS), so a public URL that 302s to the metadata server is
 *     refused mid-chain:
 *       - `fetchWithSsrfProtection` — returns the native `Response`; drop-in
 *         for `fetch(url, { redirect: "follow" })`.
 *       - `safeFetch` — additionally enforces a response-body byte cap so a
 *         hostile URL can't OOM the instance; returns a `SafeFetchResult`.
 *
 * On GCP/Cloud Run the metadata server at 169.254.169.254 (a.k.a.
 * metadata.google.internal) vends the service-account OAuth token, so a single
 * SSRF that reaches it is a credential-exfiltration bug. These checks are the
 * boundary that prevents that.
 */

import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

const FETCH_TIMEOUT = parseInt(process.env.FETCH_TIMEOUT || "30000", 10);
const MAX_REDIRECTS = 10;
/** Max bytes any single `safeFetch` will read into memory (default 25 MB). */
export const MAX_FETCH_BYTES = parseInt(process.env.MAX_FETCH_BYTES || String(25 * 1024 * 1024), 10);

/** Error thrown when a fetch target resolves to a blocked address. */
export class SsrfError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SsrfError";
  }
}

/** Hostnames that always resolve to internal infrastructure. */
const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
  "metadata.goog",
  "metadata",
]);

/**
 * Is a raw IP string (v4 or v6) a private / loopback / link-local / reserved
 * address that must never be fetched?
 *
 * Expects a CANONICAL IP string — the IPv4-mapped-IPv6 matchers only recognize
 * compressed forms (`::ffff:a.b.c.d`), not expanded ones like
 * `0:0:0:0:0:ffff:a.b.c.d`. Every caller feeds canonical input: `isPrivateUrl`
 * passes the WHATWG-URL-normalized host and `assertUrlAllowed` passes
 * getaddrinfo output. Don't call this on raw, un-normalized user strings.
 */
export function isPrivateIp(raw: string): boolean {
  // Strip an IPv6 zone id (e.g. "fe80::1%eth0").
  const ip = raw.includes("%") ? raw.slice(0, raw.indexOf("%")) : raw;
  const kind = isIP(ip);

  if (kind === 4) return isPrivateIpv4(ip);
  if (kind === 6) return isPrivateIpv6(ip.toLowerCase());
  return false;
}

function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true;
  const [a, b] = parts;
  if (a === 0) return true; // 0.0.0.0/8 — "this network"
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local incl. cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a === 192 && b === 0 && parts[2] === 0) return true; // 192.0.0.0/24
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 benchmarking
  if (a >= 224) return true; // multicast + reserved (224.0.0.0+)
  return false;
}

function isPrivateIpv6(ip: string): boolean {
  if (ip === "::1" || ip === "::") return true;
  // Defense-in-depth beyond the canonical-input contract: expanded loopback /
  // unspecified forms, in case a raw host string reaches here un-normalized.
  if (/^(0+:){7}0*1$/.test(ip)) return true; // 0:0:0:0:0:0:0:1
  if (/^(0+:){7}0+$/.test(ip)) return true; // 0:0:0:0:0:0:0:0
  // IPv4-mapped / -compatible: ::ffff:a.b.c.d or ::ffff:HHHH:HHHH — check the embedded v4.
  const mapped = ip.match(/^::(?:ffff:)?(?:0*:)*((?:\d{1,3}\.){3}\d{1,3})$/);
  if (mapped) return isPrivateIpv4(mapped[1]);
  const mappedHex = ip.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (mappedHex) {
    const hi = parseInt(mappedHex[1], 16);
    const lo = parseInt(mappedHex[2], 16);
    const v4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
    return isPrivateIpv4(v4);
  }
  if (/^fe[89ab]/.test(ip)) return true; // fe80::/10 link-local
  if (/^f[cd]/.test(ip)) return true; // fc00::/7 unique local
  if (/^ff/.test(ip)) return true; // ff00::/8 multicast
  return false;
}

/**
 * Synchronous, literal check. Blocks IP literals (incl. IPv4-mapped IPv6 and
 * bare-integer encodings) and known-internal hostnames. Returns true (= block)
 * for anything we can't parse — fail closed.
 *
 * This does NOT resolve DNS — a hostname that resolves to a private address
 * still passes here. `assertUrlAllowed` / the guarded fetches catch that.
 */
export function isPrivateUrl(rawUrl: string): boolean {
  let hostname: string;
  try {
    ({ hostname } = new URL(rawUrl));
  } catch {
    return true;
  }

  const host = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname.toLowerCase();

  if (BLOCKED_HOSTNAMES.has(host)) return true;
  if (host.endsWith(".localhost")) return true;

  // IP literal (v4 or v6)?
  if (isIP(host)) return isPrivateIp(host);

  // Bare-integer IPv4 (e.g. http://2130706433/ === 127.0.0.1).
  if (/^\d+$/.test(host)) {
    const n = Number(host);
    if (Number.isSafeInteger(n) && n <= 0xffffffff) {
      const v4 = `${(n >>> 24) & 0xff}.${(n >>> 16) & 0xff}.${(n >>> 8) & 0xff}.${n & 0xff}`;
      return isPrivateIpv4(v4);
    }
  }

  // A normal hostname — DNS resolution (assertUrlAllowed/safeFetch) decides.
  return false;
}

/**
 * Resolve the host and throw SsrfError if the URL is private at the literal
 * level or any resolved IP is private. Use before fetching a user/LLM URL when
 * you don't go through one of the guarded fetches.
 */
export async function assertUrlAllowed(rawUrl: string): Promise<void> {
  if (isPrivateUrl(rawUrl)) {
    throw new SsrfError(`Blocked request to private/internal address: ${rawUrl}`);
  }
  let hostname: string;
  try {
    ({ hostname } = new URL(rawUrl));
  } catch {
    throw new SsrfError(`Malformed URL: ${rawUrl}`);
  }
  const host = hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  if (isIP(host)) return; // already validated as a literal above

  let addrs: { address: string }[];
  try {
    addrs = await lookup(host, { all: true });
  } catch {
    return; // unresolvable host can't reach anything internal; let fetch surface the error
  }
  for (const { address } of addrs) {
    if (isPrivateIp(address)) {
      throw new SsrfError(`Host ${host} resolves to a private/internal address (${address})`);
    }
  }
}

/**
 * Fetch with per-hop SSRF validation, returning the native `Response`.
 *
 * Replaces `redirect:"follow"` at web_fetch call sites. Each redirect is
 * tracked manually; the Location target is validated (literal + DNS) before
 * it is followed. This closes the redirect-chain bypass: a public URL that
 * 302s to http://169.254.169.254 is refused after the first hop.
 *
 * Throws SsrfError with a message starting "refused:" for any SSRF rejection;
 * callers should surface this message verbatim (Honest Response principle).
 */
export async function fetchWithSsrfProtection(
  url: string,
  init: RequestInit = {},
): Promise<Response> {
  // Validate the initial URL before touching the network
  if (isPrivateUrl(url)) {
    throw new SsrfError(`refused: resolves to a private/loopback/link-local address (${url})`);
  }

  let current = url;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    await assertHopResolvesPublic(current, hop === 0 ? "URL" : "redirect target");
    const response = await fetch(current, { ...init, redirect: "manual" });

    if (response.status >= 300 && response.status < 400) {
      if (hop === MAX_REDIRECTS) {
        throw new SsrfError(`refused: too many redirects (max ${MAX_REDIRECTS})`);
      }

      const location = response.headers.get("location");
      if (!location) {
        // 3xx with no Location — return as-is rather than looping
        return response;
      }

      let next: string;
      try {
        next = new URL(location, current).href;
      } catch {
        throw new SsrfError(`refused: redirect to malformed Location header (${location})`);
      }

      if (isPrivateUrl(next)) {
        throw new SsrfError(`refused: redirect target resolves to a private/loopback/link-local address (${next})`);
      }

      // Free the socket of the body we're abandoning. Best-effort cleanup — a
      // failure here has no effect on correctness, so the swallow is intentional.
      await response.body?.cancel().catch(() => {});

      current = next;
      continue;
    }

    return response;
  }

  // Unreachable — loop exits via return or throw — but TypeScript requires it
  throw new SsrfError(`refused: too many redirects (max ${MAX_REDIRECTS})`);
}

/** DNS-resolve a hop and rethrow SSRF rejections in the "refused:" contract. */
async function assertHopResolvesPublic(url: string, what: string): Promise<void> {
  try {
    await assertUrlAllowed(url);
  } catch (err) {
    if (err instanceof SsrfError) {
      throw new SsrfError(`refused: ${what} resolves to a private/loopback/link-local address (${url})`);
    }
    throw err;
  }
}

export interface SafeFetchOptions {
  /** Max redirects to follow (default 10). */
  maxRedirects?: number;
  /** Max response bytes to read (default MAX_FETCH_BYTES). */
  maxBytes?: number;
}

export interface SafeFetchResult {
  status: number;
  ok: boolean;
  headers: Headers;
  /** Final URL after redirects. */
  url: string;
  text: () => Promise<string>;
  arrayBuffer: () => Promise<ArrayBuffer>;
}

/**
 * SSRF-safe fetch: validates DNS-resolved IPs, follows redirects manually while
 * re-validating each hop, and caps the body it will read into memory.
 *
 * Drop-in for the `fetch` calls that take a user- or LLM-supplied URL. Pass the
 * usual init (method/headers/signal); `redirect` is handled internally.
 */
export async function safeFetch(
  rawUrl: string,
  init: RequestInit = {},
  opts: SafeFetchOptions = {},
): Promise<SafeFetchResult> {
  const maxRedirects = opts.maxRedirects ?? MAX_REDIRECTS;
  const maxBytes = opts.maxBytes ?? MAX_FETCH_BYTES;
  const signal = init.signal ?? AbortSignal.timeout(FETCH_TIMEOUT);

  let current = rawUrl;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    await assertUrlAllowed(current);

    const res = await fetch(current, { ...init, redirect: "manual", signal });

    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get("location");
      if (location) {
        // Free the socket before following. Cancelling a body we're abandoning
        // is best-effort cleanup — a failure here has no effect on correctness,
        // so the swallow is intentional, not a hidden assumption.
        await res.body?.cancel().catch(() => {});
        current = new URL(location, current).href;
        continue;
      }
    }

    const finalUrl = current;
    return {
      status: res.status,
      ok: res.ok,
      headers: res.headers,
      url: finalUrl,
      // Read through the byte cap when a streaming body is present (always true
      // for a real fetch Response); fall back to the native reader otherwise.
      text: async () => (res.body ? decodeText(await readCapped(res, maxBytes)) : res.text()),
      arrayBuffer: async () => {
        if (!res.body) return res.arrayBuffer();
        const buf = await readCapped(res, maxBytes);
        // Slice by byteOffset/byteLength, not buf.buffer wholesale: Buffer.concat
        // can hand back a view into the shared allocation pool, so the backing
        // ArrayBuffer may contain other buffers' bytes outside this range.
        return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
      },
    };
  }
  throw new SsrfError(`Too many redirects (>${maxRedirects}) for ${rawUrl}`);
}

/** Read a response body, aborting if it exceeds maxBytes. */
async function readCapped(res: Response, maxBytes: number): Promise<Buffer> {
  if (!res.body) return Buffer.alloc(0);
  const reader = res.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      // Best-effort cancel of the stream we're abandoning — the throw below is
      // the real signal; a cancel failure can't change that.
      await reader.cancel().catch(() => {});
      throw new Error(`Response exceeded max size (${maxBytes} bytes)`);
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

function decodeText(buf: Buffer): string {
  return buf.toString("utf-8");
}
