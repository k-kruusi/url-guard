import { describe, it, expect, vi, afterEach } from "vitest";
import { isPrivateIp, isPrivateUrl, fetchWithSsrfProtection, safeFetch, SsrfError } from "../index.js";

// ── isPrivateUrl ──────────────────────────────────────────────────────────────

describe("isPrivateUrl — existing cases", () => {
  it("blocks localhost", () => {
    expect(isPrivateUrl("http://localhost")).toBe(true);
    expect(isPrivateUrl("http://localhost:3000")).toBe(true);
  });

  it("blocks 127.x.x.x", () => {
    expect(isPrivateUrl("http://127.0.0.1")).toBe(true);
    expect(isPrivateUrl("http://127.1.2.3")).toBe(true);
    expect(isPrivateUrl("http://127.255.255.255")).toBe(true);
  });

  it("blocks RFC 1918 private ranges", () => {
    expect(isPrivateUrl("http://10.0.0.1")).toBe(true);
    expect(isPrivateUrl("http://172.16.0.1")).toBe(true);
    expect(isPrivateUrl("http://172.31.255.255")).toBe(true);
    expect(isPrivateUrl("http://192.168.1.1")).toBe(true);
  });

  it("blocks link-local / AWS metadata endpoint", () => {
    expect(isPrivateUrl("http://169.254.169.254/latest/meta-data/")).toBe(true);
    expect(isPrivateUrl("http://169.254.0.1/")).toBe(true);
  });

  it("blocks IPv6 loopback", () => {
    expect(isPrivateUrl("http://[::1]")).toBe(true);
    expect(isPrivateUrl("http://[::1]:8080")).toBe(true);
  });

  it("blocks IPv6 unique-local (fc00::/7)", () => {
    expect(isPrivateUrl("http://[fc00::1]")).toBe(true);
    expect(isPrivateUrl("http://[fd00::1]")).toBe(true);
  });

  it("allows public URLs", () => {
    expect(isPrivateUrl("https://example.com")).toBe(false);
    expect(isPrivateUrl("https://github.com/mozilla/readability")).toBe(false);
    expect(isPrivateUrl("https://8.8.8.8")).toBe(false);
    expect(isPrivateUrl("https://1.1.1.1")).toBe(false);
  });

  it("blocks unparseable URLs", () => {
    expect(isPrivateUrl("not-a-url")).toBe(true);
    expect(isPrivateUrl("")).toBe(true);
  });
});

describe("isPrivateUrl — IPv4-mapped IPv6 bypass (finding #3)", () => {
  // The WHATWG URL parser normalises ::ffff:127.0.0.1 → ::ffff:7f00:1 in the
  // hostname, so both forms appear in practice and both must be blocked.

  it("blocks ::ffff:127.0.0.1 (hex-normalised form after URL parsing)", () => {
    // WHATWG normalises [::ffff:127.0.0.1] → [::ffff:7f00:1]
    expect(isPrivateUrl("http://[::ffff:127.0.0.1]/")).toBe(true);
    // Verify the normalised hex form is also blocked
    expect(isPrivateUrl("http://[::ffff:7f00:1]/")).toBe(true);
  });

  it("blocks ::ffff:169.254.169.254 (AWS metadata via IPv4-mapped IPv6)", () => {
    expect(isPrivateUrl("http://[::ffff:169.254.169.254]/")).toBe(true);
    // Normalised: 169*256+254 = 43518 = 0xa9fe
    expect(isPrivateUrl("http://[::ffff:a9fe:a9fe]/")).toBe(true);
  });

  it("blocks ::ffff: addresses for all private IPv4 ranges", () => {
    // 10.0.0.1
    expect(isPrivateUrl("http://[::ffff:a00:1]/")).toBe(true);
    // 192.168.1.1 → c0a8:101
    expect(isPrivateUrl("http://[::ffff:c0a8:101]/")).toBe(true);
    // 172.16.0.1 → ac10:1
    expect(isPrivateUrl("http://[::ffff:ac10:1]/")).toBe(true);
  });

  it("allows ::ffff: addresses for public IPv4", () => {
    // 8.8.8.8 → 0808:0808
    expect(isPrivateUrl("http://[::ffff:808:808]/")).toBe(false);
    // 1.1.1.1 → 0101:0101
    expect(isPrivateUrl("http://[::ffff:101:101]/")).toBe(false);
  });
});

describe("isPrivateUrl — decimal / alternate IPv4 notation (finding #3 part 2)", () => {
  // WHATWG URL normalises these to dotted-quad — the existing check covers them
  // once the URL parser has run. Verify this is still true.

  it("blocks decimal IPv4 (2130706433 = 127.0.0.1)", () => {
    // new URL("http://2130706433/").hostname === "127.0.0.1" per WHATWG spec
    expect(isPrivateUrl("http://2130706433/")).toBe(true);
  });

  it("blocks decimal IPv4 for metadata endpoint (2852039166 = 169.254.169.254)", () => {
    // 169*16777216 + 254*65536 + 169*256 + 254 = 2852039166
    expect(isPrivateUrl("http://2852039166/")).toBe(true);
  });
});

describe("isPrivateUrl — IPv6 link-local (fe80::/10)", () => {
  it("blocks IPv6 link-local addresses", () => {
    expect(isPrivateUrl("http://[fe80::1]")).toBe(true);
    expect(isPrivateUrl("http://[fe80::1%25eth0]")).toBe(true);
    expect(isPrivateUrl("http://[fe8f::1]")).toBe(true);
    expect(isPrivateUrl("http://[feb0::1]")).toBe(true);
  });
});

describe("isPrivateUrl — regression: IPv6 prefix checks now gated on actual IPv6", () => {
  // Before fix: domains starting with fc/fd/fe[89ab] were wrongly blocked.
  // After fix: only actual IPv6 addresses (containing ':') are checked for these prefixes.

  it("allows legitimate domains matching fc/fd prefix (regression)", () => {
    // fc2.com - major Japanese host
    expect(isPrivateUrl("http://fc2.com/")).toBe(false);
    // fdn.com - real French ISP
    expect(isPrivateUrl("http://fdn.com/")).toBe(false);
    // feba.com
    expect(isPrivateUrl("http://feba.com/")).toBe(false);
    // facebook.com (starts with fe)
    expect(isPrivateUrl("https://facebook.com/")).toBe(false);
  });

  it("still blocks real IPv6 unique-local (fc/fd) addresses", () => {
    // Gate is `:` presence, so bracketed IPv6 addresses (which contain ':') are still blocked
    expect(isPrivateUrl("http://[fc00::1]/")).toBe(true);
    expect(isPrivateUrl("http://[fd12:3456::1]/")).toBe(true);
  });

  it("still blocks real IPv6 link-local (fe80::/10) addresses", () => {
    expect(isPrivateUrl("http://[fe80::1]/")).toBe(true);
    expect(isPrivateUrl("http://[fe89::1]/")).toBe(true);
    expect(isPrivateUrl("http://[fe8f::1]/")).toBe(true);
    expect(isPrivateUrl("http://[feb0::1]/")).toBe(true);
  });

  it("still blocks all existing exploit forms (unchanged)", () => {
    // IPv4-mapped IPv6 loopback
    expect(isPrivateUrl("http://[::ffff:127.0.0.1]/")).toBe(true);
    // IPv4-mapped IPv6 metadata
    expect(isPrivateUrl("http://[::ffff:169.254.169.254]/")).toBe(true);
    // Decimal IPv4 loopback
    expect(isPrivateUrl("http://2130706433/")).toBe(true);
    // Hex IPv4 loopback
    expect(isPrivateUrl("http://0x7f000001/")).toBe(true);
    // Dotted-quad loopback
    expect(isPrivateUrl("http://127.0.0.1/")).toBe(true);
    // RFC 1918
    expect(isPrivateUrl("http://10.0.0.1/")).toBe(true);
  });
});

// ── Cases hoisted with the web-fetch-server implementation (PR #455) ──────────

describe("isPrivateIp", () => {
  it("blocks IPv4 loopback / private / link-local / CGNAT ranges", () => {
    for (const ip of ["127.0.0.1", "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "0.0.0.0", "100.64.0.1"]) {
      expect(isPrivateIp(ip), ip).toBe(true);
    }
  });

  it("allows public IPv4", () => {
    for (const ip of ["8.8.8.8", "1.1.1.1", "172.32.0.1", "192.169.0.1", "93.184.216.34"]) {
      expect(isPrivateIp(ip), ip).toBe(false);
    }
  });

  it("blocks IPv6 loopback / link-local / ULA, including expanded forms", () => {
    for (const ip of ["::1", "::", "0:0:0:0:0:0:0:1", "fe80::1", "fe80::1%eth0", "fc00::1", "fd12:3456::1"]) {
      expect(isPrivateIp(ip), ip).toBe(true);
    }
  });

  it("blocks IPv4-mapped IPv6 pointing at private addresses", () => {
    for (const ip of ["::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1", "::ffff:a9fe:a9fe"]) {
      expect(isPrivateIp(ip), ip).toBe(true);
    }
  });

  it("allows public IPv6", () => {
    expect(isPrivateIp("2606:4700:4700::1111")).toBe(false);
  });
});

describe("isPrivateUrl — internal hostnames and integer encodings", () => {
  it("blocks internal hostnames including the cloud metadata server", () => {
    for (const url of [
      "http://localhost/",
      "http://foo.localhost/",
      "http://metadata.google.internal/computeMetadata/v1/",
      "http://metadata/",
    ]) {
      expect(isPrivateUrl(url), url).toBe(true);
    }
  });

  it("blocks expanded-IPv6 URL hosts (WHATWG canonicalizes before our check)", () => {
    expect(isPrivateUrl("http://[0:0:0:0:0:ffff:169.254.169.254]/")).toBe(true);
    expect(isPrivateUrl("http://[0:0:0:0:0:0:0:1]/")).toBe(true);
  });

  it("blocks CGNAT and reserved IPv4 ranges", () => {
    expect(isPrivateUrl("http://100.64.0.1/")).toBe(true);
    expect(isPrivateUrl("http://198.18.0.1/")).toBe(true);
    expect(isPrivateUrl("http://224.0.0.1/")).toBe(true);
  });
});

// ── safeFetch (byte-capped variant) ───────────────────────────────────────────

describe("safeFetch — per-hop redirect revalidation", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("rejects initial request to a private URL without hitting the network", async () => {
    const spy = vi.spyOn(global, "fetch");
    await expect(safeFetch("http://169.254.169.254/latest/meta-data/")).rejects.toBeInstanceOf(SsrfError);
    expect(spy).not.toHaveBeenCalled();
  });

  it("blocks a 3xx redirect whose Location is loopback", async () => {
    vi.spyOn(global, "fetch").mockResolvedValueOnce(
      new Response(null, { status: 302, headers: { location: "http://127.0.0.1/" } }),
    );
    await expect(safeFetch("https://example.com/redirect")).rejects.toBeInstanceOf(SsrfError);
  });

  it("follows a benign redirect and returns the final body", async () => {
    vi.spyOn(global, "fetch")
      .mockResolvedValueOnce(
        new Response(null, { status: 302, headers: { location: "https://example.com/final" } }),
      )
      .mockResolvedValueOnce(new Response("ok", { status: 200 }));

    const res = await safeFetch("https://example.com/");
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("ok");
  });
});

// ── fetchWithSsrfProtection ───────────────────────────────────────────────────

describe("fetchWithSsrfProtection — redirect bypass (finding #2)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("rejects initial request to private URL without hitting the network", async () => {
    const spy = vi.spyOn(global, "fetch");
    await expect(
      fetchWithSsrfProtection("http://127.0.0.1/"),
    ).rejects.toThrow(/refused.*private/);
    expect(spy).not.toHaveBeenCalled();
  });

  it("blocks 3xx redirect whose Location is http://127.0.0.1/", async () => {
    vi.spyOn(global, "fetch").mockResolvedValueOnce(
      new Response(null, {
        status: 302,
        headers: { location: "http://127.0.0.1/" },
      }),
    );
    await expect(
      fetchWithSsrfProtection("https://example.com/redirect"),
    ).rejects.toThrow(/refused.*redirect.*private/);
  });

  it("blocks 3xx redirect whose Location is http://169.254.169.254/", async () => {
    vi.spyOn(global, "fetch").mockResolvedValueOnce(
      new Response(null, {
        status: 301,
        headers: { location: "http://169.254.169.254/latest/meta-data/" },
      }),
    );
    await expect(
      fetchWithSsrfProtection("https://example.com/"),
    ).rejects.toThrow(/refused.*redirect.*private/);
  });

  it("follows a benign redirect and returns the final response", async () => {
    const finalResponse = new Response("ok", { status: 200 });
    vi.spyOn(global, "fetch")
      .mockResolvedValueOnce(
        new Response(null, {
          status: 302,
          headers: { location: "https://example.com/final" },
        }),
      )
      .mockResolvedValueOnce(finalResponse);

    const res = await fetchWithSsrfProtection("https://example.com/");
    expect(res.status).toBe(200);
  });

  it("allows a legitimate external URL directly (no mocking)", async () => {
    // Smoke test: a real public URL should not throw SSRF errors
    // (network may be unavailable in CI — only check it doesn't throw SSRF)
    try {
      await fetchWithSsrfProtection("https://example.com/");
    } catch (err: any) {
      // Network errors are fine; SSRF rejections are not
      expect(err.message).not.toMatch(/^refused:/);
    }
  });

  it("throws on too many redirects", async () => {
    // Always return a redirect to the same public URL
    vi.spyOn(global, "fetch").mockResolvedValue(
      new Response(null, {
        status: 302,
        headers: { location: "https://example.com/loop" },
      }),
    );
    await expect(
      fetchWithSsrfProtection("https://example.com/loop"),
    ).rejects.toThrow(/refused.*too many redirects/);
  });
});
