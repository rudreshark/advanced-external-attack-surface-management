/**
 * Race Condition Module
 *
 * Tests for race conditions (TOCTOU) by sending concurrent requests
 * to endpoints that perform state-changing operations. Detection is
 * based on response differences when multiple requests hit the same
 * endpoint simultaneously.
 *
 * Common vulnerable patterns:
 *   - Coupon/voucher code applied N times (double-spend)
 *   - Withdrawal endpoint (double-spend)
 *   - Like/vote endpoint (multiple counts)
 *   - Account creation (duplicate accounts)
 *   - Email change (confirm to old + new)
 */
import type { RaceResult } from "./types";

async function fetchOne(
  url: string,
  method: string = "POST",
  body?: string,
  timeoutMs = 8000
): Promise<{ status: number; body: string; headers: Record<string, string> }> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method,
      signal: ctrl.signal,
      redirect: "manual",
      body: body && method !== "GET" ? body : undefined,
      headers: { "User-Agent": "easm-scanner/1.0", ...(body && method !== "GET" ? { "Content-Type": "application/x-www-form-urlencoded" } : {}) },
    });
    let b = "";
    try { b = await res.text(); } catch { /* ignore */ }
    const h: Record<string, string> = {};
    res.headers.forEach((v, k) => (h[k.toLowerCase()] = v));
    return { status: res.status, body: b.slice(0, 20000), headers: h };
  } catch {
    return { status: 0, body: "", headers: {} };
  } finally { clearTimeout(t); }
}

// Common endpoints that may have race conditions
const RACE_ENDPOINTS = [
  { path: "/api/v1/coupon", method: "POST", body: "code=TEST&easm=true", note: "Coupon/voucher application" },
  { path: "/api/coupon", method: "POST", body: "code=TEST&easm=true", note: "Coupon application" },
  { path: "/api/like", method: "POST", body: "id=1&easm=true", note: "Like/vote endpoint" },
  { path: "/api/vote", method: "POST", body: "id=1&easm=true", note: "Voting endpoint" },
  { path: "/api/withdraw", method: "POST", body: "amount=1&easm=true", note: "Withdrawal endpoint" },
  { path: "/api/transfer", method: "POST", body: "amount=1&to=test&easm=true", note: "Transfer endpoint" },
  { path: "/api/profile", method: "POST", body: "email=test@test.com&easm=true", note: "Profile update" },
  { path: "/api/password", method: "POST", body: "old=test&new=test&easm=true", note: "Password change" },
  { path: "/api/email/change", method: "POST", body: "email=test@test.com&easm=true", note: "Email change" },
  { path: "/api/v1/withdraw", method: "POST", body: "amount=1&easm=true", note: "Withdrawal v1" },
  { path: "/coupon/apply", method: "POST", body: "code=TEST&easm=true", note: "Coupon apply" },
  { path: "/vote", method: "POST", body: "id=1&easm=true", note: "Vote" },
  { path: "/like", method: "POST", body: "id=1&easm=true", note: "Like" },
  { path: "/cart/add", method: "POST", body: "id=1&qty=1&easm=true", note: "Cart add" },
  { path: "/api/cart/add", method: "POST", body: "id=1&qty=1&easm=true", note: "Cart add API" },
  { path: "/api/gift", method: "POST", body: "id=1&easm=true", note: "Gift endpoint" },
  { path: "/api/redeem", method: "POST", body: "code=TEST&easm=true", note: "Redeem endpoint" },
  { path: "/api/invite", method: "POST", body: "email=test@test.com&easm=true", note: "Invite endpoint" },
];

const CONCURRENT_COUNT = 10;

export async function runRace(
  urls: string[],
  log: (msg: string) => void
): Promise<RaceResult> {
  const hosts: RaceResult["hosts"] = [];
  log(`Testing race conditions on ${urls.length} host(s) ...`);

  for (const url of urls.slice(0, 3)) {
    log(`  probing ${url} for race-condition-prone endpoints ...`);
    const endpoints: RaceResult["hosts"][0]["endpoints"] = [];
    const findings: RaceResult["hosts"][0]["findings"] = [];
    const base = new URL(url);
    let tested = 0;

    for (const ep of RACE_ENDPOINTS) {
      const testUrl = new URL(ep.path, base).href;
      tested++;
      if (tested % 5 === 0) log(`    ... tested ${tested}/${RACE_ENDPOINTS.length} endpoints`);

      // First, send a single request to check if the endpoint exists
      const single = await fetchOne(testUrl, ep.method, ep.body);
      if (single.status === 0 || single.status === 404 || single.status === 405) continue;

      // Endpoint exists — send CONCURRENT_COUNT requests simultaneously
      log(`    [~] testing ${ep.path} (${ep.method}) with ${CONCURRENT_COUNT} concurrent requests ...`);
      const promises: Promise<typeof single>[] = [];
      for (let i = 0; i < CONCURRENT_COUNT; i++) {
        promises.push(fetchOne(testUrl, ep.method, ep.body));
      }
      const responses = await Promise.all(promises);

      // Analyze responses for race condition evidence:
      // 1. Multiple 200 OK responses (vs single baseline) — possible double-spend
      // 2. Different response bodies (state divergence)
      // 3. Different status codes
      // 4. Error on some but not all (partial processing)
      const okCount = responses.filter((r) => r.status >= 200 && r.status < 300).length;
      const errorCount = responses.filter((r) => r.status >= 400).length;
      const uniqueBodies = new Set(responses.map((r) => r.body.slice(0, 500))).size;
      const uniqueStatuses = new Set(responses.map((r) => r.status)).size;

      const responseDiff = uniqueBodies > 1 || uniqueStatuses > 1;
      const possibleDoubleSpend = okCount > 1 && ep.note.toLowerCase().includes("coupon") || ep.note.toLowerCase().includes("withdraw") || ep.note.toLowerCase().includes("transfer") || ep.note.toLowerCase().includes("gift") || ep.note.toLowerCase().includes("redeem");

      if (okCount > 1 && (responseDiff || possibleDoubleSpend)) {
        const evidence = `${okCount}/${CONCURRENT_COUNT} OK, ${uniqueStatuses} unique statuses, ${uniqueBodies} unique bodies`;
        endpoints.push({
          url: testUrl,
          method: ep.method,
          concurrentRequests: CONCURRENT_COUNT,
          responseDiff,
          evidence,
        });
        findings.push({
          id: `race-${ep.path}`,
          severity: possibleDoubleSpend ? "high" : "medium",
          title: `Race condition on ${ep.note} (${ep.path})`,
          detail: `${testUrl} accepted ${okCount} concurrent ${ep.method} requests. ${responseDiff ? "Responses differ between concurrent requests — state may not be atomic. " : ""}${possibleDoubleSpend ? "This endpoint handles value transfer — a race condition enables double-spending." : ""} Evidence: ${evidence}.`,
        });
        log(`    [!] RACE CONDITION: ${ep.path} — ${evidence}`);
      } else if (okCount >= 1) {
        log(`    [-] ${ep.path}: ${okCount} OK / ${CONCURRENT_COUNT} (no race condition)`);
      }
    }

    hosts.push({ url, endpoints, findings });
    const sevCount: Record<string, number> = {};
    for (const f of findings) sevCount[f.severity] = (sevCount[f.severity] || 0) + 1;
    const summary = ["high", "medium", "low"].filter((s) => sevCount[s]).map((s) => `${sevCount[s]} ${s}`).join(", ");
    log(`  [+] ${url}: ${endpoints.length} race point(s)${summary ? " (" + summary + ")" : ""}`);
  }

  const total = hosts.reduce((a, h) => a + h.endpoints.length, 0);
  log(`Race condition testing complete: ${total} point(s) across ${hosts.length} host(s).`);
  return { hosts };
}
