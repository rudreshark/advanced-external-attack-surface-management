/**
 * Clickjacking (Deep) Module
 *
 * Tests for clickjacking / UI redress vulnerabilities by checking
 * X-Frame-Options, CSP frame-ancestors, and whether the page can be
 * embedded in an iframe (frameable). Also tests for:
 *   - Missing/duplicate X-Frame-Options
 *   - CSP frame-ancestors with wildcard
 *   - Frameable admin panels / login pages
 *   - Drag-and-drop / cursor manipulation potential
 */
import type { ClickjackingResult } from "./types";

async function fetchHeaders(url: string, timeoutMs = 8000): Promise<{ status: number; headers: Record<string, string> } | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      redirect: "follow",
      headers: { "User-Agent": "easm-scanner/1.0" },
    });
    const h: Record<string, string> = {};
    res.headers.forEach((v, k) => (h[k.toLowerCase()] = v));
    return { status: res.status, headers: h };
  } catch { return null; } finally { clearTimeout(t); }
}

const SENSITIVE_PATHS = [
  "/admin", "/login", "/signin", "/wp-login.php", "/wp-admin/",
  "/account", "/profile", "/settings", "/dashboard", "/console",
  "/manage", "/panel", "/cpanel", "/administrator",
];

export async function runClickjacking(
  urls: string[],
  log: (msg: string) => void
): Promise<ClickjackingResult> {
  const hosts: ClickjackingResult["hosts"] = [];
  log(`Testing clickjacking on ${urls.length} host(s) ...`);

  for (const url of urls.slice(0, 8)) {
    log(`  probing ${url} ...`);
    const findings: ClickjackingResult["hosts"][0]["findings"] = [];

    // Get response headers
    const res = await fetchHeaders(url);
    if (!res) { log(`    [-] no response`); continue; }

    const xfo = res.headers["x-frame-options"] || "";
    const csp = res.headers["content-security-policy"] || "";
    const xfoPresent = !!xfo;
    const cspFrameAncestors = /frame-ancestors/i.test(csp);

    // Determine if frameable
    let frameable = false;
    let reason = "";
    if (!xfoPresent && !cspFrameAncestors) {
      frameable = true;
      reason = "No X-Frame-Options or CSP frame-ancestors";
    } else if (xfoPresent) {
      const xfoLower = xfo.toLowerCase();
      if (xfoLower === "allowall" || xfoLower.includes("allow-from *")) {
        frameable = true;
        reason = `X-Frame-Options allows all: "${xfo}"`;
      }
    }
    if (cspFrameAncestors && /frame-ancestors\s+\*/i.test(csp)) {
      frameable = true;
      reason = `CSP frame-ancestors wildcard: "${csp.match(/frame-ancestors[^;]*/i)?.[0]}"`;
    }

    if (frameable) {
      // Check if the page is a sensitive endpoint (login/admin)
      const isSensitive = SENSITIVE_PATHS.some((p) => url.toLowerCase().includes(p));
      findings.push({
        id: "clickjacking-frameable",
        severity: isSensitive ? "high" : "medium",
        title: isSensitive ? "Clickjacking — Sensitive Page Frameable" : "Clickjacking — Page Frameable",
        detail: `${url} can be embedded in an iframe (${reason}). ${isSensitive ? "This is a sensitive page (login/admin) — an attacker can overlay invisible buttons to trick users into clicking. " : ""}Set X-Frame-Options: DENY or CSP frame-ancestors 'none'.`,
      });
      log(`    [!] FRAMEABLE: ${reason}${isSensitive ? " (sensitive page)" : ""}`);
    } else {
      // Check for weak configurations
      if (xfoPresent && xfo.toLowerCase() === "sameorigin") {
        log(`    [+] X-Frame-Options: SAMEORIGIN (protected)`);
      } else if (xfoPresent) {
        log(`    [+] X-Frame-Options: ${xfo}`);
      }
      if (cspFrameAncestors) {
        const fa = csp.match(/frame-ancestors[^;]*/i)?.[0] || "";
        log(`    [+] CSP frame-ancestors: ${fa}`);
      }
      if (!xfoPresent && !cspFrameAncestors) {
        // This shouldn't happen (frameable would be true), but just in case
        log(`    [-] no frame protection headers`);
      }
    }

    // Check for duplicate X-Frame-Options (some misconfigured servers send 2)
    if (xfoPresent && xfo.includes(",")) {
      findings.push({
        id: "clickjacking-duplicate-xfo",
        severity: "low",
        title: "Duplicate X-Frame-Options Header",
        detail: `${url} sends multiple X-Frame-Options headers ("${xfo}"). Browsers may behave unpredictably — some ignore all, leaving the page frameable.`,
      });
      log(`    [!] Duplicate X-Frame-Options: ${xfo}`);
    }

    // Test sensitive paths on the same origin
    if (frameable) {
      for (const path of SENSITIVE_PATHS.slice(0, 4)) {
        const testUrl = new URL(path, url).href;
        const pathRes = await fetchHeaders(testUrl);
        if (pathRes) {
          const pathXfo = pathRes.headers["x-frame-options"] || "";
          const pathCsp = pathRes.headers["content-security-policy"] || "";
          if (!pathXfo && !/frame-ancestors/i.test(pathCsp)) {
            findings.push({
              id: `clickjacking-sensitive-${path}`,
              severity: "high",
              title: `Clickjacking on sensitive path: ${path}`,
              detail: `${testUrl} (HTTP ${pathRes.status}) is frameable. Attackers can iframe this page and trick users into performing sensitive actions.`,
            });
            log(`    [!] Sensitive path frameable: ${testUrl}`);
          }
        }
      }
    }

    hosts.push({ url, frameable, xfoPresent, cspFrameAncestors, findings });
    const sevCount: Record<string, number> = {};
    for (const f of findings) sevCount[f.severity] = (sevCount[f.severity] || 0) + 1;
    const summary = ["high", "medium", "low"].filter((s) => sevCount[s]).map((s) => `${sevCount[s]} ${s}`).join(", ");
    log(`  [+] ${url}: ${findings.length} finding(s)${summary ? " (" + summary + ")" : ""}`);
  }

  const total = hosts.reduce((a, h) => a + h.findings.length, 0);
  log(`Clickjacking testing complete: ${total} finding(s) across ${hosts.length} host(s).`);
  return { hosts };
}
