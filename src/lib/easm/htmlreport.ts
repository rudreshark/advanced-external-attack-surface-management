/**
 * HTML Report Generator for EXENOM
 *
 * Generates a standalone, downloadable HTML report from scan results.
 * The report is self-contained (inline CSS, no external dependencies)
 * and can be opened in any browser or shared.
 */

export function generateHtmlReport(results: any, summary: any): string {
  const target = summary?.target || 'unknown';
  const duration = summary?.durationMs ? (summary.durationMs / 1000).toFixed(2) : '?';
  const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const modules = summary?.modulesRan || [];

  // ── Helper: severity badge ────────────────────────────────────────────
  const sevBadge = (sev: string): string => {
    const colors: Record<string, string> = {
      high: '#dc2626', medium: '#d97706', low: '#0891b2', info: '#6b7280',
    };
    const c = colors[sev?.toLowerCase()] || '#6b7280';
    return `<span class="badge" style="background:${c}">${sev?.toUpperCase() || 'INFO'}</span>`;
  };

  // ── Helper: escape HTML ───────────────────────────────────────────────
  const esc = (s: any): string => String(s ?? '').replace(/[<>&"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[c]!));

  // ── Helper: render a findings table for a host-based result ───────────
  const renderHostFindings = (hosts: any[], moduleName: string): string => {
    if (!hosts?.length) return '';
    const totalFindings = hosts.reduce((a, h) => a + (h.findings?.length || 0), 0);
    if (totalFindings === 0) return '';
    let html = `<div class="module-section"><h3>${esc(moduleName)} <span class="count">${totalFindings} finding(s)</span></h3>`;
    for (const h of hosts) {
      if (!h.findings?.length) continue;
      html += `<div class="host"><div class="host-url">${esc(h.url || h.host || '')}</div>`;
      html += '<table class="findings-table"><thead><tr><th>Severity</th><th>Title</th><th>Detail</th></tr></thead><tbody>';
      for (const f of h.findings) {
        html += `<tr><td>${sevBadge(f.severity)}</td><td>${esc(f.title)}</td><td>${esc(f.detail)}</td></tr>`;
      }
      html += '</tbody></table></div>';
    }
    return html + '</div>';
  };

  // ── Helper: render a simple list table ────────────────────────────────
  const renderListTable = (items: any[], headers: string[], moduleName: string): string => {
    if (!items?.length) return '';
    let html = `<div class="module-section"><h3>${esc(moduleName)} <span class="count">${items.length} item(s)</span></h3>`;
    html += '<table class="data-table"><thead><tr>';
    for (const h of headers) html += `<th>${esc(h)}</th>`;
    html += '</tr></thead><tbody>';
    for (const item of items.slice(0, 50)) {
      html += '<tr>';
      for (const h of headers) {
        const val = typeof item === 'object' ? (item[h] ?? item[h.toLowerCase()] ?? '') : item;
        html += `<td>${esc(val)}</td>`;
      }
      html += '</tr>';
    }
    html += '</tbody></table></div>';
    return html;
  };

  // ── Build report sections ─────────────────────────────────────────────
  let sections = '';

  // DNS
  if (results.dns?.records?.length) {
    sections += renderListTable(results.dns.records.map((r: any) => ({ type: r.type, name: r.name, value: r.value })), ['type', 'name', 'value'], 'DNS Records');
  }

  // Subdomains
  if (results.subdomains?.subdomains?.length) {
    sections += renderListTable(results.subdomains.subdomains.map((s: any) => ({ hostname: s.hostname, ip: s.ip, source: s.source })), ['hostname', 'ip', 'source'], 'Subdomains');
  }

  // Ports
  if (results.ports?.ports?.length) {
    sections += renderListTable(results.ports.ports.map((p: any) => ({ port: p.port, protocol: p.protocol || 'tcp', service: p.service, state: p.state, banner: (p.banner || '').slice(0, 60) })), ['port', 'protocol', 'service', 'state', 'banner'], 'Open Ports');
    if (results.ports.osGuess?.os) {
      sections += `<div class="module-section"><h3>OS Fingerprint</h3><p><strong>OS:</strong> ${esc(results.ports.osGuess.os)} <span class="muted">(confidence: ${esc(results.ports.osGuess.confidence)})</span></p></div>`;
    }
  }

  // HTTP
  if (results.http?.hosts?.length) {
    sections += renderListTable(results.http.hosts.map((h: any) => ({ url: h.url, status: h.status, title: h.title, server: h.server })), ['url', 'status', 'title', 'server'], 'HTTP Services');
  }

  // TLS
  if (results.tls?.certs?.length) {
    sections += `<div class="module-section"><h3>TLS Certificates <span class="count">${results.tls.certs.length}</span></h3>`;
    for (const c of results.tls.certs) {
      sections += `<div class="host"><div class="host-url">${esc(c.host)}</div>
        <p><strong>Subject:</strong> ${esc(c.subject)}<br><strong>Issuer:</strong> ${esc(c.issuer)}<br>
        <strong>Expires:</strong> ${esc(c.validTo)} (${c.daysRemaining} days) ${c.selfSigned ? '<span class="badge" style="background:#dc2626">SELF-SIGNED</span>' : ''}</p></div>`;
    }
    sections += '</div>';
  }

  // Technologies
  if (results.tech?.hosts?.length) {
    sections += `<div class="module-section"><h3>Technologies</h3>`;
    for (const h of results.tech.hosts) {
      if (h.technologies?.length) {
        sections += `<div class="host"><div class="host-url">${esc(h.url)}</div><p>${h.technologies.map((t: any) => `<span class="tech-badge">${esc(t.name)}</span>`).join(' ')}</p></div>`;
      }
    }
    sections += '</div>';
  }

  // Vulnerabilities
  if (results.vulns) {
    sections += renderHostFindings(results.vulns.hosts, 'Vulnerabilities');
  }

  // Firewall / WAF
  if (results.firewall?.hosts?.length) {
    sections += `<div class="module-section"><h3>Firewall / WAF Detection</h3>`;
    for (const h of results.firewall.hosts) {
      sections += `<div class="host"><div class="host-url">${esc(h.url)}</div>`;
      if (h.detected?.length) {
        sections += '<p><strong>WAFs detected:</strong> ' + h.detected.map((d: any) => `<span class="badge" style="background:#dc2626">${esc(d.name)}</span>`).join(' ') + '</p>';
      }
      if (h.blockStatus) sections += `<p><strong>Block status:</strong> HTTP ${h.blockStatus}</p>`;
      sections += '</div>';
    }
    if (results.firewall.bypassPayloads?.length) {
      const totalPayloads = results.firewall.bypassPayloads.reduce((a: number, p: any) => a + p.payloads.length, 0);
      sections += `<p class="info"><strong>WAF-bypass payloads generated:</strong> ${totalPayloads} across ${results.firewall.bypassPayloads.length} sets</p>`;
    }
    sections += '</div>';
  }

  // Email Security
  if (results.emailsec) {
    const e = results.emailsec;
    sections += `<div class="module-section"><h3>Email Security</h3>`;
    sections += `<p><strong>SPF:</strong> ${e.spf?.present ? esc(e.spf.policy) : '<span class="badge" style="background:#dc2626">MISSING</span>'}</p>`;
    sections += `<p><strong>DMARC:</strong> ${e.dmarc?.present ? esc(e.dmarc.policy) : '<span class="badge" style="background:#dc2626">MISSING</span>'}</p>`;
    sections += `<p><strong>DKIM:</strong> ${e.dkim?.found?.length || 0} selector(s) found</p>`;
    if (e.findings?.length) {
      sections += '<table class="findings-table"><thead><tr><th>Severity</th><th>Title</th></tr></thead><tbody>';
      for (const f of e.findings) sections += `<tr><td>${sevBadge(f.severity)}</td><td>${esc(f.title)}</td></tr>`;
      sections += '</tbody></table>';
    }
    sections += '</div>';
  }

  // Threat Intel
  if (results.threatintel) {
    const ti = results.threatintel;
    sections += `<div class="module-section"><h3>Threat Intelligence</h3>`;
    if (ti.sources) {
      for (const [name, src] of Object.entries(ti.sources)) {
        const s = src as any;
        const status = s.ok ? '<span class="badge" style="background:#16a34a">OK</span>' : `<span class="badge" style="background:#dc2626">FAIL</span>`;
        sections += `<p><strong>${esc(name)}:</strong> ${status} ${s.error ? esc(s.error) : ''}</p>`;
      }
    }
    if (ti.aggregated) {
      sections += `<p><strong>Aggregated subdomains:</strong> ${ti.aggregated.subdomains?.length || 0}</p>`;
      sections += `<p><strong>Resolved IPs:</strong> ${ti.aggregated.resolvedIps?.length || 0}</p>`;
    }
    sections += '</div>';
  }

  // Cloud Assets
  if (results.cloudenum) {
    if (results.cloudenum.buckets?.length) {
      sections += renderListTable(results.cloudenum.buckets.map((b: any) => ({ provider: b.provider, name: b.name, public: b.public, listing: b.listing })), ['provider', 'name', 'public', 'listing'], 'Cloud Storage Buckets');
    }
    if (results.cloudenum.repos?.length) {
      sections += renderListTable(results.cloudenum.repos.map((r: any) => ({ provider: r.provider, name: r.name, public: r.exists && !r.private })), ['provider', 'name', 'public'], 'Code Repositories');
    }
  }

  // Recon (WHOIS/ASN/Geo)
  if (results.recon) {
    const r = results.recon;
    sections += `<div class="module-section"><h3>Recon (WHOIS / ASN / GeoIP)</h3>`;
    if (r.whois?.registrar) sections += `<p><strong>Registrar:</strong> ${esc(r.whois.registrar)}</p>`;
    if (r.whois?.createdDate) sections += `<p><strong>Created:</strong> ${esc(r.whois.createdDate)}</p>`;
    if (r.whois?.expiryDate) sections += `<p><strong>Expires:</strong> ${esc(r.whois.expiryDate)}</p>`;
    if (r.geo?.city) sections += `<p><strong>Geo:</strong> ${esc(r.geo.city)}, ${esc(r.geo.country)} (${esc(r.geo.isp)})</p>`;
    if (r.asn?.asn) sections += `<p><strong>ASN:</strong> ${esc(r.asn.asn)} — ${esc(r.asn.org)}</p>`;
    sections += '</div>';
  }

  // Injection points
  if (results.inject) {
    sections += renderHostFindings(results.inject.hosts?.map((h: any) => ({
      url: h.url,
      findings: h.points?.map((p: any) => ({ severity: p.severity, title: `${p.type.toUpperCase()} on param '${p.param}'`, detail: `Payload: ${p.payload} | Evidence: ${p.evidence}` }))
    })), 'Injection Points');
  }

  // Auth bypass
  if (results.auth) {
    sections += renderHostFindings(results.auth.hosts, 'Auth Bypass');
  }

  // CSRF
  if (results.csrf) {
    const csrfHosts = results.csrf.hosts?.map((h: any) => ({
      url: h.url,
      findings: h.findings
    }));
    sections += renderHostFindings(csrfHosts, 'CSRF');
  }

  // Deserialization
  if (results.deserialization) {
    sections += renderHostFindings(results.deserialization.hosts, 'Deserialization');
  }

  // Smuggling
  if (results.smuggling) {
    sections += renderHostFindings(results.smuggling.hosts, 'HTTP Smuggling');
  }

  // Cache
  if (results.cache) {
    sections += renderHostFindings(results.cache.hosts, 'Cache Poisoning');
  }

  // Host header
  if (results.hostheader) {
    sections += renderHostFindings(results.hostheader.hosts, 'Host Header / SSRF / CRLF');
  }

  // Subdomain takeover
  if (results.subtakeover?.vulnerable?.length) {
    sections += renderListTable(results.subtakeover.vulnerable.map((v: any) => ({ hostname: v.hostname, service: v.service, severity: v.severity, fingerprint: v.fingerprint })), ['hostname', 'service', 'severity', 'fingerprint'], 'Subdomain Takeover');
  }

  // SSL tests
  if (results.ssltests) {
    sections += renderHostFindings(results.ssltests.hosts, 'SSL/TLS Tests');
  }

  // Open directories
  if (results.opendirs) {
    if (results.opendirs.directories?.length) {
      sections += renderListTable(results.opendirs.directories.map((d: any) => ({ url: d.url, listingType: d.listingType, server: d.server })), ['url', 'listingType', 'server'], 'Open Directories');
    }
    if (results.opendirs.exposedFiles?.length) {
      sections += renderListTable(results.opendirs.exposedFiles.map((f: any) => ({ url: f.url, status: f.status, type: f.type })), ['url', 'status', 'type'], 'Exposed Files');
    }
  }

  // JS analysis
  if (results.jsanalyze?.files?.length) {
    const totalSecrets = results.jsanalyze.files.reduce((a: number, f: any) => a + f.secrets.length, 0);
    if (totalSecrets > 0) {
      sections += `<div class="module-section"><h3>JavaScript Analysis <span class="count">${totalSecrets} secret(s)</span></h3>`;
      for (const f of results.jsanalyze.files) {
        if (!f.secrets?.length) continue;
        sections += `<div class="host"><div class="host-url">${esc(f.url)}</div>`;
        sections += '<table class="findings-table"><thead><tr><th>Type</th><th>Value</th><th>Line</th></tr></thead><tbody>';
        for (const s of f.secrets) {
          sections += `<tr><td><span class="badge" style="background:#dc2626">${esc(s.type)}</span></td><td><code>${esc(s.value.slice(0, 60))}</code></td><td>${s.line}</td></tr>`;
        }
        sections += '</tbody></table></div>';
      }
      sections += '</div>';
    }
  }

  // Wayback
  if (results.wayback?.totalUrls) {
    sections += `<div class="module-section"><h3>Wayback Machine <span class="count">${results.wayback.totalUrls} URLs</span></h3>`;
    if (results.wayback.deletedPages?.length) {
      sections += `<p><strong>Deleted/404 pages in archive:</strong> ${results.wayback.deletedPages.length}</p>`;
    }
    if (results.wayback.fileTypes?.length) {
      sections += '<p><strong>File types:</strong> ' + results.wayback.fileTypes.slice(0, 10).map((f: any) => `<span class="tech-badge">${esc(f.ext)}: ${f.count}</span>`).join(' ') + '</p>';
    }
    sections += '</div>';
  }

  // Summary table
  const f = summary?.findings || {};
  const summaryRows: [string, any][] = [
    ['DNS records', f.dnsRecords], ['Subdomains', f.subdomains], ['Open ports', f.openPorts],
    ['HTTP services', f.httpServices], ['TLS certificates', f.tlsCerts], ['Technologies', f.technologies],
    ['Vulnerabilities', f.vulnerabilities], ['Email sec issues', f.emailSecIssues],
    ['Open dirs / files', f.openDirs], ['Firewalls detected', f.firewallsDetected],
    ['Bypass payloads', f.bypassPayloads], ['Takeover vulnerable', f.takeoverVulnerable],
    ['Cloud assets', f.cloudAssets], ['JS secrets', f.jsSecrets], ['API endpoints', f.apiEndpoints],
    ['Injection points', f.injectPoints], ['WebDAV hosts', f.webdavEnabled], ['SSL/TLS issues', f.sslIssues],
    ['Auth issues', f.authIssues], ['CSRF issues', f.csrfIssues], ['Deser issues', f.deserIssues],
    ['Smuggling issues', f.smugglingIssues], ['Cache issues', f.cacheIssues],
    ['Host header issues', f.hostHeaderIssues], ['Wayback URLs', f.waybackUrls],
  ];

  let summaryHtml = '<table class="summary-table"><thead><tr><th>Category</th><th>Findings</th></tr></thead><tbody>';
  for (const [k, v] of summaryRows) {
    if (v !== undefined && v !== null) {
      const vNum = typeof v === 'number' ? v : 0;
      const highlight = vNum > 0 ? `class="${vNum >= 5 ? 'crit' : vNum >= 1 ? 'warn' : ''}"` : '';
      summaryHtml += `<tr ${highlight}><td>${esc(k)}</td><td>${esc(v)}</td></tr>`;
    }
  }
  summaryHtml += '</tbody></table>';

  // ── Full HTML document ────────────────────────────────────────────────
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EXENOM Report — ${esc(target)}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; padding: 20px; }
  .container { max-width: 1100px; margin: 0 auto; }
  .header { text-align: center; padding: 30px 20px; background: linear-gradient(135deg, #1e1b4b, #312e81); border-radius: 12px; margin-bottom: 24px; border: 1px solid #4c1d95; }
  .header h1 { font-size: 2.5em; color: #c678dd; letter-spacing: 3px; margin-bottom: 8px; }
  .header .subtitle { color: #94a3b8; font-size: 1.1em; }
  .header .meta { margin-top: 16px; display: flex; flex-wrap: wrap; gap: 20px; justify-content: center; }
  .header .meta-item { background: rgba(255,255,255,0.05); padding: 8px 16px; border-radius: 8px; font-size: 0.9em; }
  .header .meta-item strong { color: #c678dd; }
  .developer { text-align: center; color: #c678dd; font-weight: 600; margin: 20px 0; }
  .summary-box { background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 24px; margin-bottom: 24px; }
  .summary-box h2 { color: #c678dd; margin-bottom: 16px; border-bottom: 1px solid #334155; padding-bottom: 10px; }
  .summary-table { width: 100%; border-collapse: collapse; }
  .summary-table th, .summary-table td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #334155; }
  .summary-table th { color: #94a3b8; font-size: 0.85em; text-transform: uppercase; }
  .summary-table tr.crit td { color: #fca5a5; font-weight: 600; }
  .summary-table tr.warn td { color: #fcd34d; }
  .module-section { background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 20px; margin-bottom: 16px; }
  .module-section h3 { color: #56b6c2; margin-bottom: 12px; display: flex; align-items: center; gap: 10px; }
  .count { background: #4c1d95; color: #e2e8f0; padding: 2px 10px; border-radius: 12px; font-size: 0.8em; }
  .host { background: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 12px; margin-bottom: 12px; }
  .host-url { color: #56b6c2; font-family: monospace; font-weight: 600; margin-bottom: 8px; word-break: break-all; }
  table { width: 100%; border-collapse: collapse; margin: 8px 0; }
  th, td { padding: 6px 10px; text-align: left; border-bottom: 1px solid #334155; font-size: 0.9em; }
  th { color: #94a3b8; font-size: 0.8em; text-transform: uppercase; }
  td code { background: #0f172a; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; color: #e06c75; word-break: break-all; }
  .badge { padding: 2px 8px; border-radius: 4px; font-size: 0.75em; font-weight: 600; color: #fff; }
  .tech-badge { background: #1e293b; border: 1px solid #334155; padding: 2px 10px; border-radius: 12px; font-size: 0.85em; display: inline-block; margin: 2px; }
  .findings-table td:first-child { white-space: nowrap; }
  .muted { color: #6b7280; font-size: 0.85em; }
  .info { padding: 8px 12px; background: #0f172a; border-radius: 6px; margin: 8px 0; }
  .footer { text-align: center; color: #475569; font-size: 0.85em; margin-top: 30px; padding: 20px; border-top: 1px solid #1e293b; }
  .no-findings { color: #475569; font-style: italic; text-align: center; padding: 20px; }
  @media (max-width: 700px) { .header h1 { font-size: 1.5em; } table { font-size: 0.8em; } th, td { padding: 4px 6px; } }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>EXENOM</h1>
    <div class="subtitle">External Attack Surface Management — Scan Report</div>
    <div class="meta">
      <div class="meta-item"><strong>Target:</strong> ${esc(target)}</div>
      <div class="meta-item"><strong>Duration:</strong> ${duration}s</div>
      <div class="meta-item"><strong>Modules:</strong> ${modules.length}</div>
      <div class="meta-item"><strong>Date:</strong> ${esc(timestamp)}</div>
    </div>
  </div>

  <div class="developer">Built by Rudresha RK — Cybersecurity Undergraduate</div>

  <div class="summary-box">
    <h2>📊 Summary of Findings</h2>
    ${summaryHtml}
  </div>

  ${sections || '<div class="no-findings">No detailed findings to display.</div>'}

  <div class="footer">
    <p>Generated by EXENOM — External Attack Surface Management</p>
    <p>This report is for authorized security testing only. Always obtain permission before scanning.</p>
  </div>
</div>
</body>
</html>`;
}

/** Download the HTML report as a file in the browser */
export function downloadHtmlReport(results: any, summary: any): void {
  const html = generateHtmlReport(results, summary);
  const blob = new Blob([html], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  const target = summary?.target || 'scan';
  const ts = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  a.download = `exenom-report-${target}-${ts}.html`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
