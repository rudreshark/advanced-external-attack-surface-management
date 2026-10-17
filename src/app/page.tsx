'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import { io, type Socket } from 'socket.io-client';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import '@xterm/xterm/css/xterm.css';
import {
  renderEvent,
  welcomeBanner,
  MODULE_LABEL,
  EASM_COLORS,
} from '@/lib/easm/render';
import { downloadHtmlReport } from '@/lib/easm/htmlreport';
import type { ModuleId, ScanEvent } from '@/lib/easm/types';

const ALL_MODULES: ModuleId[] = [
  'dns', 'subdomains', 'ports', 'http', 'tls', 'tech', 'banners', 'vulns', 'threatintel', 'emailsec', 'opendirs', 'firewall', 'subtakeover', 'cloudenum', 'screenshots', 'jsanalyze', 'api', 'inject', 'webdav', 'ssltests', 'crawl', 'recon', 'spider', 'wayback', 'hostheader', 'auth', 'csrf', 'deserialization', 'smuggling', 'cache', 'xxe', 'clickjacking', 'race',
];

const C = EASM_COLORS;

interface ParsedScan {
  target: string;
  modules?: ModuleId[];
  ports?: number[];
  noSubdomains?: boolean;
}

function parseScanCommand(raw: string): ParsedScan | { error: string } {
  const tokens = raw.trim().split(/\s+/);
  // tokens[0] === 'scan'
  const target = tokens[1];
  if (!target) return { error: 'Usage: scan <target> [--modules a,b] [--ports 80,443] [--no-subdomains]' };
  const result: ParsedScan = { target: target.replace(/^[a-zA-Z]+:\/\//, '').split('/')[0] };
  for (let i = 2; i < tokens.length; i++) {
    const t = tokens[i];
    if (t === '--modules' || t === '-m') {
      const next = tokens[++i];
      if (!next) return { error: '--modules requires a value' };
      const mods = next.split(',').map((s) => s.trim().toLowerCase()) as ModuleId[];
      const invalid = mods.filter((m) => !ALL_MODULES.includes(m));
      if (invalid.length) return { error: `Unknown module(s): ${invalid.join(', ')}` };
      result.modules = mods;
    } else if (t === '--ports' || t === '-p') {
      const next = tokens[++i];
      if (!next) return { error: '--ports requires a value' };
      const ports: number[] = [];
      for (const part of next.split(',')) {
        const p = part.trim();
        if (p.includes('-')) {
          const [a, b] = p.split('-').map((n) => parseInt(n.trim(), 10));
          for (let j = a; j <= b; j++) if (!isNaN(j)) ports.push(j);
        } else {
          const n = parseInt(p, 10);
          if (!isNaN(n)) ports.push(n);
        }
      }
      result.ports = ports;
    } else if (t === '--no-subdomains') {
      result.noSubdomains = true;
    }
  }
  return result;
}

const HELP_TEXT = [
  '',
  C.BCYAN + C.BOLD + 'EXENOM — How to Run This Tool' + C.RESET,
  C.GRAY + '═'.repeat(64) + C.RESET,
  '',
  C.BMAGENTA + C.BOLD + '  ── HOW TO SCAN A TARGET SITE ──' + C.RESET,
  '',
  C.YELLOW + '  Step 1:' + C.RESET + C.GRAY + '  Type the scan command with a domain or IP:' + C.RESET,
  C.CYAN + '          scan example.com' + C.RESET,
  C.GRAY + '          scan 192.168.1.1' + C.RESET,
  C.GRAY + '          scan subdomain.example.com' + C.RESET,
  '',
  C.YELLOW + '  Step 2:' + C.RESET + C.GRAY + '  Pick specific modules to run (faster):' + C.RESET,
  C.CYAN + '          scan example.com --modules dns,http,vulns' + C.RESET,
  C.GRAY + '          scan example.com --modules firewall,inject,spider' + C.RESET,
  C.GRAY + '          scan example.com --modules threatintel,cloudenum,recon' + C.RESET,
  '',
  C.YELLOW + '  Step 3:' + C.RESET + C.GRAY + '  Add flags for more control:' + C.RESET,
  C.CYAN + '          scan example.com --ports 80,443,8080-8100' + C.RESET + C.GRAY + '   (custom ports)' + C.RESET,
  C.CYAN + '          scan example.com --no-subdomains' + C.RESET + C.GRAY + '            (faster, skip subdomains)' + C.RESET,
  '',
  C.YELLOW + '  Step 4:' + C.RESET + C.GRAY + '  Scan multiple sites at once:' + C.RESET,
  C.CYAN + '          targets example.com,github.com,google.com' + C.RESET,
  C.CYAN + '          targets site1.com,site2.com --modules dns,http' + C.RESET,
  '',
  C.YELLOW + '  Step 5:' + C.RESET + C.GRAY + '  Read the output — each module shows findings' + C.RESET,
  C.GRAY + '          in colored tables with severity tags.' + C.RESET,
  C.GRAY + '          Use --output json for a machine-readable report.' + C.RESET,
  '',
  C.BMAGENTA + C.BOLD + '  ── ALL SCAN COMMANDS ──' + C.RESET,
  '',
  C.GREEN + '  scan <target>' + C.RESET + C.GRAY + '                        full scan (all 30 modules)' + C.RESET,
  C.GREEN + '  scan <target> --modules <list>' + C.RESET + C.GRAY + '       run selected modules only' + C.RESET,
  C.GREEN + '  scan <target> --ports <list>' + C.RESET + C.GRAY + '          custom port list (ranges ok)' + C.RESET,
  C.GREEN + '  scan <target> --no-subdomains' + C.RESET + C.GRAY + '        skip subdomain enumeration' + C.RESET,
  C.GREEN + '  targets <t1,t2,t3> [--modules ...]' + C.RESET + C.GRAY + '   scan multiple targets' + C.RESET,
  '',
  C.BMAGENTA + C.BOLD + '  ── OTHER COMMANDS ──' + C.RESET,
  '',
  C.GREEN + '  modules' + C.RESET + C.GRAY + '       list all 30 available modules' + C.RESET,
  C.GREEN + '  report' + C.RESET + C.GRAY + '        download HTML report of last scan' + C.RESET,
  C.GREEN + '  clear' + C.RESET + C.GRAY + '         clear the terminal screen' + C.RESET,
  C.GREEN + '  about' + C.RESET + C.GRAY + '         tool info + developer credit' + C.RESET,
  C.GREEN + '  help' + C.RESET + C.GRAY + '          show this help' + C.RESET,
  '',
  C.BMAGENTA + C.BOLD + '  ── REAL CLI (run in your Linux terminal) ──' + C.RESET,
  '',
  C.CYAN + '  bun run easm scan example.com' + C.RESET,
  C.CYAN + '  bun run easm scan example.com --modules dns,http,vulns' + C.RESET,
  C.CYAN + '  bun run easm scan example.com --ports 80,443,8080' + C.RESET,
  C.CYAN + '  bun run easm scan example.com --no-subdomains' + C.RESET,
  C.CYAN + '  bun run easm scan example.com --output json' + C.RESET + C.GRAY + '  (JSON report)' + C.RESET,
  C.CYAN + '  python3 download/easm.py scan example.com' + C.RESET + C.GRAY + '  (standalone Python)' + C.RESET,
  '',
  C.BMAGENTA + C.BOLD + '  ── ALL 30 MODULES ──' + C.RESET,
  '',
  C.GRAY + '  ' + ALL_MODULES.join(', ') + C.RESET,
  '',
  C.BMAGENTA + C.BOLD + '  ── QUICK COMBOS ──' + C.RESET,
  '',
  C.GRAY + '  Recon:        ' + C.CYAN + 'scan example.com --modules dns,subdomains,recon,threatintel' + C.RESET,
  C.GRAY + '  Web app sec:  ' + C.CYAN + 'scan example.com --modules http,vulns,firewall,inject,spider' + C.RESET,
  C.GRAY + '  Cloud:        ' + C.CYAN + 'scan example.com --modules cloudenum,subtakeover,jsanalyze' + C.RESET,
  C.GRAY + '  Red-team:     ' + C.CYAN + 'scan example.com --modules auth,csrf,deserialization,smuggling,cache' + C.RESET,
  C.GRAY + '  Full scan:    ' + C.CYAN + 'scan example.com' + C.RESET,
  '',
].join('\r\n');

const ABOUT_TEXT = [
  '',
  C.BMAGENTA + C.BOLD + '  ╔══════════════════════════════════════════════╗' + C.RESET,
  C.BMAGENTA + C.BOLD + '  ║  EXENOM — External Attack Surface Management ║' + C.RESET,
  C.BMAGENTA + C.BOLD + '  ║         Advanced Recon & Red-Team Tool       ║' + C.RESET,
  C.BMAGENTA + C.BOLD + '  ║                    v1.0                      ║' + C.RESET,
  C.BMAGENTA + C.BOLD + '  ╚══════════════════════════════════════════════╝' + C.RESET,
  '',
  C.GRAY + '  An advanced attack-surface management engine that maps an' + C.RESET,
  C.GRAY + '  organisation\'s internet-facing assets from a single target.' + C.RESET,
  '',
  C.CYAN + C.BOLD + '  ── 30 RECON & RED-TEAM MODULES ──' + C.RESET,
  C.GRAY + '  • DNS recon            • Subdomain enum (6 sources)' + C.RESET,
  C.GRAY + '  • TCP+UDP port scan    • HTTP/HTTPS probing' + C.RESET,
  C.GRAY + '  • TLS/cert analysis    • Technology fingerprinting' + C.RESET,
  C.GRAY + '  • Service banners      • Vulnerability checks' + C.RESET,
  C.GRAY + '  • Threat intel (4 APIs) • Email security (SPF/DMARC/DKIM)' + C.RESET,
  C.GRAY + '  • Open directories     • Firewall/WAF detection + bypass' + C.RESET,
  C.GRAY + '  • Subdomain takeover   • Cloud asset enum (S3/Azure/GCP)' + C.RESET,
  C.GRAY + '  • Deep HTTP fingerprint • JavaScript analysis (secrets)' + C.RESET,
  C.GRAY + '  • API discovery        • Injection testing (SQLi/XSS/SSTI/CMDi)' + C.RESET,
  C.GRAY + '  • WebDAV probing       • Advanced SSL/TLS tests' + C.RESET,
  C.GRAY + '  • Web crawler          • Recon (WHOIS/ASN/GeoIP)' + C.RESET,
  C.GRAY + '  • Advanced spider      • Wayback Machine (historical URLs)' + C.RESET,
  C.GRAY + '  • Host header/SSRF/CRLF • Auth bypass (JWT/default creds)' + C.RESET,
  C.GRAY + '  • CSRF checks          • Deserialization (Java/PHP/Python)' + C.RESET,
  C.GRAY + '  • HTTP request smuggling • Cache poisoning + WCD' + C.RESET,
  '',
  C.CYAN + C.BOLD + '  ── 330+ ENCODED WAF-BYPASS PAYLOADS PER CATEGORY ──' + C.RESET,
  C.GRAY + '  XSS · SQLi · LFI · CMDi · Open Dirs — each with 330+' + C.RESET,
  C.GRAY + '  encoded variants (URL/HTML/Unicode/hex/case/ws) to' + C.RESET,
  C.GRAY + '  bypass Cloudflare, ModSecurity, AWS WAF, Akamai, Imperva.' + C.RESET,
  '',
  C.CYAN + C.BOLD + '  ── ALSO A REAL CLI ──' + C.RESET,
  C.GRAY + '  bun run easm scan <target>          (runs in your terminal)' + C.RESET,
  C.GRAY + '  python3 download/easm.py scan <target>  (standalone Python)' + C.RESET,
  '',
  C.GRAY + '  ────────────────────────────────────────────────' + C.RESET,
  C.BMAGENTA + C.BOLD + '  Built by Rudresha RK' + C.RESET,
  C.BMAGENTA + '  Cybersecurity Undergraduate' + C.RESET,
  C.GRAY + '  ────────────────────────────────────────────────' + C.RESET,
  '',
].join('\r\n');

export default function Home() {
  const terminalRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const socketRef = useRef<Socket | null>(null);
  const [connected, setConnected] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [input, setInput] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);
  const historyRef = useRef<string[]>([]);
  const historyIdxRef = useRef(-1);
  // Persistence buffer — stores all terminal output lines + scan results
  // so they survive browser refresh.
  const outputBufferRef = useRef<string[]>([]);
  const lastResultsRef = useRef<any>(null);
  const lastSummaryRef = useRef<any>(null);
  const globalScanStatusRef = useRef({ scanning: false, target: '', eventCount: 0 });

  // ── Persistence helpers ──────────────────────────────────────────────
  const STORAGE_KEY = 'exenom_terminal_output';
  const RESULTS_KEY = 'exenom_last_results';
  const SUMMARY_KEY = 'exenom_last_summary';

  const saveOutput = useCallback(() => {
    try {
      // Keep last 2000 lines to avoid localStorage overflow
      const buf = outputBufferRef.current.slice(-2000);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(buf));
    } catch { /* quota exceeded — ignore */ }
  }, []);

  const saveResults = useCallback((results: any, summary: any) => {
    try {
      localStorage.setItem(RESULTS_KEY, JSON.stringify(results));
      localStorage.setItem(SUMMARY_KEY, JSON.stringify(summary));
    } catch { /* ignore */ }
  }, []);

  const writeLine = useCallback((text: string) => {
    const term = termRef.current;
    if (!term) return;
    term.write(text + '\n');
    outputBufferRef.current.push(text + '\n');
    saveOutput();
  }, [saveOutput]);

  const writeRaw = useCallback((text: string) => {
    const term = termRef.current;
    if (!term) return;
    term.write(text);
    outputBufferRef.current.push(text);
    // Only save on newline to avoid excessive localStorage writes
    if (text.endsWith('\n')) saveOutput();
  }, [saveOutput]);

  // init terminal + socket
  useEffect(() => {
    if (!terminalRef.current) return;
    const term = new Terminal({
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Geist Mono', ui-monospace, monospace",
      fontSize: 13,
      lineHeight: 1.3,
      cursorBlink: true,
      cursorStyle: 'bar',
      convertEol: true,
      allowProposedApi: true,
      scrollback: 5000,
      theme: {
        background: '#0a0e14',
        foreground: '#c8ccd4',
        cursor: '#7c3aed',
        cursorAccent: '#0a0e14',
        selectionBackground: '#2a2f3a',
        black: '#0a0e14',
        red: '#e06c75',
        green: '#56d364',
        yellow: '#e5c07b',
        blue: '#61afef',
        magenta: '#c678dd',
        cyan: '#56b6c2',
        white: '#c8ccd4',
        brightBlack: '#5c6370',
        brightRed: '#e06c75',
        brightGreen: '#56d364',
        brightYellow: '#e5c07b',
        brightBlue: '#61afef',
        brightMagenta: '#c678dd',
        brightCyan: '#56b6c2',
        brightWhite: '#ffffff',
      },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.loadAddon(new WebLinksAddon());
    term.open(terminalRef.current);
    fit.fit();
    termRef.current = term;
    fitRef.current = fit;

    // ── Restore saved output from localStorage (survives refresh) ──────
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        const lines = JSON.parse(saved) as string[];
        if (Array.isArray(lines) && lines.length > 0) {
          outputBufferRef.current = lines;
          // Write a separator before restored content
          term.write(C.GRAY + '[*] Restored previous session (' + lines.length + ' lines)' + C.RESET + '\n');
          term.write(C.GRAY + '─'.repeat(60) + C.RESET + '\n');
          for (const line of lines) {
            term.write(line);
          }
          term.write(C.GRAY + '─'.repeat(60) + C.RESET + '\n');
          term.write(C.GRAY + '[*] Session restored. Type ' + C.RESET + C.CYAN + 'clear' + C.RESET + C.GRAY + ' to wipe, or ' + C.RESET + C.CYAN + 'report' + C.RESET + C.GRAY + ' for HTML report.' + C.RESET + '\n\n');
        } else {
          term.write(welcomeBanner());
        }
      } else {
        term.write(welcomeBanner());
      }
    } catch {
      term.write(welcomeBanner());
    }

    // Restore last scan results if available
    try {
      const savedResults = localStorage.getItem(RESULTS_KEY);
      const savedSummary = localStorage.getItem(SUMMARY_KEY);
      if (savedResults) lastResultsRef.current = JSON.parse(savedResults);
      if (savedSummary) lastSummaryRef.current = JSON.parse(savedSummary);
    } catch { /* ignore */ }

    const onResize = () => {
      try { fit.fit(); } catch { /* ignore */ }
    };
    window.addEventListener('resize', onResize);
    const ro = new ResizeObserver(onResize);
    ro.observe(terminalRef.current);

    // socket.io connection
    const socket = io('/?XTransformPort=3004', {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionAttempts: 10,
      reconnectionDelay: 1500,
      timeout: 10000,
    });
    socketRef.current = socket;

    socket.on('connect', () => {
      setConnected(true);
      // Don't show "Connected" if we're restoring — the status handler will do that
    });
    socket.on('disconnect', () => {
      setConnected(false);
      // NOTE: do NOT set scanning=false here — the scan continues on the backend.
      // The user will reconnect and receive missed events via scan:replay.
      writeLine(C.YELLOW + '[!] Connection lost. Scan continues in the background — refresh to reconnect.' + C.RESET);
    });
    socket.on('scan:ready', () => {
      // Only show if no scan is ongoing
      if (!globalScanStatusRef.current.scanning) {
        writeLine(C.GRAY + '[*] Scan engine ready. Awaiting commands.' + C.RESET);
      }
    });

    // ── Handle scan:status (sent on connect + on resubscribe) ────────────
    // This tells us if a scan is ongoing and how many events we missed.
    socket.on('scan:status', (status: { scanning: boolean; target: string; eventCount: number; hasResults: boolean }) => {
      globalScanStatusRef.current = status;
      if (status.scanning) {
        setScanning(true);
        writeLine(C.BMAGENTA + '[*] Ongoing scan detected on ' + status.target + ' (' + status.eventCount + ' events so far). Re-subscribing...' + C.RESET);
      } else if (status.hasResults && status.eventCount > 0) {
        // Scan already completed — results are available
        writeLine(C.GRAY + '[*] Previous scan of ' + status.target + ' completed (' + status.eventCount + ' events). Results available — type ' + C.CYAN + 'report' + C.RESET + C.GRAY + ' for HTML.' + C.RESET);
      }
    });

    // ── Handle scan:replay (all missed events on reconnect) ──────────────
    socket.on('scan:replay', (events: ScanEvent[]) => {
      if (!events || events.length === 0) return;
      writeLine(C.GRAY + '[*] Replaying ' + events.length + ' missed event(s)...' + C.RESET);
      writeLine(C.GRAY + '─'.repeat(60) + C.RESET);

      // Reconstruct results from replayed events
      let hasResults = false;
      for (const ev of events) {
        const text = renderEvent(ev);
        if (text !== null) writeRaw(text + (ev.type === 'progress' ? '' : '\n'));
        // Capture result data
        if (ev.type === 'result') {
          if (!lastResultsRef.current) lastResultsRef.current = {};
          lastResultsRef.current[ev.module] = ev.data;
          hasResults = true;
        }
        if (ev.type === 'done') {
          lastSummaryRef.current = ev.summary;
          saveResults(lastResultsRef.current, ev.summary);
        }
      }
      writeLine(C.GRAY + '─'.repeat(60) + C.RESET);
      if (hasResults) {
        writeLine(C.GREEN + '[*] Replay complete. Continuing live scan output...' + C.RESET);
      } else {
        writeLine(C.GREEN + '[*] Replay complete.' + C.RESET);
      }
    });

    socket.on('scan:event', (ev: ScanEvent) => {
      const text = renderEvent(ev);
      if (text !== null) writeRaw(text + (ev.type === 'progress' ? '' : '\n'));
      // Capture result data for HTML report
      if (ev.type === 'result') {
        if (!lastResultsRef.current) lastResultsRef.current = {};
        lastResultsRef.current[ev.module] = ev.data;
      }
      if (ev.type === 'done') {
        setScanning(false);
        lastSummaryRef.current = ev.summary;
        saveResults(lastResultsRef.current, ev.summary);
        writeLine(C.BMAGENTA + C.BOLD + '\n[✓] Scan complete! Type ' + C.CYAN + 'report' + C.RESET + C.BMAGENTA + C.BOLD + ' to generate an HTML report.' + C.RESET);
      }
    });
    socket.on('scan:complete', (data: any) => {
      setScanning(false);
      // Capture full results from the scan engine
      if (data?.results) {
        lastResultsRef.current = data.results;
        if (data.summary) lastSummaryRef.current = data.summary;
        saveResults(data.results, data.summary || lastSummaryRef.current);
      }
    });
    socket.on('scan:error', (data: { message: string }) => {
      setScanning(false);
      writeLine(C.RED + '[!] Scan error: ' + data.message + C.RESET);
    });
    socket.on('scan:cancelled', () => {
      setScanning(false);
      writeLine(C.YELLOW + '[*] Scan cancelled.' + C.RESET);
    });
    socket.on('connect_error', () => {
      setConnected(false);
    });

    setTimeout(() => inputRef.current?.focus(), 100);

    return () => {
      window.removeEventListener('resize', onResize);
      ro.disconnect();
      socket.disconnect();
      term.dispose();
    };
  }, [writeLine, writeRaw]);

  const echoPrompt = (cmd: string) => {
    writeLine(C.BMAGENTA + 'easm ❯ ' + C.RESET + C.CYAN + cmd + C.RESET);
  };

  const runScan = useCallback((parsed: ParsedScan) => {
    const socket = socketRef.current;
    if (!socket || !connected) {
      writeLine(C.RED + '[!] Not connected to scan engine.' + C.RESET);
      return;
    }
    setScanning(true);
    socket.emit('scan:start', {
      target: parsed.target,
      modules: parsed.modules,
      ports: parsed.ports,
      enumerateSubdomains: !parsed.noSubdomains,
    });
  }, [connected, writeLine]);

  const handleCommand = useCallback((raw: string) => {
    const cmd = raw.trim();
    if (!cmd) return;
    echoPrompt(cmd);
    historyRef.current.push(cmd);
    historyIdxRef.current = historyRef.current.length;

    const parts = cmd.split(/\s+/);
    const action = parts[0].toLowerCase();

    if (action === 'help' || action === '?') {
      writeLine(HELP_TEXT);
      return;
    }
    if (action === 'about') {
      writeLine(ABOUT_TEXT);
      return;
    }
    if (action === 'clear' || action === 'cls') {
      termRef.current?.clear();
      // Also clear the persisted output buffer
      outputBufferRef.current = [];
      try { localStorage.removeItem(STORAGE_KEY); } catch { /* ignore */ }
      writeLine(C.GRAY + '[*] Terminal cleared.' + C.RESET);
      return;
    }
    if (action === 'report') {
      // Generate and download HTML report from last scan results
      const results = lastResultsRef.current;
      const summary = lastSummaryRef.current;
      if (!results && !summary) {
        writeLine(C.YELLOW + '[!] No scan results available. Run a scan first.' + C.RESET);
        return;
      }
      writeLine(C.BMAGENTA + '[*] Generating HTML report ...' + C.RESET);
      try {
        downloadHtmlReport(results || {}, summary || {});
        writeLine(C.GREEN + '[✓] HTML report downloaded! Check your downloads folder.' + C.RESET);
      } catch (e: any) {
        writeLine(C.RED + '[!] Failed to generate report: ' + (e?.message || e) + C.RESET);
      }
      return;
    }
    if (action === 'modules') {
      const lines = ['', C.BCYAN + C.BOLD + 'Available Modules' + C.RESET, C.GRAY + '─'.repeat(40) + C.RESET, ''];
      ALL_MODULES.forEach((m) => {
        lines.push(C.GREEN + '  • ' + C.RESET + C.CYAN + m.padEnd(14) + C.RESET + C.GRAY + MODULE_LABEL[m] + C.RESET);
      });
      lines.push('');
      writeLine(lines.join('\r\n'));
      return;
    }
    if (action === 'scan') {
      if (scanning) {
        writeLine(C.YELLOW + '[*] A scan is already running. Please wait...' + C.RESET);
        return;
      }
      const parsed = parseScanCommand(cmd);
      if ('error' in parsed) {
        writeLine(C.RED + '[!] ' + parsed.error + C.RESET);
        return;
      }
      runScan(parsed);
      return;
    }
    if (action === 'targets') {
      // Multi-target sequential scan: targets example.com,github.com,google.com
      if (scanning) {
        writeLine(C.YELLOW + '[*] A scan is already running. Please wait...' + C.RESET);
        return;
      }
      const argStr = cmd.slice(cmd.indexOf(' ') + 1).trim();
      if (!argStr) {
        writeLine(C.RED + '[!] Usage: targets <domain1,domain2,domain3> [--modules ...]' + C.RESET);
        return;
      }
      const targets = argStr.split(/\s+/)[0].split(',').map((t) => t.trim()).filter(Boolean);
      if (targets.length === 0) {
        writeLine(C.RED + '[!] No targets provided.' + C.RESET);
        return;
      }
      writeLine(C.BMAGENTA + C.BOLD + `[*] Multi-target scan: ${targets.length} target(s) — ${targets.join(', ')}` + C.RESET);
      // Parse remaining flags after the target list
      const restArgs = argStr.slice(argStr.indexOf(' ') >= 0 ? argStr.indexOf(' ') + 1 : argStr.length);
      const runSequentially = async () => {
        for (let i = 0; i < targets.length; i++) {
          writeLine(C.CYAN + `\n══ Target ${i + 1}/${targets.length}: ${targets[i]} ══` + C.RESET);
          const scanCmd = `scan ${targets[i]}${restArgs ? ' ' + restArgs : ''}`;
          const parsed = parseScanCommand(scanCmd);
          if ('error' in parsed) {
            writeLine(C.RED + '[!] ' + parsed.error + C.RESET);
            continue;
          }
          runScan(parsed);
          // Wait for this scan to finish before starting the next
          await new Promise<void>((resolve) => {
            const check = setInterval(() => {
              if (!scanning) {
                clearInterval(check);
                resolve();
              }
            }, 500);
          });
        }
        writeLine(C.BMAGENTA + C.BOLD + '\n[✓] All targets scanned.' + C.RESET);
      };
      runSequentially();
      return;
    }
    writeLine(C.RED + `[!] Unknown command: ${action}` + C.RESET + C.GRAY + '  (type "help")' + C.RESET);
  }, [scanning, runScan, writeLine]);

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    handleCommand(input);
    setInput('');
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (historyRef.current.length === 0) return;
      historyIdxRef.current = Math.max(0, historyIdxRef.current - 1);
      setInput(historyRef.current[historyIdxRef.current] || '');
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      historyIdxRef.current = Math.min(historyRef.current.length, historyIdxRef.current + 1);
      setInput(historyRef.current[historyIdxRef.current] || '');
    } else if (e.key === 'l' && e.ctrlKey) {
      e.preventDefault();
      termRef.current?.clear();
    }
  };

  const quickRun = (target: string, modules?: ModuleId[]) => {
    const cmd = modules ? `scan ${target} --modules ${modules.join(',')}` : `scan ${target}`;
    setInput('');
    handleCommand(cmd);
  };

  return (
    <div className="h-screen flex flex-col bg-[#0a0e14] text-[#c8ccd4] overflow-hidden">
      {/* Header */}
      <header className="flex items-center justify-between gap-3 px-4 h-12 border-b border-[#1c2230] bg-[#0d1119] flex-shrink-0">
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-full bg-[#ff5f56]" />
            <span className="w-3 h-3 rounded-full bg-[#ffbd2e]" />
            <span className="w-3 h-3 rounded-full bg-[#27c93f]" />
          </div>
          <div className="flex items-center gap-2 min-w-0">
            <span className="text-[#c678dd] font-bold tracking-wider text-sm">EXENOM</span>
            <span className="text-[#5c6370] text-xs hidden sm:inline">External Attack Surface Management</span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-[#0a0e14] border border-[#1c2230]">
            <span className={`w-2 h-2 rounded-full ${connected ? 'bg-[#27c93f]' : 'bg-[#ff5f56]'} ${connected ? 'animate-pulse' : ''}`} />
            <span className="text-[10px] font-mono text-[#5c6370] hidden sm:inline">
              {connected ? (scanning ? 'scanning' : 'engine online') : 'offline'}
            </span>
          </div>
        </div>
      </header>

      {/* Quick actions */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-[#1c2230] bg-[#0d1119] overflow-x-auto flex-shrink-0">
        <span className="text-[10px] text-[#5c6370] font-mono whitespace-nowrap pr-1">QUICK RUN:</span>
        <QuickBtn label="scan example.com" onClick={() => quickRun('example.com', ['dns', 'http', 'ports', 'vulns'])} />
        <QuickBtn label="scan github.com" onClick={() => quickRun('github.com', ['dns', 'http', 'tls', 'tech', 'vulns'])} />
        <QuickBtn label="scan google.com" onClick={() => quickRun('google.com', ['dns', 'subdomains', 'http'])} />
        <QuickBtn label="intel example.com" onClick={() => quickRun('example.com', ['threatintel'])} />
        <QuickBtn label="emailsec example.com" onClick={() => quickRun('example.com', ['emailsec'])} />
        <QuickBtn label="firewall example.com" onClick={() => quickRun('example.com', ['http', 'firewall'])} />
        <QuickBtn label="redteam example.com" onClick={() => quickRun('example.com', ['http', 'opendirs', 'firewall', 'vulns'])} />
        <QuickBtn label="cloud example.com" onClick={() => quickRun('example.com', ['cloudenum'])} />
        <QuickBtn label="deep example.com" onClick={() => quickRun('example.com', ['http', 'screenshots', 'subtakeover', 'cloudenum'])} />
        <QuickBtn label="js+api example.com" onClick={() => quickRun('example.com', ['http', 'jsanalyze', 'api'])} />
        <QuickBtn label="inject example.com" onClick={() => quickRun('example.com', ['http', 'inject'])} />
        <QuickBtn label="webdav example.com" onClick={() => quickRun('example.com', ['http', 'webdav'])} />
        <QuickBtn label="ssl example.com" onClick={() => quickRun('example.com', ['ssltests'])} />
        <QuickBtn label="crawl example.com" onClick={() => quickRun('example.com', ['http', 'crawl'])} />
        <QuickBtn label="recon example.com" onClick={() => quickRun('example.com', ['dns', 'recon'])} />
        <QuickBtn label="spider example.com" onClick={() => quickRun('example.com', ['http', 'spider'])} />
        <QuickBtn label="wayback example.com" onClick={() => quickRun('example.com', ['wayback'])} />
        <QuickBtn label="hosthdr example.com" onClick={() => quickRun('example.com', ['http', 'hostheader'])} />
        <QuickBtn label="auth example.com" onClick={() => quickRun('example.com', ['http', 'auth'])} />
        <QuickBtn label="csrf example.com" onClick={() => quickRun('example.com', ['http', 'csrf'])} />
        <QuickBtn label="deser example.com" onClick={() => quickRun('example.com', ['http', 'deserialization'])} />
        <QuickBtn label="smuggling example.com" onClick={() => quickRun('example.com', ['http', 'smuggling'])} />
        <QuickBtn label="cache example.com" onClick={() => quickRun('example.com', ['http', 'cache'])} />
        <QuickBtn label="xxe example.com" onClick={() => quickRun('example.com', ['http', 'xxe'])} />
        <QuickBtn label="clickjack example.com" onClick={() => quickRun('example.com', ['http', 'clickjacking'])} />
        <QuickBtn label="race example.com" onClick={() => quickRun('example.com', ['http', 'race'])} />
        <QuickBtn label="multi-target" onClick={() => handleCommand('targets example.com,github.com,google.com --modules dns,http --no-subdomains')} />
        <QuickBtn label="download report" onClick={() => handleCommand('report')} />
        <QuickBtn label="full scan example.com" onClick={() => quickRun('example.com')} />
        <span className="ml-auto text-[10px] text-[#5c6370] font-mono whitespace-nowrap pl-2 hidden md:inline">
          also a real CLI: <span className="text-[#56b6c2]">bun run easm scan &lt;target&gt;</span>
        </span>
      </div>

      {/* Terminal */}
      <main className="flex-1 min-h-0 relative">
        <div ref={terminalRef} className="absolute inset-0 p-2" />
      </main>

      {/* Prompt input (sticky footer) */}
      <footer className="flex items-center gap-2 px-3 h-12 border-t border-[#1c2230] bg-[#0d1119] flex-shrink-0">
        <span className="text-[#c678dd] font-mono font-bold text-sm whitespace-nowrap">easm ❯</span>
        <form onSubmit={onSubmit} className="flex-1 flex items-center">
          <input
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder={scanning ? 'scan in progress… (type scan:cancel not available, wait for completion)' : 'type a command — e.g.  scan example.com   |   help'}
            disabled={scanning}
            spellCheck={false}
            autoComplete="off"
            className="flex-1 bg-transparent outline-none font-mono text-sm text-[#c8ccd4] placeholder:text-[#3a4150] disabled:opacity-50"
          />
        </form>
        {scanning ? (
          <span className="text-[10px] text-[#e5c07b] font-mono animate-pulse whitespace-nowrap">● running</span>
        ) : (
          <span className="text-[10px] text-[#27c93f] font-mono whitespace-nowrap">● idle</span>
        )}
      </footer>
    </div>
  );
}

function QuickBtn({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="px-2.5 py-1 rounded-md bg-[#0a0e14] border border-[#1c2230] text-[11px] font-mono text-[#56b6c2] hover:bg-[#c678dd]/10 hover:border-[#c678dd]/40 hover:text-[#c678dd] transition-colors whitespace-nowrap"
    >
      {label}
    </button>
  );
}
