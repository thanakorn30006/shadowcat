const API_BASE = '/api';

// =============================================================================
// Strongly-Typed Data Contracts & Response DTOs
// =============================================================================

export interface RsaAttack {
  name: string;
  success: boolean;
  d?: number | string;
  p?: number | string;
  q?: number | string;
  plaintext?: string;
  flags?: string[];
  error?: string;
}

export interface RsaAttackResult {
  attacks: RsaAttack[];
  flags: string[];
}

export interface RepeaterResponse {
  status_code: number;
  status_text: string;
  latency_ms: number;
  size_bytes: number;
  headers: Record<string, string>;
  body: string;
  body_truncated: boolean;
  flags_found: string[];
  error?: string;
}

export interface ScannerFinding {
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: string;
  description: string;
  evidence: string;
  url?: string;
}

export interface ScannerResult {
  target_url: string;
  probes_run: number;
  total_findings: number;
  findings: ScannerFinding[];
}

export interface JsSecret {
  type: string;
  value: string;
}

export interface JsAnalysisResult {
  source_type: string;
  endpoints: string[];
  secrets: JsSecret[];
  analyzed_scripts?: string[];
  flags_found?: string[];
}

export interface WafResult {
  waf_detected: boolean;
  waf_name: string;
  confidence: string;
  indicators: string[];
  signatures_matched: string[];
}

export interface EntropyResult {
  entropy: number;
  ideal_entropy: number;
  metric: string;
  assessment: string;
  probabilities?: Record<string, number>;
}

export interface RecipeResult {
  success: boolean;
  output: string;
  output_length: number;
  execution_time_ms: number;
  steps_completed: number;
  total_steps: number;
  error?: string;
}

export interface JwtDecodeResult {
  valid_structure: boolean;
  header: Record<string, any>;
  payload: Record<string, any>;
  signature: string;
  algorithm: string;
  flags: string[];
  issues: string[];
}

export interface JwtForgeResult {
  token: string;
  algorithm: string;
  length: number;
  status: string;
}

export interface LicenseStatus {
  tier: string;
  status: string;
  signature_valid: boolean;
  expires: string;
  channel: string;
  pro_features: boolean;
}

export interface CrackResult {
  hash: string;
  hash_type: string;
  cracked: boolean;
  plaintext: string | null;
  method: string;
  latency_ms: number;
  candidates_tested: number;
}

export interface CyclicGenerateResult {
  pattern: string;
  length: number;
  width: number;
}

export interface CyclicFindResult {
  query: string;
  found: boolean;
  offset: number | null;
  width: number;
  suggestion: string;
}

export interface HeaderCheckResult {
  filename: string;
  extension: string;
  current_header_hex: string;
  is_corrupted: boolean;
  expected_format: string;
  expected_magic_hex: string | null;
  diagnosis: string;
}

export interface MagicUnwrapResult {
  success: boolean;
  depth: number;
  recipe: Array<{ step: number; op: string; preview: string }>;
  flag: string | null;
  flags_found: string[];
  output: string;
}

export async function apiRequest<T>(endpoint: string, options: RequestInit = {}, timeoutMs: number = 30000): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(`${API_BASE}${endpoint}`, {
      signal: options.signal || controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {})
      },
      ...options
    });
    clearTimeout(timer);
    
    if (!res.ok) {
      const errorData = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(errorData.detail || `Request failed with status ${res.status}`);
    }
    
    return res.json();
  } catch (err: any) {
    clearTimeout(timer);
    if (err.name === 'AbortError') {
      throw new Error(`Request to ${endpoint} timed out after ${timeoutMs / 1000}s`);
    }
    throw err;
  }
}

// Forensics API
export async function analyzeFile(file: File): Promise<any> {
  const formData = new FormData();
  formData.append('file', file);
  
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 60000); // 60s timeout for large uploads

  try {
    const res = await fetch(`${API_BASE}/forensics/analyze`, {
      method: 'POST',
      body: formData,
      signal: controller.signal
    });
    clearTimeout(timer);
    
    if (!res.ok) {
      const errorData = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(errorData.detail || 'Forensics upload failed');
    }
    return res.json();
  } catch (err: any) {
    clearTimeout(timer);
    if (err.name === 'AbortError') {
      throw new Error('Forensics file upload timed out after 60s');
    }
    throw err;
  }
}

export async function checkFileHeader(file: File): Promise<HeaderCheckResult> {
  const formData = new FormData();
  formData.append('file', file);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30000);

  try {
    const res = await fetch(`${API_BASE}/forensics/check-header`, {
      method: 'POST',
      body: formData,
      signal: controller.signal
    });
    clearTimeout(timer);

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(errorData.detail || 'Header check failed');
    }
    return res.json();
  } catch (err: any) {
    clearTimeout(timer);
    throw err;
  }
}

export async function repairFileHeader(file: File, targetFormat: string): Promise<Blob> {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('target_format', targetFormat);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30000);

  try {
    const res = await fetch(`${API_BASE}/forensics/repair-header`, {
      method: 'POST',
      body: formData,
      signal: controller.signal
    });
    clearTimeout(timer);

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(errorData.detail || 'Header repair failed');
    }
    return res.blob();
  } catch (err: any) {
    clearTimeout(timer);
    throw err;
  }
}

// Binary / Pwn API
export async function inspectBinary(file: File): Promise<any> {
  const formData = new FormData();
  formData.append('file', file);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 60000);

  try {
    const res = await fetch(`${API_BASE}/binary/inspect`, {
      method: 'POST',
      body: formData,
      signal: controller.signal
    });
    clearTimeout(timer);

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(errorData.detail || 'Binary inspection failed');
    }
    return res.json();
  } catch (err: any) {
    clearTimeout(timer);
    if (err.name === 'AbortError') {
      throw new Error('Binary file upload timed out after 60s');
    }
    throw err;
  }
}

export async function generateCyclicPattern(length: number = 200, width: number = 4): Promise<CyclicGenerateResult> {
  return apiRequest<CyclicGenerateResult>('/binary/cyclic-generate', {
    method: 'POST',
    body: JSON.stringify({ length, width }),
  });
}

export async function findCyclicOffset(pattern: string, width: number = 4, maxLength: number = 10000): Promise<CyclicFindResult> {
  return apiRequest<CyclicFindResult>('/binary/cyclic-find', {
    method: 'POST',
    body: JSON.stringify({ pattern, width, max_length: maxLength }),
  });
}

// JWT Studio API
export async function decodeJWT(token: string): Promise<JwtDecodeResult> {
  return apiRequest<JwtDecodeResult>('/jwt/decode', {
    method: 'POST',
    body: JSON.stringify({ token }),
  });
}

export async function forgeJWT(header: any, payload: any, secret?: string, alg_none?: boolean): Promise<JwtForgeResult> {
  return apiRequest<JwtForgeResult>('/jwt/forge', {
    method: 'POST',
    body: JSON.stringify({ header, payload, secret, alg_none }),
  });
}

export async function forgeJwtConfusion(header: any, payload: any, publicKey: string): Promise<JwtForgeResult> {
  return apiRequest<JwtForgeResult>('/jwt/forge', {
    method: 'POST',
    body: JSON.stringify({ header, payload, public_key: publicKey, alg_confusion: true }),
  });
}

// Crypto API
export async function decodeText(text: string, context?: string): Promise<any> {
  return apiRequest('/crypto/decode', {
    method: 'POST',
    body: JSON.stringify({ text, context }),
  });
}

export async function caesarAllShifts(text: string): Promise<any> {
  return apiRequest('/crypto/caesar-all', {
    method: 'POST',
    body: JSON.stringify({ text }),
  });
}

export async function vigenereTool(text: string, key: string, decrypt: boolean = true): Promise<any> {
  return apiRequest('/crypto/vigenere', {
    method: 'POST',
    body: JSON.stringify({ text, key, decrypt }),
  });
}

export async function xorBruteforce(text: string, is_hex?: boolean): Promise<any> {
  return apiRequest('/crypto/xor-bruteforce', {
    method: 'POST',
    body: JSON.stringify({ text, is_hex }),
  });
}

export async function convertEndianness(value: string): Promise<any> {
  return apiRequest('/crypto/endianness', {
    method: 'POST',
    body: JSON.stringify({ value }),
  });
}

// RSA API — Preserves arbitrary precision BigInt / Large Decimal / Hex strings
export async function attackRSA(n: string, e: string, c?: string): Promise<RsaAttackResult> {
  return apiRequest<RsaAttackResult>('/rsa/attack', {
    method: 'POST',
    body: JSON.stringify({
      n: n.trim(),
      e: e.trim(),
      c: c && c.trim() ? c.trim() : undefined,
    }),
  });
}

// Hash API
export async function crackHash(hash: string): Promise<CrackResult> {
  return apiRequest<CrackResult>('/hash/crack', {
    method: 'POST',
    body: JSON.stringify({ hash }),
  });
}

// Web API
export async function huntWeb(url: string): Promise<any> {
  return apiRequest('/web/hunt', {
    method: 'POST',
    body: JSON.stringify({ url }),
  });
}

export async function detectWaf(url: string): Promise<WafResult> {
  return apiRequest<WafResult>('/web/waf-detect', {
    method: 'POST',
    body: JSON.stringify({ url }),
  });
}

export async function mutatePayload(payload: string): Promise<{ variants: string[]; count: number }> {
  return apiRequest('/web/mutate-payload', {
    method: 'POST',
    body: JSON.stringify({ payload }),
  });
}

export async function analyzeJs(url?: string, raw_code?: string): Promise<JsAnalysisResult> {
  return apiRequest<JsAnalysisResult>('/web/analyze-js', {
    method: 'POST',
    body: JSON.stringify({ url: url || '', raw_code: raw_code || '' }),
  });
}

// Netcat API
export async function solveNetcat(host: string, port: number): Promise<any> {
  return apiRequest('/netcat/solve', {
    method: 'POST',
    body: JSON.stringify({ host, port }),
  });
}

// Classify API
export async function classifyChallenge(description: string): Promise<any> {
  return apiRequest('/classify', {
    method: 'POST',
    body: JSON.stringify({ description }),
  });
}

// Writeup API
export async function searchWriteups(query: string): Promise<any> {
  return apiRequest('/writeup/search', {
    method: 'POST',
    body: JSON.stringify({ query }),
  });
}

// Chat API
export async function sendChatMessage(messages: { role: string; content: string }[], context?: string): Promise<any> {
  return apiRequest('/chat', {
    method: 'POST',
    body: JSON.stringify({ messages, context }),
  });
}

// License API
export async function getLicenseStatus(): Promise<LicenseStatus> {
  return apiRequest<LicenseStatus>('/license/status');
}

export async function activateLicense(token: string, license_content?: string): Promise<any> {
  return apiRequest('/license/activate', {
    method: 'POST',
    body: JSON.stringify({ token, license_content: license_content || '' }),
  });
}

// CyberChef-Grade Crypto APIs
export async function calculateEntropy(text: string, is_hex: boolean = false): Promise<EntropyResult> {
  return apiRequest<EntropyResult>('/crypto/entropy', {
    method: 'POST',
    body: JSON.stringify({ text, is_hex }),
  });
}

export async function executeRecipe(input: string, recipe: Array<{ op: string; args?: any }>): Promise<RecipeResult> {
  return apiRequest<RecipeResult>('/crypto/recipe', {
    method: 'POST',
    body: JSON.stringify({ input, recipe }),
  });
}

export async function magicUnwrap(input: string, maxDepth: number = 8): Promise<MagicUnwrapResult> {
  return apiRequest<MagicUnwrapResult>('/crypto/magic-unwrap', {
    method: 'POST',
    body: JSON.stringify({ input, max_depth: maxDepth }),
  });
}

// Burp Suite-Grade Web APIs
export async function sendRepeater(
  url: string,
  method: string = 'GET',
  headers: Record<string, string> = {},
  cookies: Record<string, string> = {},
  body?: string
): Promise<RepeaterResponse> {
  return apiRequest<RepeaterResponse>('/web/repeater', {
    method: 'POST',
    body: JSON.stringify({ url, method, headers, cookies, body }),
  });
}

export async function scanVulnerabilities(url: string): Promise<ScannerResult> {
  return apiRequest<ScannerResult>('/web/scan-vulns', {
    method: 'POST',
    body: JSON.stringify({ url }),
  });
}
