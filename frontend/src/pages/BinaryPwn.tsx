import React, { useState } from 'react';
import { 
  FileCode2, 
  UploadCloud, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle, 
  RefreshCw, 
  Cpu, 
  ShieldCheck, 
  Terminal, 
  Flame,
  Code,
  Copy,
  Check
} from 'lucide-react';
import { inspectBinary, generateCyclicPattern, findCyclicOffset, CyclicFindResult } from '../api/client';
import { FlagCard } from '../components/FlagCard';

export const BinaryPwn: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedFunc, setSelectedFunc] = useState<string>('');
  const [copiedDisasm, setCopiedDisasm] = useState(false);

  // Cyclic Pattern & Offset Finder State
  const [cyclicLen, setCyclicLen] = useState(200);
  const [cyclicWidth, setCyclicWidth] = useState(4);
  const [generatedPattern, setGeneratedPattern] = useState('');
  const [cyclicQuery, setCyclicQuery] = useState('');
  const [findResult, setFindResult] = useState<CyclicFindResult | null>(null);
  const [copiedPattern, setCopiedPattern] = useState(false);
  const [copiedPayload, setCopiedPayload] = useState(false);
  const [cyclicLoading, setCyclicLoading] = useState(false);

  const handleGenerateCyclic = async () => {
    setCyclicLoading(true);
    try {
      const res = await generateCyclicPattern(cyclicLen, cyclicWidth);
      setGeneratedPattern(res.pattern);
    } catch (err: any) {
      setError(err.message || 'Pattern generation failed');
    } finally {
      setCyclicLoading(false);
    }
  };

  const handleFindOffset = async () => {
    if (!cyclicQuery.trim()) return;
    setCyclicLoading(true);
    try {
      const res = await findCyclicOffset(cyclicQuery.trim(), cyclicWidth);
      setFindResult(res);
    } catch (err: any) {
      setError(err.message || 'Offset lookup failed');
    } finally {
      setCyclicLoading(false);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const handleInspect = async () => {
    if (!file) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await inspectBinary(file);
      setResult(data);
      if (data.disassembly?.priority_functions?.length > 0) {
        setSelectedFunc(data.disassembly.priority_functions[0]);
      } else if (data.disassembly?.functions_found?.length > 0) {
        setSelectedFunc(data.disassembly.functions_found[0]);
      }
    } catch (err: any) {
      setError(err.message || 'Binary inspection failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div className="border-b border-slate-800 pb-4">
        <h2 className="text-xl font-semibold font-sans text-slate-100 flex items-center gap-2">
          <FileCode2 className="w-5 h-5 text-emerald-400" />
          Binary Mitigations (Checksec) & Dangerous Function Audit
        </h2>
        <p className="text-slate-400 text-xs mt-1 font-sans">
          Executable analysis (ELF & PE): NX/DEP, Stack Canary, PIE/ASLR, architecture target, and identification of dangerous C memory functions.
        </p>
      </div>

      {/* Upload Zone */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-6">
        <label className="border-2 border-dashed border-cyber-border hover:border-red-500/50 rounded-lg p-8 flex flex-col items-center justify-center cursor-pointer transition-all bg-cyber-dark/40 hover:bg-cyber-dark/80 group">
          <FileCode2 className="w-12 h-12 text-gray-500 group-hover:text-red-400 transition-colors mb-3" />
          <span className="text-sm font-medium text-gray-300 group-hover:text-white">
            {file ? file.name : "Select or drag & drop Linux ELF or Windows PE executable"}
          </span>
          <span className="text-xs text-gray-500 mt-1 font-mono">
            Accepts compiled binaries (no extension, .elf, .exe, .bin, .so)
          </span>
          <input type="file" className="hidden" onChange={handleFileChange} />
        </label>

        {file && (
          <div className="mt-4 flex items-center justify-between bg-cyber-dark px-4 py-3 rounded-lg border border-cyber-border">
            <div className="flex items-center gap-3">
              <Cpu className="w-5 h-5 text-red-400" />
              <div>
                <p className="text-sm font-mono text-white">{file.name}</p>
                <p className="text-xs text-gray-500">{(file.size / 1024).toFixed(1)} KB</p>
              </div>
            </div>
            <button
              onClick={handleInspect}
              disabled={loading}
              className="flex items-center gap-2 px-5 py-2 rounded-lg bg-red-500 text-white font-semibold text-sm hover:bg-red-600 disabled:opacity-50 transition-all font-mono"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Inspecting ELF Headers...
                </>
              ) : (
                'Run Checksec & Symbols'
              )}
            </button>
          </div>
        )}
      </div>

      {/* Cyclic Pattern Generator & Crash Offset Finder */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-cyber-border pb-3">
          <div className="flex items-center gap-2">
            <Terminal className="w-5 h-5 text-red-400" />
            <h3 className="text-white font-bold text-sm uppercase tracking-wider font-mono">
              [PWN] De Bruijn Cyclic Pattern & Crash Offset Finder
            </h3>
          </div>
          <span className="text-[11px] text-gray-500 font-mono">Pwntools cyclic() Replacement</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 font-mono text-xs">
          {/* Section 1: Generator */}
          <div className="space-y-3 bg-cyber-darker p-4 rounded-lg border border-cyber-border">
            <span className="text-red-400 font-bold uppercase tracking-wider block">
              1. Cyclic Pattern Generator
            </span>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-gray-400 block mb-1">Length (bytes)</label>
                <input
                  type="number"
                  value={cyclicLen}
                  onChange={(e) => setCyclicLen(parseInt(e.target.value) || 200)}
                  min={16}
                  max={20000}
                  className="w-full bg-black/60 border border-cyber-border rounded px-3 py-1.5 text-white focus:outline-none focus:border-red-500"
                />
              </div>
              <div>
                <label className="text-gray-400 block mb-1">Word Width</label>
                <select
                  value={cyclicWidth}
                  onChange={(e) => setCyclicWidth(parseInt(e.target.value))}
                  className="w-full bg-black/60 border border-cyber-border rounded px-3 py-1.5 text-white focus:outline-none focus:border-red-500"
                >
                  <option value={4}>4-byte (32-bit x86)</option>
                  <option value={8}>8-byte (64-bit AMD64)</option>
                </select>
              </div>
            </div>

            <button
              onClick={handleGenerateCyclic}
              disabled={cyclicLoading}
              className="w-full py-2 bg-red-500/20 border border-red-500/50 hover:bg-red-500/30 text-red-300 font-bold rounded transition-all flex items-center justify-center gap-2"
            >
              {cyclicLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Code className="w-3.5 h-3.5" />}
              Generate De Bruijn Sequence
            </button>

            {generatedPattern && (
              <div className="space-y-1.5 pt-1">
                <div className="flex items-center justify-between text-[11px] text-gray-400">
                  <span>Pattern ({generatedPattern.length} bytes):</span>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(generatedPattern);
                      setCopiedPattern(true);
                      setTimeout(() => setCopiedPattern(false), 2000);
                    }}
                    className="text-red-400 hover:text-white flex items-center gap-1"
                  >
                    {copiedPattern ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    {copiedPattern ? 'Copied!' : 'Copy'}
                  </button>
                </div>
                <textarea
                  readOnly
                  value={generatedPattern}
                  rows={3}
                  className="w-full bg-black/80 border border-cyber-border rounded p-2 text-white select-all break-all text-[11px]"
                />
              </div>
            )}
          </div>

          {/* Section 2: Offset Finder */}
          <div className="space-y-3 bg-cyber-darker p-4 rounded-lg border border-cyber-border">
            <span className="text-cyan-400 font-bold uppercase tracking-wider block">
              2. Crash Offset Lookup
            </span>
            <div>
              <label className="text-gray-400 block mb-1">
                Crash Register Value (Hex 0x... or ASCII)
              </label>
              <input
                type="text"
                value={cyclicQuery}
                onChange={(e) => setCyclicQuery(e.target.value)}
                placeholder="e.g. 0x61616167 or gaaa"
                className="w-full bg-black/60 border border-cyber-border rounded px-3 py-1.5 text-cyan-300 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <button
              onClick={handleFindOffset}
              disabled={cyclicLoading || !cyclicQuery.trim()}
              className="w-full py-2 bg-cyan-500/20 border border-cyan-500/50 hover:bg-cyan-500/30 text-cyan-300 font-bold rounded transition-all flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {cyclicLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Cpu className="w-3.5 h-3.5" />}
              Calculate Overflow Offset
            </button>

            {findResult && (
              <div className="space-y-2 pt-1">
                <div className={`p-3 rounded border ${findResult.found ? 'bg-emerald-950/30 border-emerald-500/40' : 'bg-red-950/30 border-red-500/40'}`}>
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white">
                      Offset: {findResult.found ? `${findResult.offset} bytes` : 'NOT FOUND'}
                    </span>
                    {findResult.found && (
                      <span className="text-[10px] bg-emerald-500/20 text-emerald-400 px-2 py-0.5 rounded font-bold">
                        MATCH CONFIRMED
                      </span>
                    )}
                  </div>
                  <p className="text-gray-400 text-[11px] mt-1">{findResult.suggestion}</p>
                </div>

                {findResult.found && findResult.offset !== null && (
                  <div className="bg-black/80 p-2.5 rounded border border-cyber-border space-y-1">
                    <div className="flex items-center justify-between text-[10px] text-gray-400">
                      <span>Python Pwntools Template:</span>
                      <button
                        onClick={() => {
                          const code = `payload = b'A' * ${findResult.offset} + p64(target_addr)`;
                          navigator.clipboard.writeText(code);
                          setCopiedPayload(true);
                          setTimeout(() => setCopiedPayload(false), 2000);
                        }}
                        className="text-cyan-400 hover:text-white flex items-center gap-1"
                      >
                        {copiedPayload ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        {copiedPayload ? 'Copied' : 'Copy Template'}
                      </button>
                    </div>
                    <code className="text-emerald-400 block select-all text-[11px]">
                      payload = b'A' * {findResult.offset} + p64(target_addr)
                    </code>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/50 flex items-start gap-3 text-red-200">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <h4 className="font-semibold text-sm">Binary Audit Error</h4>
            <p className="text-xs text-red-300 mt-0.5 font-mono">{error}</p>
          </div>
        </div>
      )}

      {result && (
        <div className="space-y-6">
          <FlagCard flags={result.flags_found || []} source={`Binary (${file?.name})`} />

          {/* Core Info */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-cyber-card border border-cyber-border p-4 rounded-xl font-mono">
              <span className="text-[10px] text-gray-500 uppercase block">Format</span>
              <p className="text-sm font-bold text-white mt-1">{result.format}</p>
            </div>
            <div className="bg-cyber-card border border-cyber-border p-4 rounded-xl font-mono">
              <span className="text-[10px] text-gray-500 uppercase block">Architecture</span>
              <p className="text-sm font-bold text-cyber-cyan mt-1">{result.architecture || `${result.bits}-bit`}</p>
            </div>
            <div className="bg-cyber-card border border-cyber-border p-4 rounded-xl font-mono">
              <span className="text-[10px] text-gray-500 uppercase block">Endianness</span>
              <p className="text-sm font-bold text-gray-300 mt-1">{result.endian || 'N/A'}</p>
            </div>
            <div className="bg-cyber-card border border-cyber-border p-4 rounded-xl font-mono">
              <span className="text-[10px] text-gray-500 uppercase block">Binary Type</span>
              <p className="text-sm font-bold text-purple-400 mt-1">{result.type || 'Standard'}</p>
            </div>
          </div>

          {/* Checksec Mitigations Card */}
          {result.checksec && (
            <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 space-y-4 font-mono">
              <div className="flex items-center gap-2 text-white font-bold text-sm border-b border-cyber-border pb-3 uppercase tracking-wider">
                <ShieldCheck className="w-4 h-4 text-cyber-green" />
                <span>Security Mitigations (Checksec)</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {Object.entries(result.checksec).map(([mitigation, status]: [string, any]) => {
                  const isSafe = String(status).toLowerCase().includes('enabled') || String(status).toLowerCase().includes('found');
                  const isVulnerable = String(status).toLowerCase().includes('disabled') || String(status).toLowerCase().includes('no stack') || String(status).toLowerCase().includes('no pie');

                  return (
                    <div 
                      key={mitigation}
                      className={`p-3.5 rounded-lg border text-xs flex items-start gap-3 ${
                        isVulnerable 
                          ? 'bg-red-950/20 border-red-500/40 text-red-300' 
                          : isSafe 
                          ? 'bg-cyber-green/10 border-cyber-green/30 text-cyber-green' 
                          : 'bg-cyber-darker border-cyber-border text-gray-400'
                      }`}
                    >
                      {isVulnerable ? (
                        <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                      ) : (
                        <CheckCircle2 className="w-4 h-4 text-cyber-green shrink-0 mt-0.5" />
                      )}
                      <div>
                        <span className="uppercase font-bold text-[11px] block">{mitigation}</span>
                        <p className="text-xs mt-0.5">{status}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Dangerous Imports / Exploitation Vectors */}
          {result.dangerous_imports && (
            <div className="bg-cyber-card border border-red-500/30 rounded-xl p-5 space-y-4 font-mono">
              <div className="flex items-center justify-between border-b border-cyber-border pb-3">
                <span className="text-red-400 font-bold text-sm flex items-center gap-2 uppercase tracking-wider">
                  <Flame className="w-4 h-4 text-red-400" />
                  <span>Exploitable & Dangerous Calls ({result.dangerous_imports.length})</span>
                </span>
                <span className="text-[11px] text-gray-500">Common Pwn targets</span>
              </div>

              {result.dangerous_imports.length === 0 ? (
                <p className="text-xs text-gray-500">No common dangerous functions directly detected in symbol table.</p>
              ) : (
                <div className="space-y-2">
                  {result.dangerous_imports.map((item: any, idx: number) => (
                    <div key={idx} className="bg-cyber-darker p-3 rounded-lg border border-red-500/30 flex items-start justify-between text-xs">
                      <div>
                        <span className="text-white font-bold text-sm font-mono text-red-400">{item.function}()</span>
                        <p className="text-gray-400 text-xs mt-1">{item.risk}</p>
                      </div>
                      <span className="px-2 py-0.5 rounded bg-red-950 text-red-300 text-[10px] uppercase font-bold border border-red-800 shrink-0">
                        ATTACK TARGET
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Disassembly & Function Routine Analysis */}
          {result.disassembly && result.disassembly.success && (
            <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 space-y-4 font-mono">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-cyber-border pb-3 gap-2">
                <div>
                  <h3 className="text-sm font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-2">
                    <Code className="w-4 h-4 text-emerald-400" />
                    <span>Linear Disassembly & Routine Inspection</span>
                  </h3>
                  <p className="text-[11px] text-gray-400 mt-0.5">
                    Intel syntax disassembly generated via {result.disassembly.used_tool || 'LLVM / GNU objdump'}
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      const text = result.disassembly.raw_preview || '';
                      navigator.clipboard.writeText(text);
                      setCopiedDisasm(true);
                      setTimeout(() => setCopiedDisasm(false), 2000);
                    }}
                    className="px-2.5 py-1 text-xs border border-cyber-border rounded hover:border-emerald-500/50 text-gray-300 hover:text-white flex items-center gap-1 transition-all"
                  >
                    {copiedDisasm ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedDisasm ? 'Copied' : 'Copy Assembly'}</span>
                  </button>
                </div>
              </div>

              {/* Dangerous Calls Radar */}
              {result.disassembly.dangerous_calls && result.disassembly.dangerous_calls.length > 0 && (
                <div className="bg-red-950/30 border border-red-500/40 p-3 rounded-lg space-y-1.5">
                  <span className="text-[11px] font-bold text-red-400 uppercase flex items-center gap-1.5">
                    <Flame className="w-3.5 h-3.5" />
                    [CRITICAL VECTORS] Direct Dangerous Function Calls Detected in Assembly ({result.disassembly.dangerous_calls.length})
                  </span>
                  <div className="space-y-1">
                    {result.disassembly.dangerous_calls.map((dc: any, idx: number) => (
                      <div key={idx} className="flex items-center justify-between text-xs bg-black/40 px-2 py-1 rounded">
                        <span className="text-gray-300">
                          Function <strong className="text-emerald-400">&lt;{dc.caller}&gt;</strong> calls <span className="text-red-400 font-bold">{dc.callee}()</span>
                        </span>
                        <span className="text-gray-500 font-mono text-[11px]">{dc.address}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Function Selector Pills */}
              {result.disassembly.functions_found && result.disassembly.functions_found.length > 0 && (
                <div className="space-y-2">
                  <span className="text-[10px] text-gray-500 uppercase font-bold block">
                    Disassembled Functions ({result.disassembly.functions_found.length}):
                  </span>
                  <div className="flex flex-wrap gap-1.5 text-xs">
                    {result.disassembly.functions_found.slice(0, 15).map((fName: string) => {
                      const isPriority = result.disassembly.priority_functions?.includes(fName);
                      const isSelected = selectedFunc === fName;
                      return (
                        <button
                          key={fName}
                          onClick={() => setSelectedFunc(fName)}
                          className={`px-2.5 py-1 rounded text-xs transition-all flex items-center gap-1 ${
                            isSelected
                              ? 'bg-emerald-500 text-black font-bold shadow'
                              : isPriority
                              ? 'bg-emerald-950/60 border border-emerald-500/50 text-emerald-300 hover:border-emerald-400'
                              : 'bg-cyber-darker border border-cyber-border text-gray-300 hover:text-white hover:border-gray-600'
                          }`}
                        >
                          {isPriority && <span className="text-[10px] font-bold text-emerald-400">*</span>}
                          <span>&lt;{fName}&gt;</span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Disassembly Code Container */}
              <div className="bg-black/60 border border-cyber-border rounded-lg p-3 max-h-96 overflow-y-auto space-y-1 text-xs">
                {selectedFunc && result.disassembly.functions?.[selectedFunc] ? (
                  <div className="space-y-1">
                    <div className="text-emerald-400 font-bold text-xs pb-1 border-b border-gray-800">
                      Disassembly for &lt;{selectedFunc}&gt; ({result.disassembly.functions[selectedFunc].length} instructions):
                    </div>
                    {result.disassembly.functions[selectedFunc].map((inst: any, idx: number) => {
                      const isCall = inst.mnemonic?.toLowerCase().includes('call');
                      return (
                        <div
                          key={idx}
                          className={`flex items-baseline gap-3 py-0.5 px-1 rounded hover:bg-white/5 ${
                            isCall ? 'bg-red-950/20 text-red-300' : 'text-gray-300'
                          }`}
                        >
                          <span className="text-gray-500 select-all w-24 shrink-0 font-mono text-[11px]">
                            {inst.address}
                          </span>
                          <span className="text-cyan-400 font-semibold w-16 shrink-0">
                            {inst.mnemonic}
                          </span>
                          <span className="text-white select-all flex-1">
                            {inst.operands}
                          </span>
                          {inst.comment && (
                            <span className="text-yellow-400/80 text-[11px] truncate max-w-xs">
                              ; {inst.comment}
                            </span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <pre className="text-gray-300 select-all whitespace-pre leading-relaxed text-xs">
                    {result.disassembly.raw_preview || 'No disassembly routines available.'}
                  </pre>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
