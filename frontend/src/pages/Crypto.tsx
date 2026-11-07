import React, { useState, useEffect } from 'react';
import { KeyRound, RefreshCw, AlertCircle, ArrowRight, Zap, Table, Sliders, Binary, Copy, Check, Cpu, Plus, Trash2, Layers, Gauge } from 'lucide-react';
import { decodeText, caesarAllShifts, vigenereTool, xorBruteforce, convertEndianness, calculateEntropy, executeRecipe, magicUnwrap } from '../api/client';
import { FlagCard } from '../components/FlagCard';
import { useApp } from '../context/AppContext';

export const Crypto: React.FC = () => {
  const { pipedData, clearPipedData, sendToTab } = useApp();
  const [activeSubTab, setActiveSubTab] = useState<'auto' | 'recipe' | 'entropy' | 'caesar' | 'vigenere' | 'xor' | 'endian'>('auto');

  useEffect(() => {
    if (pipedData && pipedData.targetTab === 'crypto' && pipedData.data) {
      setText(pipedData.data);
      setRecipeInput(pipedData.data);
      setEntropyInput(pipedData.data);
      clearPipedData();
    }
  }, [pipedData]);

  // CyberChef Recipe state
  const [recipeInput, setRecipeInput] = useState('464c41477b736861646f776361745f6379626572636865667d');
  const [selectedOps, setSelectedOps] = useState<string[]>(['from_hex']);
  const [recipeResult, setRecipeResult] = useState<any>(null);
  const [recipeLoading, setRecipeLoading] = useState(false);
  const [magicResult, setMagicResult] = useState<any>(null);
  const [magicLoading, setMagicLoading] = useState(false);

  // Entropy state
  const [entropyInput, setEntropyInput] = useState('');
  const [entropyIsHex, setEntropyIsHex] = useState(false);
  const [entropyResult, setEntropyResult] = useState<any>(null);
  const [entropyLoading, setEntropyLoading] = useState(false);

  // Auto decode state
  const [text, setText] = useState('');
  const [context, setContext] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  // Caesar matrix state
  const [caesarInput, setCaesarInput] = useState('');
  const [caesarShifts, setCaesarShifts] = useState<any[]>([]);
  const [caesarLoading, setCaesarLoading] = useState(false);

  // Vigenere state
  const [vigText, setVigText] = useState('');
  const [vigKey, setVigKey] = useState('');
  const [vigOutput, setVigOutput] = useState<any>(null);
  const [vigLoading, setVigLoading] = useState(false);

  // XOR Brute force state
  const [xorInput, setXorInput] = useState('');
  const [xorIsHex, setXorIsHex] = useState(true);
  const [xorCandidates, setXorCandidates] = useState<any[]>([]);
  const [xorLoading, setXorLoading] = useState(false);
  const [copiedXorKey, setCopiedXorKey] = useState<number | null>(null);

  // Endianness state
  const [endianInput, setEndianInput] = useState('0x08048492');
  const [endianResult, setEndianResult] = useState<any>(null);
  const [endianLoading, setEndianLoading] = useState(false);
  const [copiedEndianItem, setCopiedEndianItem] = useState<string | null>(null);

  const handleDecode = async () => {
    if (!text.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await decodeText(text, context);
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Decoding failed');
    } finally {
      setLoading(false);
    }
  };

  const handleCaesarMatrix = async () => {
    if (!caesarInput.trim()) return;
    setCaesarLoading(true);
    try {
      const res = await caesarAllShifts(caesarInput.trim());
      setCaesarShifts(res.shifts || []);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setCaesarLoading(false);
    }
  };

  const handleVigenere = async (decrypt: boolean = true) => {
    if (!vigText.trim() || !vigKey.trim()) return;
    setVigLoading(true);
    try {
      const res = await vigenereTool(vigText.trim(), vigKey.trim(), decrypt);
      setVigOutput(res);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setVigLoading(false);
    }
  };

  const handleXorBruteforce = async () => {
    if (!xorInput.trim()) return;
    setXorLoading(true);
    setError(null);
    try {
      const res = await xorBruteforce(xorInput.trim(), xorIsHex);
      setXorCandidates(res.candidates || []);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setXorLoading(false);
    }
  };

  const handleConvertEndian = async () => {
    if (!endianInput.trim()) return;
    setEndianLoading(true);
    try {
      const res = await convertEndianness(endianInput.trim());
      setEndianResult(res);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setEndianLoading(false);
    }
  };

  const handleBakeRecipe = async () => {
    if (!recipeInput.trim() || selectedOps.length === 0) return;
    setRecipeLoading(true);
    setError(null);
    try {
      const recipePayload = selectedOps.map((op) => ({ op }));
      const data = await executeRecipe(recipeInput.trim(), recipePayload);
      setRecipeResult(data);
    } catch (err: any) {
      setError(err.message || 'Recipe execution failed');
    } finally {
      setRecipeLoading(false);
    }
  };

  const handleMagicUnwrap = async () => {
    if (!recipeInput.trim()) return;
    setMagicLoading(true);
    setError(null);
    setMagicResult(null);
    try {
      const res = await magicUnwrap(recipeInput.trim(), 8);
      setMagicResult(res);
    } catch (err: any) {
      setError(err.message || 'Magic unwrap failed');
    } finally {
      setMagicLoading(false);
    }
  };

  const handleCalcEntropy = async () => {
    if (!entropyInput.trim()) return;
    setEntropyLoading(true);
    setError(null);
    try {
      const data = await calculateEntropy(entropyInput.trim(), entropyIsHex);
      setEntropyResult(data);
    } catch (err: any) {
      setError(err.message || 'Entropy calculation failed');
    } finally {
      setEntropyLoading(false);
    }
  };

  const handleCopyText = (val: string, key: string) => {
    navigator.clipboard.writeText(val);
    setCopiedEndianItem(key);
    setTimeout(() => setCopiedEndianItem(null), 2000);
  };

  const sampleInputs = [
    { label: 'Base64 Flag', val: 'cGljb0NURntiNHMzNjRfM25jMGQxbmdfMXM0X2Z1bn0=' },
    { label: 'Hex String', val: '666c61677b683378305f31735f346d347a316e677d' },
    { label: 'ROT13 Cipher', val: 'cvpbPGS{e0g13_1f_f4_s4s4_c1p0PGS}' },
    { label: 'Binary Bits', val: '01100110 01101100 01100001 01100111 01111011 01100010 00110001 01101110 00110100 01110010 01111001 01111101' },
    { label: 'JWT Token', val: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJmbGFnIjoicGljb0NURntkMGNfeTB1X2duMHdfand0X3kwdV9nMHRfMXR9In0.fakesig' }
  ];

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div className="border-b border-slate-800 pb-4">
        <h2 className="text-xl font-semibold font-sans text-slate-100 flex items-center gap-2">
          <KeyRound className="w-5 h-5 text-emerald-400" />
          Cryptanalysis & Multi-Cipher Decoding Engine
        </h2>
        <p className="text-slate-400 text-xs mt-1 font-sans">
          Autonomous multi-layer decoding covering 20+ encoding schemes, Caesar shifts, Vigenère cipher, single-byte XOR brute-force, and memory endianness.
        </p>
      </div>

      {/* Tabs Switcher */}
      <div className="flex border-b border-cyber-border gap-2 overflow-x-auto">
        <button
          onClick={() => setActiveSubTab('auto')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-mono rounded-t-lg transition-all border-t border-x shrink-0 ${
            activeSubTab === 'auto'
              ? 'bg-cyber-card border-cyber-green text-cyber-green font-bold'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          <Zap className="w-4 h-4" />
          Auto-Decoder & Attack Chain
        </button>
        <button
          onClick={() => {
            setActiveSubTab('recipe');
            if (!recipeResult) handleBakeRecipe();
          }}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-mono rounded-t-lg transition-all border-t border-x shrink-0 ${
            activeSubTab === 'recipe'
              ? 'bg-cyber-card border-emerald-400 text-emerald-400 font-bold'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          <Cpu className="w-4 h-4" />
          CyberChef Recipe Pipeline
        </button>
        <button
          onClick={() => setActiveSubTab('entropy')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-mono rounded-t-lg transition-all border-t border-x shrink-0 ${
            activeSubTab === 'entropy'
              ? 'bg-cyber-card border-yellow-400 text-yellow-300 font-bold'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          <Binary className="w-4 h-4" />
          Shannon Entropy Meter
        </button>
        <button
          onClick={() => setActiveSubTab('caesar')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-mono rounded-t-lg transition-all border-t border-x shrink-0 ${
            activeSubTab === 'caesar'
              ? 'bg-cyber-card border-cyber-cyan text-cyber-cyan font-bold'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          <Table className="w-4 h-4" />
          Caesar 25-Shift Matrix
        </button>
        <button
          onClick={() => setActiveSubTab('vigenere')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-mono rounded-t-lg transition-all border-t border-x shrink-0 ${
            activeSubTab === 'vigenere'
              ? 'bg-cyber-card border-purple-500 text-purple-300 font-bold'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          <Sliders className="w-4 h-4" />
          Vigenere Key Tool
        </button>
        <button
          onClick={() => setActiveSubTab('xor')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-mono rounded-t-lg transition-all border-t border-x shrink-0 ${
            activeSubTab === 'xor'
              ? 'bg-cyber-card border-yellow-500 text-yellow-300 font-bold'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          <Binary className="w-4 h-4" />
          XOR 256-Key Brute-Force
        </button>
        <button
          onClick={() => {
            setActiveSubTab('endian');
            if (!endianResult) handleConvertEndian();
          }}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-mono rounded-t-lg transition-all border-t border-x shrink-0 ${
            activeSubTab === 'endian'
              ? 'bg-cyber-card border-red-500 text-red-300 font-bold'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          <Cpu className="w-4 h-4" />
          Endianness & Pwntools
        </button>
      </div>

      {/* SUBTAB 1: Auto Decoder */}
      {activeSubTab === 'auto' && (
        <div className="space-y-6">
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 space-y-4">
            <div>
              <label className="block text-xs font-mono uppercase text-gray-400 mb-2">
                Ciphertext / Encoded String
              </label>
              <textarea
                value={text}
                onChange={(e) => setText(e.target.value)}
                rows={4}
                placeholder="Paste ciphertext, Base64, Hex, JWT, or obfuscated message here..."
                className="w-full bg-cyber-darker border border-cyber-border rounded-lg p-3 text-sm font-mono text-white placeholder-gray-600 focus:outline-none focus:border-cyber-green/60"
              />
            </div>

            <div>
              <label className="block text-xs font-mono uppercase text-gray-400 mb-2">
                Optional Hint / Challenge Context
              </label>
              <input
                type="text"
                value={context}
                onChange={(e) => setContext(e.target.value)}
                placeholder="e.g. 'Found in Caesar challenge' or key hints"
                className="w-full bg-cyber-darker border border-cyber-border rounded-lg px-3 py-2 text-sm font-mono text-white placeholder-gray-600 focus:outline-none focus:border-cyber-green/60"
              />
            </div>

            {/* Quick Samples */}
            <div className="flex flex-wrap items-center gap-2 pt-1">
              <span className="text-xs text-gray-500 font-mono">Presets:</span>
              {sampleInputs.map((sample, idx) => (
                <button
                  key={idx}
                  onClick={() => setText(sample.val)}
                  className="text-xs font-mono px-2.5 py-1 rounded bg-cyber-dark border border-cyber-border hover:border-cyber-cyan/50 text-gray-300 hover:text-cyber-cyan transition-colors"
                >
                  {sample.label}
                </button>
              ))}
            </div>

            <button
              onClick={handleDecode}
              disabled={loading || !text.trim()}
              className="flex items-center gap-2 px-6 py-2.5 rounded-lg bg-cyber-green text-black font-semibold text-sm hover:bg-cyber-green/90 disabled:opacity-50 transition-all font-mono"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Decrypting & Cracking...
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4" />
                  Auto-Decode & Attack
                </>
              )}
            </button>
          </div>

          {error && (
            <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/50 flex items-start gap-3 text-red-200">
              <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
              <div>
                <h4 className="font-semibold text-sm">Decoding Failed</h4>
                <p className="text-xs text-red-300 mt-0.5 font-mono">{error}</p>
              </div>
            </div>
          )}

          {result && (
            <div className="space-y-6">
              <FlagCard flags={result.flags_found || []} source="Crypto Auto-Decoder" />

              {/* Detections */}
              {result.auto_detect && result.auto_detect.length > 0 && (
                <div className="bg-cyber-card border border-cyber-border rounded-xl p-5">
                  <h3 className="text-sm font-bold font-mono text-cyber-cyan uppercase tracking-wider mb-3">
                    Detected Encodings & Candidates ({result.auto_detect.length})
                  </h3>
                  <div className="space-y-3">
                    {result.auto_detect.map((d: any, idx: number) => (
                      <div key={idx} className="bg-cyber-darker border border-cyber-border p-3.5 rounded-lg font-mono text-xs">
                        <div className="flex items-center justify-between mb-1.5">
                          <span className="text-cyber-green font-semibold text-sm">[{d.encoding}]</span>
                          <span className="text-gray-500">Confidence: {(d.confidence * 100).toFixed(0)}%</span>
                        </div>
                        <pre className="text-gray-300 overflow-x-auto p-2 bg-black/50 rounded select-all whitespace-pre-wrap break-all">
                          {d.decoded}
                        </pre>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recursive Chain */}
              {result.recursive_chain && result.recursive_chain.length > 0 && (
                <div className="bg-cyber-card border border-cyber-border rounded-xl p-5">
                  <h3 className="text-sm font-bold font-mono text-purple-400 uppercase tracking-wider mb-3">
                    Recursive Multi-Layer Chain
                  </h3>
                  <div className="space-y-2">
                    {result.recursive_chain.map((c: any, idx: number) => (
                      <div key={idx} className="flex items-center gap-2 text-xs font-mono bg-cyber-darker p-2.5 rounded border border-cyber-border">
                        <ArrowRight className="w-4 h-4 text-purple-400 shrink-0" />
                        <span className="text-purple-300 font-bold">[{c.encoding}]</span>
                        <span className="text-gray-300 truncate flex-1">{c.output}</span>
                        {c.flags_found && c.flags_found.length > 0 && (
                          <span className="bg-cyber-green/20 text-cyber-green px-2 py-0.5 rounded font-bold">
                            FLAG!
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* AI Analysis */}
              {result.ai_analysis && (
                <div className="bg-cyber-card border border-cyber-border rounded-xl p-5">
                  <h3 className="text-sm font-bold font-mono text-gray-300 uppercase tracking-wider mb-2">
                    AI Deep Cryptanalysis
                  </h3>
                  <div className="text-sm text-gray-300 whitespace-pre-wrap font-mono bg-cyber-darker p-4 rounded-lg border border-cyber-border">
                    {result.ai_analysis}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* SUBTAB 2: CyberChef Recipe Pipeline */}
      {activeSubTab === 'recipe' && (
        <div className="space-y-6">
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 space-y-5">
            <div className="flex items-center justify-between border-b border-cyber-border pb-3">
              <div>
                <h3 className="text-sm font-bold font-mono text-emerald-400 uppercase tracking-wider flex items-center gap-2">
                  <Cpu className="w-4 h-4" />
                  CyberChef Multi-Stage Recipe Pipeline
                </h3>
                <p className="text-gray-400 text-xs mt-0.5">
                  Chain atomic transformation, decoding, and decompression operations sequentially to crack complex multi-layer challenges.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setSelectedOps([])}
                  className="px-2.5 py-1 text-xs font-mono text-gray-400 hover:text-red-400 border border-cyber-border rounded hover:border-red-500/50 transition-all flex items-center gap-1"
                >
                  <Trash2 className="w-3 h-3" />
                  Clear Pipeline
                </button>
              </div>
            </div>

            {/* Recipe Presets */}
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
              <span className="text-gray-500 uppercase text-[10px] font-bold">Quick Presets:</span>
              <button
                onClick={() => {
                  setSelectedOps(['from_hex']);
                  setRecipeInput('464c41477b736861646f776361745f6379626572636865667d');
                }}
                className="px-2 py-0.5 rounded bg-cyber-darker border border-cyber-border text-gray-300 hover:text-emerald-400 hover:border-emerald-500/50"
              >
                Hex to ASCII
              </button>
              <button
                onClick={() => {
                  setSelectedOps(['from_base64', 'gzip_decompress']);
                  setRecipeInput('H4sICN6qcmcCA3Rlc3QudHh0AMtIzcnJVyjPL8pJUeTiAgDq9f2AEAAAAA==');
                }}
                className="px-2 py-0.5 rounded bg-cyber-darker border border-cyber-border text-gray-300 hover:text-emerald-400 hover:border-emerald-500/50"
              >
                Base64 to Gunzip
              </button>
              <button
                onClick={() => {
                  setSelectedOps(['from_base85', 'rot13']);
                  setRecipeInput('BOu!rD]j7BEbo7');
                }}
                className="px-2 py-0.5 rounded bg-cyber-darker border border-cyber-border text-gray-300 hover:text-emerald-400 hover:border-emerald-500/50"
              >
                Base85 to ROT13
              </button>
              <button
                onClick={() => {
                  setSelectedOps(['rot47', 'reverse']);
                  setRecipeInput('k^!~44!v~_');
                }}
                className="px-2 py-0.5 rounded bg-cyber-darker border border-cyber-border text-gray-300 hover:text-emerald-400 hover:border-emerald-500/50"
              >
                ROT47 to Reverse
              </button>
            </div>

            {/* Pipeline Stage Visualizer */}
            <div className="bg-cyber-darker border border-cyber-border rounded-lg p-4 space-y-3">
              <div className="flex items-center justify-between text-xs font-mono text-gray-400">
                <span className="uppercase font-bold flex items-center gap-1.5">
                  <Layers className="w-3.5 h-3.5 text-emerald-400" />
                  Active Execution Recipe ({selectedOps.length} Operations)
                </span>
                <span className="text-[11px] text-gray-500">Ordered execution: left-to-right</span>
              </div>

              {selectedOps.length === 0 ? (
                <div className="text-center py-4 border border-dashed border-gray-700 rounded text-xs font-mono text-gray-500">
                  No operations added yet. Click available operations below to construct your pipeline.
                </div>
              ) : (
                <div className="flex flex-wrap items-center gap-2">
                  {selectedOps.map((op, idx) => (
                    <div
                      key={idx}
                      className="flex items-center gap-1.5 bg-emerald-950/40 border border-emerald-500/50 text-emerald-300 px-2.5 py-1 rounded text-xs font-mono shadow-sm"
                    >
                      <span className="text-[10px] text-emerald-500 font-bold">#{idx + 1}</span>
                      <span className="font-semibold uppercase">{op.replace(/_/g, ' ')}</span>
                      <button
                        onClick={() => setSelectedOps(selectedOps.filter((_, i) => i !== idx))}
                        className="text-gray-400 hover:text-red-400 ml-1"
                        title="Remove step"
                      >
                        x
                      </button>
                      {idx < selectedOps.length - 1 && (
                        <ArrowRight className="w-3 h-3 text-emerald-500/60 ml-1" />
                      )}
                    </div>
                  ))}
                </div>
              )}

              {/* Available Operations Picker */}
              <div className="pt-2 border-t border-cyber-border space-y-2">
                <span className="text-[10px] font-mono uppercase text-gray-500 block font-bold">Add Operation To Recipe:</span>
                <div className="flex flex-wrap gap-1.5 font-mono text-[11px]">
                  {[
                    { id: 'from_hex', label: 'From Hex' },
                    { id: 'to_hex', label: 'To Hex' },
                    { id: 'from_base64', label: 'From Base64' },
                    { id: 'to_base64', label: 'To Base64' },
                    { id: 'from_base58', label: 'From Base58' },
                    { id: 'to_base58', label: 'To Base58' },
                    { id: 'from_base85', label: 'From Base85' },
                    { id: 'to_base85', label: 'To Base85' },
                    { id: 'url_decode', label: 'URL Decode' },
                    { id: 'url_encode', label: 'URL Encode' },
                    { id: 'rot13', label: 'ROT13' },
                    { id: 'rot47', label: 'ROT47' },
                    { id: 'atbash', label: 'Atbash' },
                    { id: 'reverse', label: 'Reverse' },
                    { id: 'gzip_decompress', label: 'Gunzip' },
                    { id: 'zlib_decompress', label: 'Zlib Inflate' },
                    { id: 'brainfuck', label: 'Brainfuck VM' }
                  ].map((item) => (
                    <button
                      key={item.id}
                      onClick={() => setSelectedOps([...selectedOps, item.id])}
                      className="px-2 py-1 rounded bg-black/40 border border-cyber-border hover:border-emerald-400/80 hover:text-emerald-300 text-gray-300 transition-all flex items-center gap-1"
                    >
                      <Plus className="w-2.5 h-2.5 text-emerald-400" />
                      {item.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Input payload */}
            <div>
              <label className="block text-xs font-mono uppercase text-gray-400 mb-1.5 font-bold">
                Input Payload
              </label>
              <textarea
                value={recipeInput}
                onChange={(e) => setRecipeInput(e.target.value)}
                rows={4}
                placeholder="Paste payload or encoded data here..."
                className="w-full bg-cyber-darker border border-cyber-border rounded-lg p-3 text-sm font-mono text-white placeholder-gray-600 focus:outline-none focus:border-emerald-500"
              />
            </div>

            {/* Execution CTA */}
            <div className="flex flex-wrap items-center gap-3">
              <button
                onClick={handleBakeRecipe}
                disabled={recipeLoading || selectedOps.length === 0 || !recipeInput.trim()}
                className="flex items-center gap-2 px-6 py-2.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-black font-mono font-bold text-xs transition-all disabled:opacity-50"
              >
                {recipeLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Cpu className="w-4 h-4" />}
                <span>Bake Recipe Pipeline</span>
              </button>
              <button
                onClick={handleMagicUnwrap}
                disabled={magicLoading || !recipeInput.trim()}
                className="flex items-center gap-2 px-6 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-mono font-bold text-xs transition-all disabled:opacity-50"
              >
                {magicLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                <span>Autonomous Magic Auto-Unwrap</span>
              </button>
              <span className="text-xs font-mono text-gray-500">
                {selectedOps.length} step(s) ready to bake, or 1-click auto unwrap
              </span>
            </div>
          </div>

          {/* Autonomous Magic Unwrap Results */}
          {magicResult && (
            <div className="space-y-4 font-mono">
              {magicResult.flags_found && magicResult.flags_found.length > 0 && (
                <FlagCard flags={magicResult.flags_found} source="Magic Auto-Unwrap" />
              )}

              <div className="bg-cyber-card border border-cyan-500/40 rounded-xl p-5 space-y-3">
                <div className="flex items-center justify-between border-b border-cyber-border pb-2">
                  <span className="text-xs font-bold text-cyan-300 uppercase flex items-center gap-2">
                    <Zap className="w-4 h-4 text-cyan-400" />
                    Autonomous Unwrap Steps ({magicResult.depth || 0} Layers Decoded)
                  </span>
                  <span className="text-[11px] text-gray-400">
                    Status: {magicResult.success ? 'SOLVED' : 'UNRESOLVED'}
                  </span>
                </div>

                {magicResult.recipe && magicResult.recipe.length > 0 && (
                  <div className="flex flex-wrap items-center gap-2 py-1">
                    {magicResult.recipe.map((step: any, idx: number) => (
                      <div
                        key={idx}
                        className="flex items-center gap-1.5 bg-cyan-950/40 border border-cyan-500/40 text-cyan-200 px-2.5 py-1 rounded text-xs"
                      >
                        <span className="text-[10px] text-cyan-400 font-bold">L{step.step}</span>
                        <span className="font-semibold uppercase">{step.op.replace(/_/g, ' ')}</span>
                        {idx < magicResult.recipe.length - 1 && (
                          <ArrowRight className="w-3 h-3 text-cyan-500/60 ml-1" />
                        )}
                      </div>
                    ))}
                  </div>
                )}

                <div className="space-y-1.5 pt-2">
                  <div className="flex items-center justify-between text-xs text-gray-400">
                    <span>Unwrapped Result:</span>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(magicResult.output || '');
                        handleCopyText(magicResult.output || '', 'magic_out');
                      }}
                      className="text-cyan-400 hover:text-white flex items-center gap-1"
                    >
                      {copiedEndianItem === 'magic_out' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      {copiedEndianItem === 'magic_out' ? 'Copied' : 'Copy Output'}
                    </button>
                  </div>
                  <pre className="bg-black/80 border border-cyber-border rounded p-3 text-white select-all break-all whitespace-pre-wrap text-xs">
                    {magicResult.output || 'No output'}
                  </pre>
                </div>
              </div>
            </div>
          )}

          {/* Recipe Execution Results */}
          {recipeResult && (
            <div className="space-y-5">
              {/* Flag notification if detected */}
              {recipeResult.flags_found && recipeResult.flags_found.length > 0 && (
                <FlagCard flags={recipeResult.flags_found} source="CyberChef Pipeline" />
              )}

              {/* Final Baked Result */}
              <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 space-y-3 font-mono">
                <div className="flex items-center justify-between border-b border-cyber-border pb-2">
                  <span className="text-xs font-bold text-emerald-400 uppercase flex items-center gap-2">
                    <Check className="w-4 h-4 text-emerald-400" />
                    Final Baked Output ({recipeResult.output_length || 0} bytes)
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => sendToTab('hash', recipeResult.output || '')}
                      className="px-2 py-1 rounded bg-slate-900 border border-slate-700 hover:border-yellow-500/50 text-gray-300 hover:text-yellow-400 text-[11px] flex items-center gap-1 transition-all"
                      title="Pipe baked output to Hash Cracker"
                    >
                      <span>{'[-> Hash]'}</span>
                    </button>
                    <button
                      onClick={() => sendToTab('jwt', recipeResult.output || '')}
                      className="px-2 py-1 rounded bg-slate-900 border border-slate-700 hover:border-purple-500/50 text-gray-300 hover:text-purple-400 text-[11px] flex items-center gap-1 transition-all"
                      title="Pipe baked output to JWT Studio"
                    >
                      <span>{'[-> JWT]'}</span>
                    </button>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(recipeResult.output || '');
                        handleCopyText(recipeResult.output || '', 'recipe_out');
                      }}
                      className="p-1.5 text-gray-400 hover:text-white flex items-center gap-1 text-xs"
                    >
                      {copiedEndianItem === 'recipe_out' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>Copy Result</span>
                    </button>
                  </div>
                </div>
                <pre className="text-white text-sm bg-black/60 p-4 rounded-lg border border-cyber-border select-all whitespace-pre-wrap break-all max-h-80 overflow-y-auto">
                  {recipeResult.output}
                </pre>
              </div>

              {/* Intermediate Step Audit */}
              {recipeResult.steps && recipeResult.steps.length > 0 && (
                <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 space-y-3 font-mono text-xs">
                  <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider">
                    Execution Trace & Intermediate States
                  </h4>
                  <div className="space-y-2">
                    {recipeResult.steps.map((st: any) => (
                      <div key={st.step} className="bg-cyber-darker border border-cyber-border p-3 rounded-lg space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="text-emerald-400 font-bold uppercase">
                            Step #{st.step}: [{st.operation}]
                          </span>
                          <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                            st.success ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/40' : 'bg-red-950 text-red-400 border border-red-500/40'
                          }`}>
                            {st.success ? '[OK] PROCESSED' : '[ERROR]'}
                          </span>
                        </div>
                        <p className="text-gray-400 text-[11px] truncate select-all">
                          Output: {st.output_preview}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* SUBTAB 3: Shannon Entropy Meter */}
      {activeSubTab === 'entropy' && (
        <div className="space-y-6 font-mono text-xs">
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 space-y-5">
            <div className="flex items-center justify-between border-b border-cyber-border pb-3">
              <div>
                <h3 className="text-sm font-bold text-yellow-400 uppercase tracking-wider flex items-center gap-2">
                  <Gauge className="w-4 h-4" />
                  Shannon Entropy & Randomness Analyzer
                </h3>
                <p className="text-gray-400 text-xs mt-0.5">
                  Calculate bits of entropy per byte (0.0 to 8.0 bits) to identify compressed streams, encrypted payloads, and packed code.
                </p>
              </div>
            </div>

            {/* Presets */}
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span className="text-gray-500 uppercase text-[10px] font-bold">Samples:</span>
              <button
                onClick={() => {
                  setEntropyInput('The quick brown fox jumps over the lazy dog. Cybersecurity CTF challenge flag string.');
                  setEntropyIsHex(false);
                }}
                className="px-2 py-0.5 rounded bg-cyber-darker border border-cyber-border text-gray-300 hover:text-yellow-400"
              >
                Plaintext ASCII (~4.1 bits)
              </button>
              <button
                onClick={() => {
                  setEntropyInput('cGljb0NURntzaGFkb3djYXRfY3liZXJjaGVmX2VudHJvcHlfMDgyNH0=');
                  setEntropyIsHex(false);
                }}
                className="px-2 py-0.5 rounded bg-cyber-darker border border-cyber-border text-gray-300 hover:text-yellow-400"
              >
                Base64 String (~5.6 bits)
              </button>
              <button
                onClick={() => {
                  setEntropyInput('e8409b8d2345d8b76251b68e983421d098ab2134cdef12876543120956784321fa89bcaef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abc');
                  setEntropyIsHex(true);
                }}
                className="px-2 py-0.5 rounded bg-cyber-darker border border-cyber-border text-gray-300 hover:text-yellow-400"
              >
                AES-256 Key Hex (~7.9 bits)
              </button>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-gray-400 uppercase font-bold">
                  Input Stream / Buffer
                </label>
                <label className="text-gray-400 cursor-pointer flex items-center gap-1.5 text-[11px]">
                  <input
                    type="checkbox"
                    checked={entropyIsHex}
                    onChange={(e) => setEntropyIsHex(e.target.checked)}
                    className="rounded bg-cyber-darker border-cyber-border text-yellow-500 focus:ring-0"
                  />
                  <span>Treat input as Hex byte string</span>
                </label>
              </div>
              <textarea
                value={entropyInput}
                onChange={(e) => setEntropyInput(e.target.value)}
                rows={4}
                placeholder="Paste raw text or hex data here to gauge Shannon entropy..."
                className="w-full bg-cyber-darker border border-cyber-border rounded-lg p-3 text-sm font-mono text-white placeholder-gray-600 focus:outline-none focus:border-yellow-500"
              />
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={handleCalcEntropy}
                disabled={entropyLoading || !entropyInput.trim()}
                className="flex items-center gap-2 px-6 py-2.5 rounded-lg bg-yellow-500 hover:bg-yellow-400 text-black font-bold text-xs transition-all disabled:opacity-50"
              >
                {entropyLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Gauge className="w-4 h-4" />}
                <span>Calculate Shannon Entropy</span>
              </button>
            </div>
          </div>

          {/* Entropy Result Visualization */}
          {entropyResult && (
            <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* Metric 1: Entropy Score */}
                <div className="bg-cyber-darker border border-cyber-border rounded-lg p-4 space-y-1">
                  <span className="text-[10px] text-gray-500 uppercase font-bold block">Shannon Entropy Score</span>
                  <div className="flex items-baseline gap-2">
                    <span className="text-2xl font-bold text-yellow-400">{entropyResult.entropy}</span>
                    <span className="text-gray-500 text-xs">/ 8.00 bits/byte</span>
                  </div>
                  <div className="w-full bg-black/60 rounded-full h-2 mt-2 overflow-hidden border border-cyber-border">
                    <div
                      className={`h-full ${
                        entropyResult.entropy > 6.8
                          ? 'bg-red-500'
                          : entropyResult.entropy > 4.5
                          ? 'bg-yellow-500'
                          : 'bg-emerald-500'
                      }`}
                      style={{ width: `${Math.min(100, (entropyResult.entropy / 8.0) * 100)}%` }}
                    />
                  </div>
                </div>

                {/* Metric 2: Stream Density */}
                <div className="bg-cyber-darker border border-cyber-border rounded-lg p-4 space-y-1">
                  <span className="text-[10px] text-gray-500 uppercase font-bold block">Stream Properties</span>
                  <div className="text-sm text-gray-300 space-y-0.5">
                    <div>Length: <span className="text-white font-bold">{entropyResult.length} bytes</span></div>
                    <div>Unique Symbols: <span className="text-white font-bold">{entropyResult.unique_bytes} / 256</span></div>
                  </div>
                </div>

                {/* Metric 3: Classification */}
                <div className="bg-cyber-darker border border-cyber-border rounded-lg p-4 space-y-1">
                  <span className="text-[10px] text-gray-500 uppercase font-bold block">Stream Classification</span>
                  <span className={`inline-block px-2 py-0.5 rounded text-[11px] font-bold ${
                    entropyResult.is_likely_encrypted_or_compressed
                      ? 'bg-red-950/60 text-red-400 border border-red-500/50'
                      : 'bg-emerald-950/60 text-emerald-400 border border-emerald-500/50'
                  }`}>
                    {entropyResult.classification}
                  </span>
                  <p className="text-[10px] text-gray-400 mt-1">
                    {entropyResult.is_likely_encrypted_or_compressed
                      ? '[!] High density consistent with AES/RC4 ciphertext or gzip/deflate.'
                      : '[OK] Natural dispersion consistent with plaintext language or script.'}
                  </p>
                </div>
              </div>

              {/* Assessment Narrative */}
              <div className="bg-cyber-darker border border-cyber-border rounded-lg p-4 space-y-1.5">
                <span className="text-[10px] text-gray-500 uppercase font-bold block">Heuristic Assessment</span>
                <p className="text-gray-300 text-xs leading-relaxed">
                  {entropyResult.assessment}
                </p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* SUBTAB 4: Caesar 25-Shift Matrix */}
      {activeSubTab === 'caesar' && (
        <div className="space-y-4">
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 space-y-3">
            <label className="text-xs font-mono text-gray-400 uppercase">Input Ciphertext</label>
            <input
              type="text"
              value={caesarInput}
              onChange={(e) => setCaesarInput(e.target.value)}
              placeholder="e.g. cvpbPGS{e0g13_1f_f4_s4s4_c1p0PGS}"
              className="w-full bg-cyber-darker border border-cyber-border rounded-lg px-3 py-2 text-sm font-mono text-white placeholder-gray-600 focus:outline-none focus:border-cyber-cyan"
            />
            <button
              onClick={handleCaesarMatrix}
              disabled={caesarLoading || !caesarInput.trim()}
              className="px-5 py-2 rounded-lg bg-cyber-cyan text-black font-semibold text-xs font-mono hover:bg-cyber-cyan/90 transition-all flex items-center gap-1.5"
            >
              {caesarLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Table className="w-3.5 h-3.5" />}
              Generate All 25 Shifts
            </button>
          </div>

          {caesarShifts.length > 0 && (
            <div className="bg-cyber-card border border-cyber-border rounded-xl p-4 overflow-hidden">
              <h4 className="text-xs font-mono text-gray-400 uppercase mb-3">All 25 Shift Variations</h4>
              <div className="space-y-1.5 max-h-[60vh] overflow-y-auto font-mono text-xs pr-2">
                {caesarShifts.map((s) => (
                  <div
                    key={s.shift}
                    className={`flex items-center justify-between p-2.5 rounded border transition-colors ${
                      s.has_flag
                        ? 'bg-cyber-green/10 border-cyber-green/50 text-cyber-green font-bold glow-green'
                        : 'bg-cyber-darker border-cyber-border text-gray-300'
                    }`}
                  >
                    <div className="flex items-center gap-3 select-all truncate">
                      <span className="w-16 shrink-0 text-gray-500 text-[11px]">Shift {s.shift}:</span>
                      <span className="truncate">{s.text}</span>
                    </div>
                    {s.has_flag && (
                      <span className="px-2 py-0.5 rounded bg-cyber-green text-black font-bold text-[10px] shrink-0">
                        FLAG DETECTED
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* SUBTAB 3: Vigenere Tool */}
      {activeSubTab === 'vigenere' && (
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 space-y-4 font-mono text-xs">
          <div>
            <label className="text-gray-400 uppercase block mb-1.5">Text (Plaintext or Ciphertext)</label>
            <textarea
              value={vigText}
              onChange={(e) => setVigText(e.target.value)}
              rows={3}
              placeholder="Enter text to encrypt or decrypt..."
              className="w-full bg-cyber-darker border border-cyber-border rounded-lg p-3 text-white placeholder-gray-600 focus:outline-none focus:border-purple-500"
            />
          </div>

          <div>
            <label className="text-gray-400 uppercase block mb-1.5">Secret Key</label>
            <input
              type="text"
              value={vigKey}
              onChange={(e) => setVigKey(e.target.value)}
              placeholder="e.g. SECRET or KEYWORD"
              className="w-full bg-cyber-darker border border-cyber-border rounded-lg px-3 py-2 text-white placeholder-gray-600 focus:outline-none focus:border-purple-500"
            />
          </div>

          <div className="flex items-center gap-2 pt-2">
            <button
              onClick={() => handleVigenere(true)}
              disabled={vigLoading || !vigText || !vigKey}
              className="px-5 py-2 rounded-lg bg-purple-500 text-white font-bold hover:bg-purple-600 transition-all"
            >
              Decrypt Text
            </button>
            <button
              onClick={() => handleVigenere(false)}
              disabled={vigLoading || !vigText || !vigKey}
              className="px-5 py-2 rounded-lg bg-cyber-card border border-purple-500 text-purple-300 font-bold hover:bg-purple-950/40 transition-all"
            >
              Encrypt Text
            </button>
          </div>

          {vigOutput && (
            <div className="mt-4 p-4 rounded-lg bg-black/60 border border-purple-500/40 space-y-2">
              <span className="text-purple-400 uppercase font-bold block">Output Result</span>
              <pre className="text-white text-sm select-all whitespace-pre-wrap">{vigOutput.result}</pre>
              {vigOutput.flags && vigOutput.flags.length > 0 && (
                <div className="pt-2">
                  <FlagCard flags={vigOutput.flags} source="Vigenere Tool" />
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* SUBTAB 4: XOR 256-Key Brute-Force */}
      {activeSubTab === 'xor' && (
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 space-y-5 font-mono text-xs">
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-gray-400 uppercase font-bold flex items-center gap-2">
                <Binary className="w-4 h-4 text-yellow-400" />
                Ciphertext (Hex or Raw String)
              </label>
              <div className="flex items-center gap-2">
                <label className="text-gray-400 cursor-pointer flex items-center gap-1.5 text-[11px]">
                  <input
                    type="checkbox"
                    checked={xorIsHex}
                    onChange={(e) => setXorIsHex(e.target.checked)}
                    className="rounded bg-cyber-darker border-cyber-border text-yellow-500 focus:ring-0"
                  />
                  <span>Treat as Hex (e.g. 1b373733...)</span>
                </label>
              </div>
            </div>
            <textarea
              value={xorInput}
              onChange={(e) => setXorInput(e.target.value)}
              rows={3}
              placeholder="Paste hex or encrypted string (e.g. 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736)..."
              className="w-full bg-cyber-darker border border-cyber-border rounded-lg p-3 text-white placeholder-gray-600 focus:outline-none focus:border-yellow-500 text-sm"
            />
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleXorBruteforce}
              disabled={xorLoading || !xorInput.trim()}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-yellow-500 hover:bg-yellow-400 text-black font-bold transition-all disabled:opacity-50"
            >
              {xorLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
              <span>Brute-Force All 256 Keys</span>
            </button>
            <button
              onClick={() => {
                setXorInput('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736');
                setXorIsHex(true);
              }}
              className="px-3 py-2 rounded-lg bg-cyber-darker border border-cyber-border hover:border-yellow-500/50 text-gray-400 hover:text-yellow-300 text-[11px]"
            >
              Load Sample Hex XOR
            </button>
          </div>

          {/* Results table */}
          {xorCandidates.length > 0 && (
            <div className="space-y-3 pt-3 border-t border-cyber-border">
              <div className="flex items-center justify-between text-gray-400 text-xs">
                <span>Top Viable Plaintext Candidates ({xorCandidates.length} ranked)</span>
                <span className="text-[11px] text-gray-500">Sorted by English & Flag Score</span>
              </div>
              <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
                {xorCandidates.map((c, idx) => (
                  <div
                    key={idx}
                    className={`p-3 rounded-lg border transition-all flex items-start justify-between gap-3 ${
                      c.has_flag
                        ? 'bg-cyber-green/10 border-cyber-green/60 text-cyber-green glow-green'
                        : idx === 0
                        ? 'bg-yellow-950/20 border-yellow-500/50 text-yellow-200'
                        : 'bg-cyber-darker border-cyber-border text-gray-300'
                    }`}
                  >
                    <div className="space-y-1 flex-1 break-all font-mono">
                      <div className="flex items-center gap-2 text-[11px] text-gray-400">
                        <span className="font-bold text-white px-1.5 py-0.5 rounded bg-black/50 border border-cyber-border">
                          Key: {c.key_repr}
                        </span>
                        <span>Printable: {c.printable_ratio}%</span>
                        <span>Score: {c.score}</span>
                        {c.has_flag && (
                          <span className="bg-cyber-green text-black font-extrabold px-1.5 py-0.2 rounded text-[10px]">
                            FLAG FOUND!
                          </span>
                        )}
                      </div>
                      <p className="text-sm select-all">{c.text}</p>
                    </div>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(c.text);
                        setCopiedXorKey(c.key);
                        setTimeout(() => setCopiedXorKey(null), 2000);
                      }}
                      className="p-1.5 rounded hover:bg-white/10 text-gray-400 hover:text-white shrink-0"
                      title="Copy Output"
                    >
                      {copiedXorKey === c.key ? <Check className="w-4 h-4 text-cyber-green" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* SUBTAB 5: Endianness & Pwntools */}
      {activeSubTab === 'endian' && (
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 space-y-5 font-mono text-xs">
          <div>
            <label className="text-gray-400 uppercase font-bold flex items-center gap-2 mb-2">
              <Cpu className="w-4 h-4 text-red-400" />
              Memory Address / Integer / Raw Bytes
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={endianInput}
                onChange={(e) => setEndianInput(e.target.value)}
                placeholder="e.g. 0x08048492 or \x92\x84\x04\x08 or 134513810"
                className="flex-1 bg-cyber-darker border border-cyber-border rounded-lg px-3 py-2.5 text-white placeholder-gray-600 focus:outline-none focus:border-red-500 text-sm"
              />
              <button
                onClick={handleConvertEndian}
                disabled={endianLoading || !endianInput.trim()}
                className="px-5 py-2.5 rounded-lg bg-red-500 hover:bg-red-600 text-white font-bold transition-all disabled:opacity-50 flex items-center gap-2"
              >
                {endianLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                <span>Convert</span>
              </button>
            </div>
          </div>

          {endianResult && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
              {/* 32-bit Architecture Card */}
              <div className="bg-cyber-darker border border-cyber-border rounded-lg p-4 space-y-3">
                <div className="flex items-center justify-between border-b border-cyber-border pb-2">
                  <span className="font-bold text-red-400 uppercase flex items-center gap-1.5">
                    x86 32-Bit Architecture
                  </span>
                  <span className="text-[11px] text-gray-500">p32()</span>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between bg-black/60 p-2 rounded border border-cyber-border">
                    <div>
                      <span className="text-[10px] text-gray-500 uppercase block">Little-Endian Bytes</span>
                      <span className="text-cyber-green text-xs select-all font-bold">
                        {endianResult['32bit']?.little_endian_bytes}
                      </span>
                    </div>
                    <button
                      onClick={() => handleCopyText(endianResult['32bit']?.little_endian_bytes, '32_le_bytes')}
                      className="p-1 text-gray-400 hover:text-white"
                    >
                      {copiedEndianItem === '32_le_bytes' ? <Check className="w-3.5 h-3.5 text-cyber-green" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>

                  <div className="flex items-center justify-between bg-black/60 p-2 rounded border border-cyber-border">
                    <div>
                      <span className="text-[10px] text-gray-500 uppercase block">Pwntools Snippet</span>
                      <span className="text-white text-xs select-all">
                        {endianResult['32bit']?.pwntools}
                      </span>
                    </div>
                    <button
                      onClick={() => handleCopyText(endianResult['32bit']?.pwntools, '32_pwn')}
                      className="p-1 text-gray-400 hover:text-white"
                    >
                      {copiedEndianItem === '32_pwn' ? <Check className="w-3.5 h-3.5 text-cyber-green" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>

                  <div className="flex items-center justify-between bg-black/60 p-2 rounded border border-cyber-border">
                    <div>
                      <span className="text-[10px] text-gray-500 uppercase block">Hex String</span>
                      <span className="text-gray-300 text-xs select-all">
                        {endianResult['32bit']?.little_endian_hex}
                      </span>
                    </div>
                    <button
                      onClick={() => handleCopyText(endianResult['32bit']?.little_endian_hex, '32_hex')}
                      className="p-1 text-gray-400 hover:text-white"
                    >
                      {copiedEndianItem === '32_hex' ? <Check className="w-3.5 h-3.5 text-cyber-green" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>
              </div>

              {/* 64-bit Architecture Card */}
              <div className="bg-cyber-darker border border-cyber-border rounded-lg p-4 space-y-3">
                <div className="flex items-center justify-between border-b border-cyber-border pb-2">
                  <span className="font-bold text-cyber-cyan uppercase flex items-center gap-1.5">
                    x86_64 64-Bit Architecture
                  </span>
                  <span className="text-[11px] text-gray-500">p64()</span>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between bg-black/60 p-2 rounded border border-cyber-border">
                    <div>
                      <span className="text-[10px] text-gray-500 uppercase block">Little-Endian Bytes (8-Byte Padded)</span>
                      <span className="text-cyber-green text-xs select-all font-bold">
                        {endianResult['64bit']?.little_endian_bytes}
                      </span>
                    </div>
                    <button
                      onClick={() => handleCopyText(endianResult['64bit']?.little_endian_bytes, '64_le_bytes')}
                      className="p-1 text-gray-400 hover:text-white"
                    >
                      {copiedEndianItem === '64_le_bytes' ? <Check className="w-3.5 h-3.5 text-cyber-green" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>

                  <div className="flex items-center justify-between bg-black/60 p-2 rounded border border-cyber-border">
                    <div>
                      <span className="text-[10px] text-gray-500 uppercase block">Pwntools Snippet</span>
                      <span className="text-white text-xs select-all">
                        {endianResult['64bit']?.pwntools}
                      </span>
                    </div>
                    <button
                      onClick={() => handleCopyText(endianResult['64bit']?.pwntools, '64_pwn')}
                      className="p-1 text-gray-400 hover:text-white"
                    >
                      {copiedEndianItem === '64_pwn' ? <Check className="w-3.5 h-3.5 text-cyber-green" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>

                  <div className="flex items-center justify-between bg-black/60 p-2 rounded border border-cyber-border">
                    <div>
                      <span className="text-[10px] text-gray-500 uppercase block">Hex String</span>
                      <span className="text-gray-300 text-xs select-all">
                        {endianResult['64bit']?.little_endian_hex}
                      </span>
                    </div>
                    <button
                      onClick={() => handleCopyText(endianResult['64bit']?.little_endian_hex, '64_hex')}
                      className="p-1 text-gray-400 hover:text-white"
                    >
                      {copiedEndianItem === '64_hex' ? <Check className="w-3.5 h-3.5 text-cyber-green" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
