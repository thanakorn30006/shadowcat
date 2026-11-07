import React, { useState, useEffect } from 'react';
import { Hash as HashIcon, RefreshCw, AlertCircle, CheckCircle, Copy, ShieldCheck } from 'lucide-react';
import { crackHash } from '../api/client';
import { useApp } from '../context/AppContext';

export const HashCrack: React.FC = () => {
  const { pipedData, clearPipedData } = useApp();
  const [hash, setHash] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (pipedData && pipedData.targetTab === 'hash' && pipedData.data) {
      setHash(pipedData.data.trim());
      clearPipedData();
    }
  }, [pipedData]);

  const handleCrack = async () => {
    if (!hash.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await crackHash(hash.trim());
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Hash cracking failed');
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const presets = [
    { label: 'MD5 ("password")', hash: '5f4dcc3b5aa765d61d8327deb882cf99' },
    { label: 'MD5 ("123456")', hash: 'e10adc3949ba59abbe56e057f20f883e' },
    { label: 'SHA1 ("password")', hash: '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8' },
    { label: 'SHA256 ("shadowcat2026")', hash: '63ac1d4937524c69172c7a880d053306efc3d9c24726adade4eadbdfc4181fb4' },
    { label: 'NTLM ("admin")', hash: '209c6174da490caeb422f3fa5a7ae634' },
  ];

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div className="border-b border-slate-800 pb-4">
        <h2 className="text-xl font-semibold font-sans text-slate-100 flex items-center gap-2">
          <HashIcon className="w-5 h-5 text-emerald-400" />
          Cryptographic Hash Identification & Recovery
        </h2>
        <p className="text-slate-400 text-xs mt-1 font-sans">
          Algorithm identification by bit-length, precomputed rainbow table lookup, and multi-source reverse hash databases.
        </p>
      </div>

      <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 space-y-4">
        {/* Offline Dictionary Banner */}
        <div className="bg-emerald-950/30 border border-emerald-500/40 p-3 rounded-lg flex items-center justify-between text-xs font-mono">
          <div className="flex items-center gap-2 text-emerald-400 font-semibold">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>[OFFLINE ROCKYOU DICTIONARY: 56,641 PRE-INDEXED PASSWORDS]</span>
          </div>
          <span className="text-gray-400 text-[11px] hidden sm:inline-block">
            100% Air-Gapped O(1) Instant Lookup &bull; MD5, SHA1, SHA256, NTLM
          </span>
        </div>

        <div>
          <label className="block text-xs font-mono uppercase text-gray-400 mb-2">
            Target Hash
          </label>
          <input
            type="text"
            value={hash}
            onChange={(e) => setHash(e.target.value)}
            placeholder="e.g. 5f4dcc3b5aa765d61d8327deb882cf99"
            className="w-full bg-cyber-darker border border-cyber-border rounded-lg px-3 py-2.5 text-sm font-mono text-white placeholder-gray-600 focus:outline-none focus:border-cyber-green/60"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2 pt-1">
          <span className="text-xs text-gray-500 font-mono">Presets:</span>
          {presets.map((p, idx) => (
            <button
              key={idx}
              onClick={() => setHash(p.hash)}
              className="text-xs font-mono px-2.5 py-1 rounded bg-cyber-dark border border-cyber-border hover:border-cyber-cyan/50 text-gray-300 hover:text-cyber-cyan transition-colors"
            >
              {p.label}
            </button>
          ))}
        </div>

        <button
          onClick={handleCrack}
          disabled={loading || !hash.trim()}
          className="flex items-center gap-2 px-6 py-2.5 rounded-lg bg-cyber-green text-black font-semibold text-sm hover:bg-cyber-green/90 disabled:opacity-50 transition-all font-mono"
        >
          {loading ? (
            <>
              <RefreshCw className="w-4 h-4 animate-spin" />
              Searching Tables & APIs...
            </>
          ) : (
            <>
              <HashIcon className="w-4 h-4" />
              Crack Hash
            </>
          )}
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/50 flex items-start gap-3 text-red-200">
          <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <h4 className="font-semibold text-sm">Crack Error</h4>
            <p className="text-xs text-red-300 mt-0.5 font-mono">{error}</p>
          </div>
        </div>
      )}

      {result && (
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-cyber-border pb-3">
            <span className="text-xs font-mono text-gray-400 uppercase">Algorithm Detected</span>
            <span className="text-sm font-mono font-bold text-cyber-cyan">{result.type || 'Unknown'}</span>
          </div>

          {result.cracked ? (
            <div className="bg-cyber-darker border border-cyber-green/40 rounded-lg p-5 glow-green">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono uppercase text-cyber-green font-bold flex items-center gap-1.5">
                  <CheckCircle className="w-4 h-4" />
                  Successfully Cracked ({result.source})
                </span>
                <button
                  onClick={() => handleCopy(result.plaintext)}
                  className="text-xs flex items-center gap-1 text-gray-400 hover:text-white"
                >
                  <Copy className="w-3.5 h-3.5" />
                  {copied ? 'Copied' : 'Copy'}
                </button>
              </div>
              <div className="text-xl font-bold font-mono text-white select-all break-all">
                {result.plaintext}
              </div>
            </div>
          ) : (
            <div className="bg-cyber-darker border border-yellow-500/30 rounded-lg p-4 font-mono text-xs text-gray-300">
              <p className="text-yellow-400 font-bold mb-1">Hash Not Found in Online Databases</p>
              {result.hint && <p className="text-gray-400 mt-2">{result.hint}</p>}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
