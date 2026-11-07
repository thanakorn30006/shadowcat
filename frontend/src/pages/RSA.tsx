import React, { useState } from 'react';
import { Binary, RefreshCw, AlertCircle, CheckCircle, Shield } from 'lucide-react';
import { attackRSA } from '../api/client';
import { FlagCard } from '../components/FlagCard';

export const RSA: React.FC = () => {
  const [n, setN] = useState('');
  const [e, setE] = useState('65537');
  const [c, setC] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAttack = async () => {
    if (!n.trim() || !e.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await attackRSA(n, e, c.trim() ? c : undefined);
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'RSA attack failed');
    } finally {
      setLoading(false);
    }
  };

  const handleDemoSmallN = () => {
    setN('3233');
    setE('17');
    setC('2790');
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div className="border-b border-slate-800 pb-4">
        <h2 className="text-xl font-semibold font-sans text-slate-100 flex items-center gap-2">
          <Binary className="w-5 h-5 text-emerald-400" />
          RSA Asymmetric Cryptanalysis & Factoring Engine
        </h2>
        <p className="text-slate-400 text-xs mt-1 font-sans">
          Automated algebraic attacks: Small N prime factorization, Wiener continued fraction attack (small d), low public exponent ($e=3$), and FactorDB query.
        </p>
      </div>

      <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 space-y-4">
        <div>
          <label className="block text-xs font-mono uppercase text-gray-400 mb-2">
            Modulus N
          </label>
          <textarea
            value={n}
            onChange={(e) => setN(e.target.value)}
            rows={2}
            placeholder="Modulus n (decimal integer)..."
            className="w-full bg-cyber-darker border border-cyber-border rounded-lg p-3 text-sm font-mono text-white placeholder-gray-600 focus:outline-none focus:border-cyber-green/60"
          />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-mono uppercase text-gray-400 mb-2">
              Public Exponent e
            </label>
            <input
              type="text"
              value={e}
              onChange={(e) => setE(e.target.value)}
              placeholder="65537 or 3"
              className="w-full bg-cyber-darker border border-cyber-border rounded-lg px-3 py-2 text-sm font-mono text-white placeholder-gray-600 focus:outline-none focus:border-cyber-green/60"
            />
          </div>
          <div>
            <label className="block text-xs font-mono uppercase text-gray-400 mb-2">
              Ciphertext c (Optional)
            </label>
            <input
              type="text"
              value={c}
              onChange={(e) => setC(e.target.value)}
              placeholder="Ciphertext c (decimal integer)"
              className="w-full bg-cyber-darker border border-cyber-border rounded-lg px-3 py-2 text-sm font-mono text-white placeholder-gray-600 focus:outline-none focus:border-cyber-green/60"
            />
          </div>
        </div>

        <div className="flex items-center gap-3 pt-2">
          <button
            onClick={handleAttack}
            disabled={loading || !n.trim() || !e.trim()}
            className="flex items-center gap-2 px-6 py-2.5 rounded-lg bg-cyber-green text-black font-semibold text-sm hover:bg-cyber-green/90 disabled:opacity-50 transition-all font-mono"
          >
            {loading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                Factoring & Attacking...
              </>
            ) : (
              <>
                <Binary className="w-4 h-4" />
                Launch RSA Attacks
              </>
            )}
          </button>

          <button
            onClick={handleDemoSmallN}
            className="text-xs font-mono px-3 py-2 rounded bg-cyber-dark border border-cyber-border hover:border-cyber-cyan/50 text-gray-300 hover:text-cyber-cyan transition-colors"
          >
            Load Demo Challenge (n=3233)
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/50 flex items-start gap-3 text-red-200">
          <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <h4 className="font-semibold text-sm">Attack Execution Failed</h4>
            <p className="text-xs text-red-300 mt-0.5 font-mono">{error}</p>
          </div>
        </div>
      )}

      {result && (
        <div className="space-y-6">
          <FlagCard flags={result.flags || []} />

          {/* Attacks Summary */}
          {result.attacks && result.attacks.length > 0 ? (
            <div className="bg-cyber-card border border-cyber-border rounded-xl p-5">
              <h3 className="text-sm font-bold font-mono text-cyber-cyan uppercase tracking-wider mb-4">
                Attack Outcomes ({result.attacks.length})
              </h3>
              <div className="space-y-3">
                {result.attacks.map((att: any, idx: number) => (
                  <div key={idx} className="bg-cyber-darker border border-cyber-border p-4 rounded-lg font-mono text-xs">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-white font-bold text-sm flex items-center gap-2">
                        <CheckCircle className="w-4 h-4 text-cyber-green" />
                        {att.name}
                      </span>
                      {att.d && (
                        <span className="text-cyber-green bg-cyber-green/10 px-2 py-0.5 rounded">
                          d found
                        </span>
                      )}
                    </div>
                    {att.plaintext && (
                      <div className="mt-2 p-2.5 bg-black/50 border border-cyber-green/30 rounded">
                        <span className="text-gray-400 text-[11px] block mb-1">RECOVERED PLAINTEXT:</span>
                        <span className="text-cyber-green font-bold text-sm select-all">{att.plaintext}</span>
                      </div>
                    )}
                    {att.note && <p className="text-gray-400 mt-2">{att.note}</p>}
                    {att.p && (
                      <div className="grid grid-cols-2 gap-2 mt-2 text-gray-500">
                        <div>p: {String(att.p)}</div>
                        <div>q: {String(att.q)}</div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 text-center text-gray-400 text-sm font-mono">
              No automatic attacks succeeded. Consider querying yafu or check if N is a prime.
            </div>
          )}
        </div>
      )}
    </div>
  );
};
