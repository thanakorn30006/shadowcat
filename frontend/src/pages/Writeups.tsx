import React, { useState } from 'react';
import { BookOpen, Search, RefreshCw, AlertCircle, FileCode, Wrench } from 'lucide-react';
import { searchWriteups } from '../api/client';

export const Writeups: React.FC = () => {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<any[]>([]);
  const [error, setError] = useState<string | null>(null);

  const handleSearch = async () => {
    if (!query.trim()) return;
    setLoading(true);
    setError(null);

    try {
      const data = await searchWriteups(query.trim());
      setResults(data.results || []);
    } catch (err: any) {
      setError(err.message || 'Search failed');
    } finally {
      setLoading(false);
    }
  };

  const sampleKeywords = ['RSA small n', 'LSB steganography', 'SQL injection union', 'LFI etc passwd', 'ret2libc buffer overflow', 'PCAP credentials'];

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div className="border-b border-slate-800 pb-4">
        <h2 className="text-xl font-semibold font-sans text-slate-100 flex items-center gap-2">
          <BookOpen className="w-5 h-5 text-emerald-400" />
          Technical Knowledge Base & Exploit Templates
        </h2>
        <p className="text-slate-400 text-xs mt-1 font-sans">
          Vectorized semantic search (cosine similarity) over verified security writeups, attack methodologies, and executable exploit scripts.
        </p>
      </div>

      <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 space-y-4">
        <div>
          <label className="block text-xs font-mono uppercase text-gray-400 mb-2">
            Search Topic or Attack Vector
          </label>
          <div className="relative">
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              placeholder="e.g. RSA Wiener attack, JWT none, SSTI Jinja2..."
              className="w-full bg-cyber-darker border border-cyber-border rounded-lg pl-10 pr-3 py-2.5 text-sm font-mono text-white placeholder-gray-600 focus:outline-none focus:border-cyber-green/60"
            />
            <Search className="w-4 h-4 text-gray-500 absolute left-3 top-3.5" />
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 pt-1">
          <span className="text-xs text-gray-500 font-mono">Popular queries:</span>
          {sampleKeywords.map((k, idx) => (
            <button
              key={idx}
              onClick={() => {
                setQuery(k);
              }}
              className="text-xs font-mono px-2.5 py-1 rounded bg-cyber-dark border border-cyber-border hover:border-cyber-cyan/50 text-gray-300 hover:text-cyber-cyan transition-colors"
            >
              {k}
            </button>
          ))}
        </div>

        <button
          onClick={handleSearch}
          disabled={loading || !query.trim()}
          className="flex items-center gap-2 px-6 py-2.5 rounded-lg bg-cyber-green text-black font-semibold text-sm hover:bg-cyber-green/90 disabled:opacity-50 transition-all font-mono"
        >
          {loading ? (
            <>
              <RefreshCw className="w-4 h-4 animate-spin" />
              Searching Knowledge Base...
            </>
          ) : (
            <>
              <BookOpen className="w-4 h-4" />
              Search Playbooks
            </>
          )}
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/50 flex items-start gap-3 text-red-200">
          <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <h4 className="font-semibold text-sm">Query Error</h4>
            <p className="text-xs text-red-300 mt-0.5 font-mono">{error}</p>
          </div>
        </div>
      )}

      {results.length > 0 && (
        <div className="space-y-4">
          <h3 className="text-sm font-bold font-mono text-cyber-cyan uppercase tracking-wider">
            Matching CTF Playbooks ({results.length})
          </h3>

          <div className="space-y-4">
            {results.map((w, idx) => (
              <div key={idx} className="bg-cyber-card border border-cyber-border rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-cyber-border pb-3">
                  <div>
                    <h4 className="text-lg font-bold font-mono text-white">{w.title}</h4>
                    <span className="text-xs uppercase font-mono text-cyber-green">
                      Category: {w.category}
                    </span>
                  </div>
                  <span className="text-xs font-mono bg-cyber-green/10 text-cyber-green px-2.5 py-1 rounded border border-cyber-green/30">
                    {w.similarity}% match
                  </span>
                </div>

                <p className="text-sm text-gray-300 font-mono">{w.description}</p>

                {w.tools && w.tools.length > 0 && (
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-mono text-gray-500 flex items-center gap-1">
                      <Wrench className="w-3.5 h-3.5" /> Tools:
                    </span>
                    {w.tools.map((t: string, tIdx: number) => (
                      <span key={tIdx} className="text-xs font-mono px-2 py-0.5 bg-cyber-dark rounded text-gray-400 border border-cyber-border">
                        {t}
                      </span>
                    ))}
                  </div>
                )}

                {w.approach && (
                  <div>
                    <span className="text-xs font-mono uppercase text-gray-400 font-bold block mb-2">
                      Execution Steps
                    </span>
                    <ul className="space-y-1.5 font-mono text-xs text-gray-300 bg-cyber-darker p-3.5 rounded-lg border border-cyber-border">
                      {w.approach.map((step: string, sIdx: number) => (
                        <li key={sIdx}>{step}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {w.code && (
                  <div>
                    <span className="text-xs font-mono uppercase text-gray-400 font-bold block mb-2 flex items-center gap-1.5">
                      <FileCode className="w-3.5 h-3.5 text-cyber-green" /> Runnable Code Template
                    </span>
                    <pre className="bg-black/60 p-3.5 rounded-lg border border-cyber-border font-mono text-xs text-cyber-green overflow-x-auto select-all">
                      {w.code}
                    </pre>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
