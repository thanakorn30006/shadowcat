import React, { useState } from 'react';
import { Terminal, RefreshCw, AlertCircle, Send } from 'lucide-react';
import { solveNetcat } from '../api/client';
import { FlagCard } from '../components/FlagCard';

export const Netcat: React.FC = () => {
  const [host, setHost] = useState('');
  const [port, setPort] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const handleConnect = async () => {
    if (!host.trim() || !port.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await solveNetcat(host.trim(), parseInt(port.trim(), 10));
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Connection failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div className="border-b border-slate-800 pb-4">
        <h2 className="text-xl font-semibold font-sans text-slate-100 flex items-center gap-2">
          <Terminal className="w-5 h-5 text-emerald-400" />
          TCP Socket Interaction & Challenge Solver
        </h2>
        <p className="text-slate-400 text-xs mt-1 font-sans">
          Automated TCP socket stream communication: arithmetic equation evaluation, prompt pattern matching, and banner extraction.
        </p>
      </div>

      <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="md:col-span-2">
            <label className="block text-xs font-mono uppercase text-gray-400 mb-2">
              Target Host
            </label>
            <input
              type="text"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="e.g. chal.ctf.site or 192.168.1.50"
              className="w-full bg-cyber-darker border border-cyber-border rounded-lg px-3 py-2 text-sm font-mono text-white placeholder-gray-600 focus:outline-none focus:border-cyber-green/60"
            />
          </div>
          <div>
            <label className="block text-xs font-mono uppercase text-gray-400 mb-2">
              Port
            </label>
            <input
              type="number"
              value={port}
              onChange={(e) => setPort(e.target.value)}
              placeholder="e.g. 1337 or 9001"
              className="w-full bg-cyber-darker border border-cyber-border rounded-lg px-3 py-2 text-sm font-mono text-white placeholder-gray-600 focus:outline-none focus:border-cyber-green/60"
            />
          </div>
        </div>

        <button
          onClick={handleConnect}
          disabled={loading || !host.trim() || !port.trim()}
          className="flex items-center gap-2 px-6 py-2.5 rounded-lg bg-cyber-green text-black font-semibold text-sm hover:bg-cyber-green/90 disabled:opacity-50 transition-all font-mono"
        >
          {loading ? (
            <>
              <RefreshCw className="w-4 h-4 animate-spin" />
              Connecting & Handshaking...
            </>
          ) : (
            <>
              <Send className="w-4 h-4" />
              Connect & Auto-Solve
            </>
          )}
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/50 flex items-start gap-3 text-red-200">
          <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <h4 className="font-semibold text-sm">Socket Error</h4>
            <p className="text-xs text-red-300 mt-0.5 font-mono">{error}</p>
          </div>
        </div>
      )}

      {result && (
        <div className="space-y-6">
          <FlagCard flags={result.flags_found || []} />

          <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 space-y-4">
            <h3 className="text-sm font-bold font-mono text-cyber-cyan uppercase tracking-wider">
              Socket Session Transcripts
            </h3>

            {result.initial_prompt && (
              <div>
                <span className="text-xs font-mono text-gray-500 uppercase block mb-1">Incoming Prompt</span>
                <pre className="bg-black/60 p-3 rounded border border-cyber-border font-mono text-xs text-gray-300 select-all overflow-x-auto whitespace-pre-wrap">
                  {result.initial_prompt}
                </pre>
              </div>
            )}

            {result.sent_answer && (
              <div>
                <span className="text-xs font-mono text-cyber-green uppercase block mb-1">Payload Sent</span>
                <pre className="bg-cyber-green/10 p-3 rounded border border-cyber-green/30 font-mono text-xs text-cyber-green select-all">
                  {result.sent_answer}
                </pre>
              </div>
            )}

            {result.server_response && (
              <div>
                <span className="text-xs font-mono text-gray-500 uppercase block mb-1">Server Response</span>
                <pre className="bg-black/60 p-3 rounded border border-cyber-border font-mono text-xs text-gray-300 select-all overflow-x-auto whitespace-pre-wrap">
                  {result.server_response}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
