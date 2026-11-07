import React, { useState } from 'react';
import { Cpu, RefreshCw, AlertCircle, Compass, Terminal, FileCode, BookOpen } from 'lucide-react';
import { classifyChallenge } from '../api/client';

export const Classify: React.FC = () => {
  const [description, setDescription] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const handleClassify = async () => {
    if (!description.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await classifyChallenge(description.trim());
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Classification failed');
    } finally {
      setLoading(false);
    }
  };

  const sampleChallenges = [
    {
      label: 'Forensics (LSB Image)',
      text: 'Find the flag hidden in this PNG image using LSB steganography. Extract data from the red channel pixels.'
    },
    {
      label: 'Crypto (RSA Factoring)',
      text: 'Decrypt the message encrypted with RSA. Modulus n is a 64-bit integer, e=65537, ciphertext is provided.'
    },
    {
      label: 'Web (SQL Injection)',
      text: 'The login page at /login.php seems vulnerable. Bypass authentication and extract the admin flag from the database.'
    },
    {
      label: 'Pwn (Buffer Overflow)',
      text: 'Stack buffer overflow with NX enabled. Leak libc base via puts() and execute ret2libc to spawn /bin/sh.'
    }
  ];

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div className="border-b border-slate-800 pb-4">
        <h2 className="text-xl font-semibold font-sans text-slate-100 flex items-center gap-2">
          <Cpu className="w-5 h-5 text-emerald-400" />
          Machine Learning Challenge Classification & Triage
        </h2>
        <p className="text-slate-400 text-xs mt-1 font-sans">
          Natural language processing model (TF-IDF + Multinomial Classifier) trained on 300+ security challenges for tactical recommendation and attack vector identification.
        </p>
      </div>

      <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 space-y-4">
        <div>
          <label className="block text-xs font-mono uppercase text-gray-400 mb-2">
            Paste Challenge Prompt or Description
          </label>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            rows={4}
            placeholder="Paste problem statement, hints, or instructions given by the CTF challenge..."
            className="w-full bg-cyber-darker border border-cyber-border rounded-lg p-3 text-sm font-mono text-white placeholder-gray-600 focus:outline-none focus:border-cyber-green/60"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2 pt-1">
          <span className="text-xs text-gray-500 font-mono">Sample Prompts:</span>
          {sampleChallenges.map((s, idx) => (
            <button
              key={idx}
              onClick={() => setDescription(s.text)}
              className="text-xs font-mono px-2.5 py-1 rounded bg-cyber-dark border border-cyber-border hover:border-cyber-cyan/50 text-gray-300 hover:text-cyber-cyan transition-colors"
            >
              {s.label}
            </button>
          ))}
        </div>

        <button
          onClick={handleClassify}
          disabled={loading || !description.trim()}
          className="flex items-center gap-2 px-6 py-2.5 rounded-lg bg-cyber-green text-black font-semibold text-sm hover:bg-cyber-green/90 disabled:opacity-50 transition-all font-mono"
        >
          {loading ? (
            <>
              <RefreshCw className="w-4 h-4 animate-spin" />
              Running Inference...
            </>
          ) : (
            <>
              <Cpu className="w-4 h-4" />
              Classify & Retrieve Strategy
            </>
          )}
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/50 flex items-start gap-3 text-red-200">
          <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <h4 className="font-semibold text-sm">Classification Error</h4>
            <p className="text-xs text-red-300 mt-0.5 font-mono">{error}</p>
          </div>
        </div>
      )}

      {result && (
        <div className="space-y-6">
          {/* Main Classification Result */}
          {result.classification && (
            <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 glow-green">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <span className="px-2.5 py-1 rounded bg-emerald-950/60 border border-emerald-800 text-emerald-400 font-mono text-xs font-bold tracking-wider">{result.classification.icon}</span>
                  <div>
                    <h3 className="text-xl font-bold font-mono text-white uppercase tracking-wider">
                      {result.classification.category}
                    </h3>
                    <p className="text-xs text-cyber-green font-mono">
                      Confidence: {result.classification.confidence}%
                    </p>
                  </div>
                </div>
              </div>

              {/* Confidence bars */}
              {result.classification.all_scores && (
                <div className="grid grid-cols-2 md:grid-cols-6 gap-2 mb-4 pt-2">
                  {Object.entries(result.classification.all_scores).map(([cat, score]: [string, any]) => (
                    <div key={cat} className="bg-cyber-darker p-2 rounded border border-cyber-border text-center">
                      <span className="text-[10px] uppercase font-mono text-gray-500 block">{cat}</span>
                      <span className="text-xs font-bold font-mono text-gray-300">{score}%</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Tips */}
              {result.classification.tips && result.classification.tips.length > 0 && (
                <div className="border-t border-cyber-border pt-4">
                  <span className="text-xs font-mono text-cyber-cyan uppercase font-bold flex items-center gap-1.5 mb-2">
                    <Compass className="w-4 h-4" /> Tactical Playbook Tips
                  </span>
                  <ul className="space-y-1 text-xs text-gray-300 font-mono">
                    {result.classification.tips.map((t: string, idx: number) => (
                      <li key={idx} className="flex items-center gap-2">
                        <span className="text-cyber-green font-mono">{'>'}</span> {t}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Similar Writeups */}
          {result.similar_writeups && result.similar_writeups.length > 0 && (
            <div className="bg-cyber-card border border-cyber-border rounded-xl p-5">
              <h3 className="text-sm font-bold font-mono text-purple-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-purple-400" />
                <span>Similar CTF Writeups & Exploits</span>
              </h3>
              <div className="space-y-4">
                {result.similar_writeups.map((w: any, idx: number) => (
                  <div key={idx} className="bg-cyber-darker border border-cyber-border rounded-lg p-4 font-mono text-xs space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-white font-bold text-sm">{w.title}</span>
                      <span className="text-purple-400 bg-purple-500/10 px-2 py-0.5 rounded text-[10px]">
                        {w.similarity}% match
                      </span>
                    </div>
                    <p className="text-gray-400">{w.description}</p>
                    
                    {w.approach && (
                      <div>
                        <span className="text-gray-500 uppercase text-[10px] block mb-1">Recommended Approach:</span>
                        <ul className="space-y-1 text-gray-300">
                          {w.approach.map((step: string, sIdx: number) => (
                            <li key={sIdx} className="text-xs">{step}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {w.code && (
                      <div>
                        <span className="text-gray-500 uppercase text-[10px] block mb-1 flex items-center gap-1">
                          <FileCode className="w-3 h-3" /> Exploit Snippet:
                        </span>
                        <pre className="bg-black/60 p-2.5 rounded text-cyber-green text-[11px] overflow-x-auto select-all">
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
      )}
    </div>
  );
};
