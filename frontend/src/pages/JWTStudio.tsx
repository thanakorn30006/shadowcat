import React, { useState, useEffect } from 'react';
import { KeyRound, ShieldAlert, Copy, Check, RefreshCw, AlertCircle, Sparkles, ArrowRight, LockOpen, Ticket } from 'lucide-react';
import { decodeJWT, forgeJWT, forgeJwtConfusion } from '../api/client';
import { useApp } from '../context/AppContext';

export const JWTStudio: React.FC = () => {
  const { pipedData, clearPipedData } = useApp();
  const [token, setToken] = useState('');
  const [loading, setLoading] = useState(false);
  const [decoded, setDecoded] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (pipedData && pipedData.targetTab === 'jwt' && pipedData.data) {
      setToken(pipedData.data.trim());
      clearPipedData();
    }
  }, [pipedData]);

  // Editing state for forge
  const [headerJson, setHeaderJson] = useState('');
  const [payloadJson, setPayloadJson] = useState('');
  const [secret, setSecret] = useState('');
  const [publicKeyPem, setPublicKeyPem] = useState('');
  const [showConfusion, setShowConfusion] = useState(false);
  const [forgedToken, setForgedToken] = useState('');
  const [copiedForged, setCopiedForged] = useState(false);
  const [copiedNone, setCopiedNone] = useState(false);

  const handleDecode = async () => {
    if (!token.trim()) return;
    setLoading(true);
    setError(null);
    setForgedToken('');

    try {
      const data = await decodeJWT(token.trim());
      setDecoded(data);
      setHeaderJson(JSON.stringify(data.header, null, 2));
      setPayloadJson(JSON.stringify(data.payload, null, 2));
    } catch (err: any) {
      setError(err.message || 'Failed to decode JWT');
    } finally {
      setLoading(false);
    }
  };

  const handleForge = async (algNone: boolean = false) => {
    try {
      const h = JSON.parse(headerJson);
      const p = JSON.parse(payloadJson);
      const data = await forgeJWT(h, p, secret || undefined, algNone);
      setForgedToken(data.token);
    } catch (e: any) {
      setError(`Forge error: ${e.message}`);
    }
  };

  const handleConfusionForge = async () => {
    if (!publicKeyPem.trim()) {
      setError('Target RSA Public Key (PEM or text) is required for RS256 -> HS256 algorithm confusion attack');
      return;
    }
    try {
      const h = JSON.parse(headerJson);
      const p = JSON.parse(payloadJson);
      const data = await forgeJwtConfusion(h, p, publicKeyPem.trim());
      setForgedToken(data.token);
    } catch (e: any) {
      setError(`Algorithm confusion forge error: ${e.message}`);
    }
  };

  const handleCopy = (text: string, type: 'forged' | 'none') => {
    navigator.clipboard.writeText(text);
    if (type === 'forged') {
      setCopiedForged(true);
      setTimeout(() => setCopiedForged(false), 2000);
    } else {
      setCopiedNone(true);
      setTimeout(() => setCopiedNone(false), 2000);
    }
  };

  const sampleToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidmlzaXRvcnMiLCJyb2xlIjoidXNlciIsImZsYWciOiJwaWNvQ1RGe2QxZ195MHVfZ24wd19qd3RfeTB1X2dvdF8xdH0ifQ.fakesignature';

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div className="border-b border-slate-800 pb-4">
        <h2 className="text-xl font-semibold font-sans text-slate-100 flex items-center gap-2">
          <Ticket className="w-5 h-5 text-emerald-400" />
          JSON Web Token (JWT) Security Analysis & Forgery
        </h2>
        <p className="text-slate-400 text-xs mt-1 font-sans">
          Deep token parsing, claim inspection, HMAC dictionary secret recovery, and signature bypass via algorithm tampering.
        </p>
      </div>

      {/* Input Token Form */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 space-y-4 font-mono">
        <div>
          <label className="text-xs uppercase text-gray-400 mb-2 block">
            Target Encoded JWT Token (xxx.yyy.zzz)
          </label>
          <textarea
            value={token}
            onChange={(e) => setToken(e.target.value)}
            rows={3}
            placeholder="Paste raw JWT string..."
            className="w-full bg-cyber-darker border border-cyber-border rounded-lg p-3 text-xs text-white placeholder-gray-600 focus:outline-none focus:border-cyber-cyan"
          />
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleDecode}
            disabled={loading || !token.trim()}
            className="flex items-center gap-2 px-6 py-2.5 rounded-lg bg-cyber-cyan text-black font-semibold text-xs hover:bg-cyber-cyan/90 disabled:opacity-50 transition-all"
          >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <KeyRound className="w-4 h-4" />}
            Inspect & Attack Token
          </button>

          <button
            onClick={() => {
              setToken(sampleToken);
            }}
            className="text-xs px-3 py-2 rounded bg-cyber-dark border border-cyber-border hover:border-gray-500 text-gray-400 hover:text-white transition-colors"
          >
            Load Sample Challenge JWT
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/50 flex items-start gap-3 text-red-200">
          <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div className="font-mono text-xs">{error}</div>
        </div>
      )}

      {decoded && (
        <div className="space-y-6">
          {/* Quick Attack Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Alg: none card */}
            <div className="bg-cyber-card border border-cyber-green/40 p-5 rounded-xl space-y-3 font-mono">
              <div className="flex items-center justify-between">
                <span className="text-cyber-green font-bold text-xs flex items-center gap-2 uppercase tracking-wider">
                  <LockOpen className="w-4 h-4" />
                  1-Click "alg: none" Exploit
                </span>
                <span className="text-[10px] bg-cyber-green/10 text-cyber-green px-2 py-0.5 rounded border border-cyber-green/30 font-bold">
                  High Success Rate in CTF
                </span>
              </div>
              <p className="text-gray-400 text-xs">
                Creates an unsigned token with <code className="text-white">"alg": "none"</code> and empty signature. Many flawed backends accept it without verification!
              </p>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleCopy(decoded.alg_none_exploit_token, 'none')}
                  className="px-4 py-2 rounded bg-cyber-green text-black font-bold text-xs hover:bg-cyber-green/90 transition-all flex items-center gap-1.5"
                >
                  {copiedNone ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedNone ? 'Copied Exploit Token!' : 'Copy alg:none Token'}
                </button>
              </div>
            </div>

            {/* Secret cracking status */}
            <div className="bg-cyber-card border border-cyber-border p-5 rounded-xl space-y-3 font-mono">
              <span className="text-purple-400 font-bold text-xs uppercase tracking-wider block">
                Weak HMAC Secret Audit
              </span>
              {decoded.cracked_secret ? (
                <div className="p-3 bg-cyber-green/10 border border-cyber-green/40 rounded text-xs text-cyber-green">
                  <strong>CRACKED SECRET:</strong> <span className="text-white font-bold select-all">{decoded.cracked_secret}</span>
                </div>
              ) : (
                <p className="text-gray-400 text-xs">
                  Tested common wordlist secrets. Not a trivial password. You can re-sign below using custom keys.
                </p>
              )}
            </div>
          </div>

          {/* Interactive Claim Tamperer & Re-Sign */}
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 space-y-4 font-mono text-xs">
            <h3 className="text-white font-bold text-sm border-b border-cyber-border pb-2 uppercase tracking-wider">
              Token Editor & Claim Tampering (Privilege Escalation)
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-gray-400 block mb-1.5 uppercase font-bold text-[11px]">Header (JSON)</label>
                <textarea
                  value={headerJson}
                  onChange={(e) => setHeaderJson(e.target.value)}
                  rows={6}
                  className="w-full bg-cyber-darker border border-cyber-border rounded-lg p-3 text-cyber-cyan focus:outline-none"
                />
              </div>

              <div>
                <label className="text-gray-400 block mb-1.5 uppercase font-bold text-[11px]">Payload Claims (JSON)</label>
                <textarea
                  value={payloadJson}
                  onChange={(e) => setPayloadJson(e.target.value)}
                  rows={6}
                  className="w-full bg-cyber-darker border border-cyber-border rounded-lg p-3 text-purple-300 focus:outline-none"
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-3 pt-2">
              <input
                type="text"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                placeholder="HMAC Secret Key (Leave empty for none attack)"
                className="flex-1 min-w-[200px] bg-cyber-darker border border-cyber-border rounded-lg px-3 py-2 text-white placeholder-gray-600 focus:outline-none"
              />
              <button
                onClick={() => handleForge(false)}
                className="px-4 py-2 rounded-lg bg-cyber-card border border-purple-500 hover:bg-purple-950/40 text-purple-300 font-bold transition-all"
              >
                Re-Sign with Secret
              </button>
              <button
                onClick={() => handleForge(true)}
                className="px-4 py-2 rounded-lg bg-cyber-green text-black font-bold hover:bg-cyber-green/90 transition-all"
              >
                Forge (alg: none)
              </button>
              <button
                onClick={() => setShowConfusion(!showConfusion)}
                className={`px-4 py-2 rounded-lg border font-bold transition-all ${
                  showConfusion 
                    ? 'bg-amber-500/20 border-amber-500 text-amber-300' 
                    : 'bg-cyber-card border-amber-500/50 hover:bg-amber-950/30 text-amber-400'
                }`}
              >
                {showConfusion ? '[RS256 -> HS256] Active' : '[RS256 -> HS256] Confusion'}
              </button>
            </div>

            {showConfusion && (
              <div className="p-4 rounded-lg bg-amber-950/20 border border-amber-500/40 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-amber-300 uppercase tracking-wider text-[11px]">
                    {'[CVE-2015-9235] RS256 to HS256 Algorithm Confusion Exploit'}
                  </span>
                  <span className="text-gray-400 text-[10px]">Signs token using the server's public key as HMAC secret</span>
                </div>
                <div>
                  <label className="text-gray-400 block mb-1 text-[11px]">
                    Target Server RSA Public Key (PEM or raw text)
                  </label>
                  <textarea
                    value={publicKeyPem}
                    onChange={(e) => setPublicKeyPem(e.target.value)}
                    rows={4}
                    placeholder="-----BEGIN PUBLIC KEY-----&#10;MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...&#10;-----END PUBLIC KEY-----"
                    className="w-full bg-cyber-darker border border-amber-500/50 rounded-lg p-2.5 text-amber-200 placeholder-gray-600 focus:outline-none text-[11px]"
                  />
                </div>
                <button
                  onClick={handleConfusionForge}
                  className="px-5 py-2 rounded-lg bg-amber-500 hover:bg-amber-400 text-black font-bold transition-all flex items-center gap-2"
                >
                  <LockOpen className="w-3.5 h-3.5" />
                  Generate Algorithm Confusion Exploit Token
                </button>
              </div>
            )}

            {forgedToken && (
              <div className="mt-4 p-4 rounded-lg bg-black/80 border border-cyber-green/40 space-y-2">
                <div className="flex items-center justify-between text-cyber-green font-bold">
                  <span>FORGED TAMPERED TOKEN:</span>
                  <button
                    onClick={() => handleCopy(forgedToken, 'forged')}
                    className="text-xs text-gray-400 hover:text-white flex items-center gap-1"
                  >
                    {copiedForged ? <Check className="w-3.5 h-3.5 text-cyber-green" /> : <Copy className="w-3.5 h-3.5" />}
                    {copiedForged ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <pre className="text-white select-all break-all whitespace-pre-wrap">{forgedToken}</pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
