import React, { useState } from 'react';
import { X, ShieldCheck, Key, CheckCircle2, AlertCircle, ExternalLink } from 'lucide-react';
import { activateLicense } from '../api/client';

interface LicenseModalProps {
  isOpen: boolean;
  onClose: () => void;
  licenseInfo: {
    tier: string;
    status: string;
    signature_valid: boolean;
    expires: string;
    channel?: string;
    file_path?: string;
    pro_features: boolean;
  } | null;
  onRefresh: () => void;
}

export const LicenseModal: React.FC<LicenseModalProps> = ({
  isOpen,
  onClose,
  licenseInfo,
  onRefresh,
}) => {
  const [tokenInput, setTokenInput] = useState('');
  const [licContent, setLicContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  if (!isOpen) return null;

  const handleActivate = async () => {
    if (!tokenInput.trim() && !licContent.trim()) {
      setMsg({ type: 'error', text: 'Please enter a License Token or paste license file contents.' });
      return;
    }
    setLoading(true);
    setMsg(null);
    try {
      const res = await activateLicense(tokenInput.trim(), licContent.trim());
      setMsg({ type: 'success', text: res.message || 'License activated successfully!' });
      setTokenInput('');
      setLicContent('');
      onRefresh();
    } catch (err: any) {
      setMsg({ type: 'error', text: err.message || 'Failed to activate license.' });
    } finally {
      setLoading(false);
    }
  };

  const isPro = licenseInfo?.tier === 'PRO_OPERATOR';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="relative w-full max-w-lg bg-[#0a0f18] border border-slate-800 rounded-lg shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800 bg-[#070b12]">
          <div className="flex items-center gap-2.5">
            <ShieldCheck className={`w-5 h-5 ${isPro ? 'text-emerald-400' : 'text-slate-400'}`} />
            <h3 className="text-sm font-semibold text-slate-100 tracking-wide">
              SHADOW CAT AIR-GAP LICENSE
            </h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="p-5 space-y-4">
          {/* Status Banner */}
          <div className={`p-4 rounded border text-xs ${
            isPro
              ? 'bg-emerald-950/30 border-emerald-800/60 text-emerald-300'
              : 'bg-slate-900 border-slate-800 text-slate-300'
          }`}>
            <div className="flex items-center justify-between mb-2">
              <span className="font-semibold uppercase tracking-wider text-[11px] text-slate-400">
                Current Tier
              </span>
              <span className={`px-2 py-0.5 rounded font-mono font-bold text-[11px] ${
                isPro
                  ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                  : 'bg-slate-800 text-slate-300 border border-slate-700'
              }`}>
                {licenseInfo?.tier || 'COMMUNITY'}
              </span>
            </div>
            <div className="space-y-1 font-mono text-[11px] text-slate-400">
              <div className="flex justify-between">
                <span>Verification:</span>
                <span className="text-emerald-400">100% Offline (Zero Cloud Pings)</span>
              </div>
              <div className="flex justify-between">
                <span>Expiration:</span>
                <span className="text-slate-300">{licenseInfo?.expires || 'NEVER'}</span>
              </div>
              <div className="flex justify-between">
                <span>Channel:</span>
                <span className="text-slate-300">{licenseInfo?.channel || 'built_in_open_core'}</span>
              </div>
              {licenseInfo?.file_path && (
                <div className="flex justify-between truncate pt-1 border-t border-slate-800/80">
                  <span>File:</span>
                  <span className="text-slate-300 truncate max-w-[280px]" title={licenseInfo.file_path}>
                    {licenseInfo.file_path}
                  </span>
                </div>
              )}
            </div>
          </div>

          {/* Activation Inputs */}
          <div className="space-y-3 pt-2">
            <label className="block text-xs font-semibold text-slate-300">
              Inject / Activate License Token
            </label>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Key className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
                <input
                  type="text"
                  value={tokenInput}
                  onChange={(e) => setTokenInput(e.target.value)}
                  placeholder="e.g. SC-PRO-XXXX-XXXX-XXXX-OPLIFETIME"
                  className="w-full bg-slate-900 border border-slate-800 rounded pl-8 pr-3 py-1.5 text-xs font-mono text-slate-200 outline-none focus:border-emerald-500"
                />
              </div>
              <button
                onClick={handleActivate}
                disabled={loading}
                className="px-4 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium transition-colors disabled:opacity-50"
              >
                {loading ? 'Activating...' : 'Apply'}
              </button>
            </div>

            <details className="text-xs text-slate-400 group">
              <summary className="cursor-pointer hover:text-slate-300 select-none">
                Paste raw .lic file content
              </summary>
              <textarea
                value={licContent}
                onChange={(e) => setLicContent(e.target.value)}
                placeholder="-----BEGIN SHADOWCAT LICENSE-----&#10;..."
                rows={4}
                className="w-full mt-2 bg-slate-900 border border-slate-800 rounded p-2 text-[11px] font-mono text-slate-300 outline-none focus:border-emerald-500"
              />
            </details>
          </div>

          {msg && (
            <div className={`p-3 rounded text-xs flex items-center gap-2 ${
              msg.type === 'success'
                ? 'bg-emerald-950/40 border border-emerald-800 text-emerald-300'
                : 'bg-rose-950/40 border border-rose-800 text-rose-300'
            }`}>
              {msg.type === 'success' ? <CheckCircle2 className="w-4 h-4 shrink-0" /> : <AlertCircle className="w-4 h-4 shrink-0" />}
              <span>{msg.text}</span>
            </div>
          )}

          {/* Need License? */}
          {!isPro && (
            <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
              <span>Need a Pro Operator Lifetime license?</span>
              <a
                href="http://localhost:3333/pricing.html"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 text-emerald-400 hover:text-emerald-300 font-medium"
              >
                View Pricing <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};