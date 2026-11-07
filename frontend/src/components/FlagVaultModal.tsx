import React, { useState } from 'react';
import { X, Flag, Trash2, Copy, Check, Download, ShieldCheck } from 'lucide-react';
import { useApp } from '../context/AppContext';

interface FlagVaultModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const FlagVaultModal: React.FC<FlagVaultModalProps> = ({ isOpen, onClose }) => {
  const { vault, removeFlag, clearVault } = useApp();
  const [copiedId, setCopiedId] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleCopy = (flag: string, id: string) => {
    navigator.clipboard.writeText(flag);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleCopyAll = () => {
    const all = vault.map(f => f.flag).join('\n');
    navigator.clipboard.writeText(all);
    setCopiedId('ALL');
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleExportTxt = () => {
    const text = vault.map(f => `[${f.timestamp}] [${f.source}] ${f.flag}`).join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `shadowsolve-flags-${new Date().toISOString().slice(0, 10)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="bg-cyber-dark border border-cyber-green/40 rounded-2xl w-full max-w-2xl max-h-[85vh] flex flex-col shadow-2xl glow-green overflow-hidden">
        {/* Header */}
        <div className="p-5 border-b border-cyber-border flex items-center justify-between bg-cyber-card/60">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyber-green/10 text-cyber-green border border-cyber-green/30">
              <Flag className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold font-mono text-white flex items-center gap-2">
                FLAG VAULT <span className="text-cyber-green text-sm">({vault.length})</span>
              </h2>
              <p className="text-xs text-gray-400 font-mono">
                Persistent repository of flags discovered across all tabs
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-cyber-card transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-5 overflow-y-auto flex-1 space-y-3">
          {vault.length === 0 ? (
            <div className="text-center py-12 text-gray-500 font-mono">
              <ShieldCheck className="w-12 h-12 mx-auto mb-3 opacity-30 text-cyber-green" />
              <p className="text-sm">Vault is empty.</p>
              <p className="text-xs text-gray-600 mt-1">
                Flags found in Forensics, Crypto, Web, or Netcat will automatically populate here.
              </p>
            </div>
          ) : (
            vault.map((item) => (
              <div
                key={item.id}
                className="bg-black/60 border border-cyber-border hover:border-cyber-green/40 rounded-xl p-3.5 flex items-center justify-between font-mono text-xs transition-colors"
              >
                <div className="space-y-1 flex-1 pr-3">
                  <div className="text-cyber-green font-bold text-sm select-all break-all">
                    {item.flag}
                  </div>
                  <div className="text-[11px] text-gray-500 flex items-center gap-3">
                    <span>Source: <strong className="text-gray-300">{item.source}</strong></span>
                    <span>Captured: {item.timestamp}</span>
                  </div>
                </div>

                <div className="flex items-center gap-1.5 shrink-0">
                  <button
                    onClick={() => handleCopy(item.flag, item.id)}
                    className="p-1.5 rounded hover:bg-cyber-card text-gray-400 hover:text-cyber-green transition-colors"
                    title="Copy"
                  >
                    {copiedId === item.id ? <Check className="w-4 h-4 text-cyber-green" /> : <Copy className="w-4 h-4" />}
                  </button>
                  <button
                    onClick={() => removeFlag(item.id)}
                    className="p-1.5 rounded hover:bg-cyber-card text-gray-400 hover:text-red-400 transition-colors"
                    title="Remove"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Footer Actions */}
        {vault.length > 0 && (
          <div className="p-4 border-t border-cyber-border bg-cyber-card/40 flex items-center justify-between">
            <button
              onClick={clearVault}
              className="text-xs font-mono text-red-400 hover:text-red-300 transition-colors flex items-center gap-1.5 px-3 py-1.5 rounded hover:bg-red-950/30"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Clear Vault
            </button>

            <div className="flex items-center gap-2">
              <button
                onClick={handleExportTxt}
                className="text-xs font-mono px-3 py-1.5 rounded bg-cyber-card hover:bg-cyber-border text-gray-300 flex items-center gap-1.5 transition-colors"
              >
                <Download className="w-3.5 h-3.5" />
                Export .TXT
              </button>
              <button
                onClick={handleCopyAll}
                className="text-xs font-mono px-3.5 py-1.5 rounded bg-cyber-green text-black font-semibold hover:bg-cyber-green/90 transition-colors"
              >
                {copiedId === 'ALL' ? 'Copied All!' : 'Copy All Flags'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
