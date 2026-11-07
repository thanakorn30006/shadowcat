import React, { useState, useEffect } from 'react';
import { Flag, Copy, Check } from 'lucide-react';
import { useApp } from '../context/AppContext';

interface FlagCardProps {
  flags: string[];
  source?: string;
}

export const FlagCard: React.FC<FlagCardProps> = ({ flags, source = 'Analysis Engine' }) => {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const { addFlags, targetFlagPrefix } = useApp();

  useEffect(() => {
    if (flags && flags.length > 0) {
      addFlags(flags, source);
    }
  }, [flags, source]);

  if (!flags || flags.length === 0) return null;

  const handleCopy = (flag: string, index: number) => {
    navigator.clipboard.writeText(flag);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const handleCopyAll = () => {
    navigator.clipboard.writeText(flags.join('\n'));
    setCopiedIndex(-1);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <div className="bg-[#0b1320] border border-emerald-500/40 rounded-lg p-4 mb-6 relative overflow-hidden transition-all">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2.5">
          <div className="p-1 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/60">
            <Flag className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-xs font-semibold text-emerald-300 font-sans tracking-wide uppercase flex items-center gap-2">
              Captured Flag Identified ({flags.length})
            </h3>
            <span className="text-[11px] text-slate-400 font-sans">
              Saved to Vault · Source: {source}
            </span>
          </div>
        </div>

        {flags.length > 1 && (
          <button
            onClick={handleCopyAll}
            className="text-xs font-sans px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
          >
            {copiedIndex === -1 ? 'Copied' : 'Copy All'}
          </button>
        )}
      </div>

      <div className="space-y-2">
        {flags.map((flag, idx) => {
          const isTargetMatch = targetFlagPrefix.trim() && 
            flag.toLowerCase().includes(targetFlagPrefix.trim().toLowerCase().replace('{', ''));
          return (
            <div 
              key={idx} 
              className={`flex items-center justify-between rounded px-3 py-2.5 font-mono text-xs transition-colors ${
                isTargetMatch 
                  ? 'border border-amber-500/60 bg-amber-950/20 text-amber-200' 
                  : 'border border-slate-800 bg-[#070b14] text-emerald-300'
              }`}
            >
              <div className="flex items-center gap-2 flex-1 break-all">
                {isTargetMatch && (
                  <span className="bg-amber-500/20 text-amber-300 border border-amber-500/40 font-sans font-semibold text-[10px] px-1.5 py-0.2 rounded uppercase">
                    Target Match
                  </span>
                )}
                <span className="select-all tracking-wide">{flag}</span>
              </div>
              <button
                onClick={() => handleCopy(flag, idx)}
                className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors ml-3"
                title="Copy flag to clipboard"
              >
                {copiedIndex === idx ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
};
