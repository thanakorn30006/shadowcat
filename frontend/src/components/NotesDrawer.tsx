import React, { useState, useEffect } from 'react';
import { 
  X, 
  FileText, 
  Copy, 
  Check, 
  Download, 
  Trash2, 
  ShieldAlert, 
  Sparkles, 
  Terminal,
  Bookmark
} from 'lucide-react';

interface NotesDrawerProps {
  isOpen: boolean;
  onClose: () => void;
}

const STORAGE_KEY = 'shadowsolve_ctf_notes';
const META_KEY = 'shadowsolve_ctf_notes_meta';

export const NotesDrawer: React.FC<NotesDrawerProps> = ({ isOpen, onClose }) => {
  const [notes, setNotes] = useState<string>(() => {
    return localStorage.getItem(STORAGE_KEY) || '';
  });

  const [challengeName, setChallengeName] = useState<string>(() => {
    try {
      const saved = localStorage.getItem(META_KEY);
      return saved ? JSON.parse(saved).name || '' : '';
    } catch {
      return '';
    }
  });

  const [targetHost, setTargetHost] = useState<string>(() => {
    try {
      const saved = localStorage.getItem(META_KEY);
      return saved ? JSON.parse(saved).host || '' : '';
    } catch {
      return '';
    }
  });

  const [category, setCategory] = useState<string>(() => {
    try {
      const saved = localStorage.getItem(META_KEY);
      return saved ? JSON.parse(saved).category || 'Web' : 'Web';
    } catch {
      return 'Web';
    }
  });

  const [copied, setCopied] = useState(false);
  const [savedBadge, setSavedBadge] = useState(false);

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, notes);
    localStorage.setItem(META_KEY, JSON.stringify({ name: challengeName, host: targetHost, category }));
    setSavedBadge(true);
    const t = setTimeout(() => setSavedBadge(false), 1200);
    return () => clearTimeout(t);
  }, [notes, challengeName, targetHost, category]);

  if (!isOpen) return null;

  const handleCopy = () => {
    const fullText = `# Challenge: ${challengeName || 'Untitled'} [${category}]\n# Target: ${targetHost || 'N/A'}\n\n${notes}`;
    navigator.clipboard.writeText(fullText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const fullText = `# Challenge: ${challengeName || 'Untitled'} [${category}]\n# Target: ${targetHost || 'N/A'}\n# Date: ${new Date().toISOString()}\n\n${notes}`;
    const blob = new Blob([fullText], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${(challengeName || 'ctf-notes').toLowerCase().replace(/[^a-z0-9_-]/g, '_')}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleClear = () => {
    if (window.confirm('Clear all scratchpad notes?')) {
      setNotes('');
      setChallengeName('');
      setTargetHost('');
    }
  };

  const insertTemplate = (template: string) => {
    setNotes(prev => prev ? `${prev}\n\n${template}` : template);
  };

  const TEMPLATE_WRITEUP = `## Vulnerability Analysis
- Target Vector: 
- Discovered Vulnerability: 
- Flaw Description: 

## Exploitation Steps
1. 
2. 
3. 

## Discovered Flag
- Flag: `;

  const TEMPLATE_CREDS = `## Captured Credentials & Hashes
| Username | Password / Hash | Service | Notes |
|----------|-----------------|---------|-------|
| admin    |                 | HTTP    |       |`;

  const TEMPLATE_PAYLOADS = `## Tested Payloads & Responses
- Payload #1: 
  Result: 
- Payload #2: 
  Result: `;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden flex justify-end bg-black/60 backdrop-blur-sm animate-fade-in">
      <div className="w-full max-w-xl bg-[#080c14] border-l border-slate-800 flex flex-col h-full shadow-2xl font-mono text-xs text-gray-200">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 bg-[#05080f] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-emerald-950/60 border border-emerald-500/40 text-emerald-400">
              <FileText className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-white font-bold text-sm tracking-wide flex items-center gap-2">
                TACTICAL CTF SCRATCHPAD
                <span className={`text-[10px] px-1.5 py-0.2 rounded transition-opacity ${savedBadge ? 'bg-emerald-900 text-emerald-300 opacity-100' : 'opacity-0'}`}>
                  [SAVED LOCALLY]
                </span>
              </h3>
              <p className="text-[11px] text-gray-400 font-sans">
                Persistent auto-saving markdown notebook for active challenge notes and payloads.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-slate-800/60 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Quick Meta Controls */}
        <div className="p-4 border-b border-slate-800 bg-[#060a12] space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <div>
              <label className="text-[10px] text-gray-400 uppercase font-bold block mb-1">Challenge Name</label>
              <input
                type="text"
                value={challengeName}
                onChange={(e) => setChallengeName(e.target.value)}
                placeholder="e.g. SQLi Revenge 100"
                className="w-full bg-[#0b101b] border border-slate-800 rounded px-2.5 py-1.5 text-white placeholder-gray-600 focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div>
              <label className="text-[10px] text-gray-400 uppercase font-bold block mb-1">Target Host / IP:Port</label>
              <input
                type="text"
                value={targetHost}
                onChange={(e) => setTargetHost(e.target.value)}
                placeholder="e.g. 10.10.11.20:8080"
                className="w-full bg-[#0b101b] border border-slate-800 rounded px-2.5 py-1.5 text-white placeholder-gray-600 focus:outline-none focus:border-emerald-500"
              />
            </div>
          </div>

          {/* Category Pills */}
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[10px] text-gray-500 uppercase font-bold mr-1">Category:</span>
            {['Web', 'Crypto', 'Forensics', 'Pwn', 'Rev', 'Misc'].map((cat) => (
              <button
                key={cat}
                onClick={() => setCategory(cat)}
                className={`px-2 py-0.5 rounded text-[11px] transition-all ${
                  category === cat
                    ? 'bg-emerald-500 text-black font-bold'
                    : 'bg-[#0b101b] border border-slate-800 text-gray-400 hover:text-white'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>

          {/* Quick Template Inserters */}
          <div className="flex items-center gap-2 pt-1 border-t border-slate-800/60 overflow-x-auto">
            <span className="text-[10px] text-gray-500 uppercase font-bold shrink-0">Templates:</span>
            <button
              onClick={() => insertTemplate(TEMPLATE_WRITEUP)}
              className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-gray-300 hover:text-emerald-400 text-[10px] whitespace-nowrap"
            >
              + Writeup Flow
            </button>
            <button
              onClick={() => insertTemplate(TEMPLATE_CREDS)}
              className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-gray-300 hover:text-emerald-400 text-[10px] whitespace-nowrap"
            >
              + Credentials Table
            </button>
            <button
              onClick={() => insertTemplate(TEMPLATE_PAYLOADS)}
              className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-gray-300 hover:text-emerald-400 text-[10px] whitespace-nowrap"
            >
              + Payloads Log
            </button>
          </div>
        </div>

        {/* Editor Area */}
        <div className="flex-1 p-4 flex flex-col min-h-0 bg-[#070b14]">
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Type or paste challenge notes, intermediate offsets, command snippets, or thoughts here... Automatically saved in RAM and LocalStorage."
            className="flex-1 w-full bg-[#05080f] border border-slate-800 rounded-lg p-3 text-xs font-mono text-gray-200 placeholder-gray-600 focus:outline-none focus:border-emerald-500 resize-none leading-relaxed"
          />
        </div>

        {/* Footer */}
        <div className="p-3 border-t border-slate-800 bg-[#05080f] flex items-center justify-between">
          <div className="text-[11px] text-gray-500">
            {notes.length} characters &bull; {notes.split(/\s+/).filter(Boolean).length} words
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleClear}
              className="p-1.5 rounded border border-slate-800 text-gray-400 hover:text-red-400 hover:border-red-500/50 transition-all"
              title="Clear Scratchpad"
            >
              <Trash2 className="w-4 h-4" />
            </button>
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-white font-medium text-xs transition-all"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy Notes'}</span>
            </button>
            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-emerald-500 hover:bg-emerald-400 text-black font-bold text-xs transition-all"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export .md</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
