import React, { useState } from 'react';
import { X, Sparkles, Copy, Check, ArrowDownUp, Search, Key, ShieldAlert } from 'lucide-react';

interface QuickConverterModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const QuickConverterModal: React.FC<QuickConverterModalProps> = ({ isOpen, onClose }) => {
  const [activeTab, setActiveTab] = useState<'converter' | 'extractor'>('converter');

  // Converter state
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [mode, setMode] = useState<string>('b64decode');
  const [copied, setCopied] = useState(false);

  // IOC Extractor state
  const [rawLog, setRawLog] = useState('');
  const [extractedIocs, setExtractedIocs] = useState<{
    ips: string[];
    urls: string[];
    emails: string[];
    flags: string[];
    keys: string[];
    b64: string[];
  }>({ ips: [], urls: [], emails: [], flags: [], keys: [], b64: [] });
  const [copiedIocKey, setCopiedIocKey] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleConvert = (targetMode: string = mode, textToConvert: string = input) => {
    setMode(targetMode);
    try {
      let res = '';
      switch (targetMode) {
        case 'b64decode':
          res = atob(textToConvert.trim().replace(/\s/g, ''));
          break;
        case 'b64encode':
          res = btoa(textToConvert);
          break;
        case 'hexdecode':
          const cleanHex = textToConvert.replace(/[\s0x\\x]/g, '');
          let str = '';
          for (let i = 0; i < cleanHex.length; i += 2) {
            str += String.fromCharCode(parseInt(cleanHex.substring(i, i + 2), 16));
          }
          res = str;
          break;
        case 'hexencode':
          res = Array.from(new TextEncoder().encode(textToConvert))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
          break;
        case 'urldecode':
          res = decodeURIComponent(textToConvert);
          break;
        case 'urlencode':
          res = encodeURIComponent(textToConvert);
          break;
        case 'rot13':
          res = textToConvert.replace(/[a-zA-Z]/g, (c) => {
            const base = c <= 'Z' ? 65 : 97;
            return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
          });
          break;
        case 'reverse':
          res = textToConvert.split('').reverse().join('');
          break;
        default:
          res = textToConvert;
      }
      setOutput(res);
    } catch (e: any) {
      setOutput(`[Conversion error: ${e.message}]`);
    }
  };

  const handleExtractIocs = (text: string) => {
    setRawLog(text);
    if (!text.trim()) {
      setExtractedIocs({ ips: [], urls: [], emails: [], flags: [], keys: [], b64: [] });
      return;
    }

    // IPs (IPv4)
    const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
    const ips = Array.from(new Set(text.match(ipRegex) || []));

    // URLs
    const urlRegex = /https?:\/\/[^\s"'<>]+/g;
    const urls = Array.from(new Set(text.match(urlRegex) || []));

    // Emails
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const emails = Array.from(new Set(text.match(emailRegex) || []));

    // Flags
    const flagRegex = /\b[A-Za-z0-9_\-\.]{2,40}\{[^\}\n\r]{3,150}\}/g;
    const flags = Array.from(new Set(text.match(flagRegex) || []));

    // Private Keys / Secrets
    const keyRegex = /-----BEGIN [A-Z0-9_ ]+-----[\s\S]*?-----END [A-Z0-9_ ]+-----/g;
    const keys = Array.from(new Set(text.match(keyRegex) || []));

    // Base64 candidate strings (length 32+)
    const b64Regex = /\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b/g;
    const b64 = Array.from(new Set(text.match(b64Regex) || [])).slice(0, 20);

    setExtractedIocs({ ips, urls, emails, flags, keys, b64 });
  };

  const handleCopy = (textToCopy: string, keyName: string) => {
    navigator.clipboard.writeText(textToCopy);
    setCopiedIocKey(keyName);
    setTimeout(() => setCopiedIocKey(null), 2000);
  };

  const handleSwap = () => {
    setInput(output);
    setOutput(input);
  };

  const operations = [
    { id: 'b64decode', label: 'Base64 Dec' },
    { id: 'b64encode', label: 'Base64 Enc' },
    { id: 'hexdecode', label: 'Hex to Text' },
    { id: 'hexencode', label: 'Text to Hex' },
    { id: 'urldecode', label: 'URL Dec' },
    { id: 'urlencode', label: 'URL Enc' },
    { id: 'rot13', label: 'ROT13' },
    { id: 'reverse', label: 'Reverse' },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="bg-cyber-dark border border-cyber-cyan/40 rounded-2xl w-full max-w-3xl flex flex-col shadow-2xl glow-cyan overflow-hidden max-h-[90vh]">
        {/* Header */}
        <div className="p-4 border-b border-cyber-border flex items-center justify-between bg-cyber-card/60">
          <div className="flex items-center gap-3">
            <Sparkles className="w-5 h-5 text-cyber-cyan" />
            <h2 className="text-base font-bold font-mono text-white">
              QUICK SCRATCHPAD & IOC EXTRACTOR
            </h2>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-cyber-card transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Switcher */}
        <div className="flex border-b border-cyber-border bg-cyber-darker px-4 gap-2 pt-2">
          <button
            onClick={() => setActiveTab('converter')}
            className={`px-4 py-2 font-mono text-xs rounded-t-lg transition-all border-t border-x ${
              activeTab === 'converter'
                ? 'bg-cyber-card border-cyber-cyan text-cyber-cyan font-bold'
                : 'border-transparent text-gray-400 hover:text-white'
            }`}
          >
            Instant Converter
          </button>
          <button
            onClick={() => setActiveTab('extractor')}
            className={`px-4 py-2 font-mono text-xs rounded-t-lg transition-all border-t border-x ${
              activeTab === 'extractor'
                ? 'bg-cyber-card border-cyber-green text-cyber-green font-bold'
                : 'border-transparent text-gray-400 hover:text-white'
            }`}
          >
            IOC & Cyber Pattern Extractor
          </button>
        </div>

        {/* TAB 1: Converter */}
        {activeTab === 'converter' && (
          <div className="flex flex-col overflow-y-auto">
            {/* Buttons Bar */}
            <div className="p-3 bg-cyber-darker border-b border-cyber-border flex flex-wrap gap-1.5">
              {operations.map((op) => (
                <button
                  key={op.id}
                  onClick={() => handleConvert(op.id)}
                  className={`text-xs font-mono px-3 py-1.5 rounded-lg border transition-all ${
                    mode === op.id
                      ? 'bg-cyber-cyan/20 border-cyber-cyan text-cyber-cyan font-bold'
                      : 'bg-cyber-card border-cyber-border text-gray-400 hover:text-white'
                  }`}
                >
                  {op.label}
                </button>
              ))}
            </div>

            {/* Workspace */}
            <div className="p-5 space-y-4">
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-xs font-mono text-gray-400 uppercase">Input Text</label>
                  <button
                    onClick={handleSwap}
                    className="text-[11px] font-mono text-cyber-cyan hover:underline flex items-center gap-1"
                    title="Swap input and output"
                  >
                    <ArrowDownUp className="w-3 h-3" /> Swap
                  </button>
                </div>
                <textarea
                  value={input}
                  onChange={(e) => {
                    setInput(e.target.value);
                    handleConvert(mode, e.target.value);
                  }}
                  rows={3}
                  placeholder="Type or paste text..."
                  className="w-full bg-cyber-darker border border-cyber-border rounded-lg p-3 text-xs font-mono text-white placeholder-gray-600 focus:outline-none focus:border-cyber-cyan/60"
                />
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-xs font-mono text-cyber-green uppercase font-bold">Converted Output</label>
                  {output && (
                    <button
                      onClick={() => handleCopy(output, 'conv_out')}
                      className="text-[11px] font-mono text-gray-400 hover:text-white flex items-center gap-1"
                    >
                      {copiedIocKey === 'conv_out' ? <Check className="w-3 h-3 text-cyber-green" /> : <Copy className="w-3 h-3" />}
                      {copiedIocKey === 'conv_out' ? 'Copied' : 'Copy Output'}
                    </button>
                  )}
                </div>
                <textarea
                  value={output}
                  readOnly
                  rows={4}
                  placeholder="Output appears instantly..."
                  className="w-full bg-black/60 border border-cyber-border rounded-lg p-3 text-xs font-mono text-cyber-green select-all focus:outline-none"
                />
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: IOC & Cyber Pattern Extractor */}
        {activeTab === 'extractor' && (
          <div className="p-5 space-y-4 overflow-y-auto font-mono text-xs">
            <div>
              <label className="text-gray-400 uppercase block mb-1.5">
                Paste Raw Log / Memory Dump / Strings
              </label>
              <textarea
                value={rawLog}
                onChange={(e) => handleExtractIocs(e.target.value)}
                rows={4}
                placeholder="Paste server logs, terminal output, memory dump strings, or Wireshark stream here..."
                className="w-full bg-cyber-darker border border-cyber-border rounded-lg p-3 text-white placeholder-gray-600 focus:outline-none focus:border-cyber-green text-xs"
              />
            </div>

            {/* Extracted Artifacts View */}
            <div className="space-y-3">
              {/* Flags */}
              {extractedIocs.flags.length > 0 && (
                <div className="p-3 bg-cyber-green/10 border border-cyber-green/40 rounded-lg space-y-1.5">
                  <div className="flex items-center justify-between text-cyber-green font-bold">
                    <span>Captured Flags ({extractedIocs.flags.length})</span>
                    <button
                      onClick={() => handleCopy(extractedIocs.flags.join('\n'), 'flags_all')}
                      className="text-[11px] hover:underline"
                    >
                      {copiedIocKey === 'flags_all' ? 'Copied All' : 'Copy All'}
                    </button>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {extractedIocs.flags.map((f, i) => (
                      <span key={i} className="bg-black/80 px-2.5 py-1 rounded border border-cyber-green/40 text-cyber-green text-xs select-all">
                        {f}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* IP Addresses */}
              <div className="p-3 bg-cyber-darker border border-cyber-border rounded-lg space-y-1.5">
                <div className="flex items-center justify-between text-white font-bold">
                  <span>IPv4 Addresses ({extractedIocs.ips.length})</span>
                  {extractedIocs.ips.length > 0 && (
                    <button
                      onClick={() => handleCopy(extractedIocs.ips.join('\n'), 'ips_all')}
                      className="text-[11px] text-gray-400 hover:text-white"
                    >
                      {copiedIocKey === 'ips_all' ? 'Copied All' : 'Copy All'}
                    </button>
                  )}
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {extractedIocs.ips.length > 0 ? (
                    extractedIocs.ips.map((ip, i) => (
                      <span key={i} className="bg-black/60 px-2 py-0.5 rounded text-blue-400 border border-cyber-border select-all">
                        {ip}
                      </span>
                    ))
                  ) : (
                    <span className="text-gray-600 text-[11px]">No IP addresses detected</span>
                  )}
                </div>
              </div>

              {/* URLs */}
              <div className="p-3 bg-cyber-darker border border-cyber-border rounded-lg space-y-1.5">
                <div className="flex items-center justify-between text-white font-bold">
                  <span>URLs & Endpoints ({extractedIocs.urls.length})</span>
                  {extractedIocs.urls.length > 0 && (
                    <button
                      onClick={() => handleCopy(extractedIocs.urls.join('\n'), 'urls_all')}
                      className="text-[11px] text-gray-400 hover:text-white"
                    >
                      {copiedIocKey === 'urls_all' ? 'Copied All' : 'Copy All'}
                    </button>
                  )}
                </div>
                <div className="space-y-1 max-h-32 overflow-y-auto">
                  {extractedIocs.urls.length > 0 ? (
                    extractedIocs.urls.map((u, i) => (
                      <div key={i} className="text-cyber-cyan text-xs select-all truncate">
                        {u}
                      </div>
                    ))
                  ) : (
                    <span className="text-gray-600 text-[11px]">No URLs detected</span>
                  )}
                </div>
              </div>

              {/* Emails */}
              <div className="p-3 bg-cyber-darker border border-cyber-border rounded-lg space-y-1.5">
                <div className="flex items-center justify-between text-white font-bold">
                  <span>Email Addresses ({extractedIocs.emails.length})</span>
                  {extractedIocs.emails.length > 0 && (
                    <button
                      onClick={() => handleCopy(extractedIocs.emails.join('\n'), 'emails_all')}
                      className="text-[11px] text-gray-400 hover:text-white"
                    >
                      {copiedIocKey === 'emails_all' ? 'Copied All' : 'Copy All'}
                    </button>
                  )}
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {extractedIocs.emails.length > 0 ? (
                    extractedIocs.emails.map((e, i) => (
                      <span key={i} className="bg-black/60 px-2 py-0.5 rounded text-yellow-300 border border-cyber-border select-all">
                        {e}
                      </span>
                    ))
                  ) : (
                    <span className="text-gray-600 text-[11px]">No emails detected</span>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
