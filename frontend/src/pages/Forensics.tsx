import React, { useState } from 'react';
import { 
  FileSearch,
  UploadCloud, 
  File, 
  AlertCircle, 
  CheckCircle, 
  ChevronRight, 
  RefreshCw, 
  Copy, 
  Check, 
  Binary, 
  Search, 
  MessageSquare, 
  Hash, 
  Terminal,
  ImageIcon,
  HardDrive,
  FileSpreadsheet,
  Download
} from 'lucide-react';
import { analyzeFile, checkFileHeader, repairFileHeader, HeaderCheckResult } from '../api/client';
import { FlagCard } from '../components/FlagCard';
import { useApp } from '../context/AppContext';

interface ForensicsProps {
  onNavigateToChat?: () => void;
}

export const Forensics: React.FC<ForensicsProps> = ({ onNavigateToChat }) => {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  // Magic Byte Check & Repair State
  const [headerInfo, setHeaderInfo] = useState<HeaderCheckResult | null>(null);
  const [targetRepairFormat, setTargetRepairFormat] = useState('png');
  const [headerLoading, setHeaderLoading] = useState(false);
  const [repairSuccessMsg, setRepairSuccessMsg] = useState<string | null>(null);
  
  // Tabs inside results
  const [activeTab, setActiveTab] = useState<'pipeline' | 'pcap' | 'hexdump' | 'strings' | 'artifacts' | 'stego'>('pipeline');
  const [stringFilter, setStringFilter] = useState('');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const { setChatContext, sendToTab } = useApp();

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const handleAnalyze = async () => {
    if (!file) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await analyzeFile(file);
      setResult(data);
      if (data.pcap_dissection) {
        setActiveTab('pcap');
      } else if (data.extracted_image_data_uri || data.dd_details || data.evtx_summary) {
        setActiveTab('artifacts');
      }
    } catch (err: any) {
      setError(err.message || 'Analysis failed');
    } finally {
      setLoading(false);
    }
  };

  const handleCheckHeader = async () => {
    if (!file) return;
    setHeaderLoading(true);
    setRepairSuccessMsg(null);
    try {
      const info = await checkFileHeader(file);
      setHeaderInfo(info);
      if (info.extension && ['png', 'jpg', 'gif', 'zip', 'pdf', 'elf', 'pcap', 'pcapng'].includes(info.extension)) {
        setTargetRepairFormat(info.extension);
      }
    } catch (e: any) {
      setError(e.message || 'Header check failed');
    } finally {
      setHeaderLoading(false);
    }
  };

  const handleRepairHeader = async () => {
    if (!file) return;
    setHeaderLoading(true);
    setRepairSuccessMsg(null);
    try {
      const blob = await repairFileHeader(file, targetRepairFormat);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const baseName = file.name.substring(0, file.name.lastIndexOf('.')) || file.name;
      a.download = `${baseName}_repaired.${targetRepairFormat}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      setRepairSuccessMsg(`Repaired header for format [${targetRepairFormat.toUpperCase()}] and downloaded.`);
    } catch (e: any) {
      setError(e.message || 'Header repair failed');
    } finally {
      setHeaderLoading(false);
    }
  };

  const handleCopyText = (text: string, type: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(type);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const handleAskAI = () => {
    if (!result) return;
    const summary = `Challenge File: ${file?.name} (${file?.size} bytes)
Status: ${result.status}
Magic Bytes: ${JSON.stringify(result.steps?.[0]?.result || {})}
Hints: ${JSON.stringify(result.hints || [])}
Extracted Strings Count: ${result.file_meta?.strings_count || 0}`;
    setChatContext(summary);
    if (onNavigateToChat) {
      onNavigateToChat();
    }
  };

  const filteredStrings = (result?.file_meta?.sample_strings || []).filter((s: string) =>
    s.toLowerCase().includes(stringFilter.toLowerCase())
  );

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-semibold font-sans text-slate-100 flex items-center gap-2">
            <FileSearch className="w-5 h-5 text-emerald-400" />
            Digital Artifact & File Forensics
          </h2>
          <p className="text-slate-400 text-xs mt-1 font-sans">
            Multi-layer automated analysis: PCAP network traffic, Windows EVTX event logs, raw disk images, embedded artifacts, and header verification.
          </p>
        </div>

        {result && (
          <button
            onClick={handleAskAI}
            className="flex items-center gap-2 px-3 py-1.5 rounded bg-slate-900 border border-slate-700 hover:bg-slate-800 text-slate-200 text-xs font-sans transition-colors"
          >
            <MessageSquare className="w-4 h-4 text-emerald-400" />
            <span>Consult AI Advisor</span>
          </button>
        )}
      </div>

      {/* Upload Zone */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-6">
        <label className="border-2 border-dashed border-cyber-border hover:border-cyber-green/50 rounded-lg p-8 flex flex-col items-center justify-center cursor-pointer transition-all bg-cyber-dark/40 hover:bg-cyber-dark/80 group">
          <UploadCloud className="w-12 h-12 text-gray-500 group-hover:text-cyber-green transition-colors mb-3" />
          <span className="text-sm font-medium text-gray-300 group-hover:text-white">
            {file ? file.name : "Click to select or drag and drop challenge file"}
          </span>
          <span className="text-xs text-gray-500 mt-1 font-mono">
            Accepts PCAP, EVTX, .dd, images, archives, memory dumps, or corrupted headers
          </span>
          <input type="file" className="hidden" onChange={handleFileChange} />
        </label>

        {file && (
          <div className="mt-4 flex items-center justify-between bg-cyber-dark px-4 py-3 rounded-lg border border-cyber-border">
            <div className="flex items-center gap-3">
              <File className="w-5 h-5 text-cyber-cyan" />
              <div>
                <p className="text-sm font-mono text-white">{file.name}</p>
                <p className="text-xs text-gray-500">{(file.size / 1024).toFixed(1)} KB</p>
              </div>
            </div>
            <button
              onClick={handleAnalyze}
              disabled={loading}
              className="flex items-center gap-2 px-5 py-2 rounded-lg bg-cyber-green text-black font-semibold text-sm hover:bg-cyber-green/90 disabled:opacity-50 transition-all font-mono"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Analyzing Pipeline...
                </>
              ) : (
                'Run Deep Forensics'
              )}
            </button>
          </div>
        )}
      </div>

      {/* Magic Byte Repair & Header Restorer */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-cyber-border pb-3">
          <div className="flex items-center gap-2">
            <Binary className="w-5 h-5 text-cyber-cyan" />
            <h3 className="text-white font-bold text-sm uppercase tracking-wider font-mono">
              [FORENSICS] Magic Byte Repair & Header Restoration
            </h3>
          </div>
          <span className="text-[11px] text-gray-500 font-mono">PNG / JPG / GIF / ZIP / PDF / ELF / PCAP</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
          <div className="space-y-3 bg-cyber-darker p-4 rounded-lg border border-cyber-border">
            <span className="text-cyber-cyan font-bold uppercase block">
              1. Header Corruption Diagnosis
            </span>
            <p className="text-gray-400 text-[11px]">
              Verifies if file header bytes match the expected signature for its extension or detects corruption.
            </p>
            <button
              onClick={handleCheckHeader}
              disabled={headerLoading || !file}
              className="w-full py-2 bg-cyber-cyan/20 border border-cyber-cyan/50 hover:bg-cyber-cyan/30 text-cyber-cyan font-bold rounded transition-all flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {headerLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
              {file ? `Check Header of ${file.name}` : 'Select a File to Check Header'}
            </button>

            {headerInfo && (
              <div className={`p-3 rounded border text-[11px] space-y-1.5 ${headerInfo.is_corrupted ? 'bg-red-950/30 border-red-500/50 text-red-200' : 'bg-emerald-950/30 border-emerald-500/50 text-emerald-200'}`}>
                <div className="flex items-center justify-between font-bold">
                  <span>Status: {headerInfo.is_corrupted ? 'CORRUPTED HEADER DETECTED' : 'VALID / UNKNOWN'}</span>
                  <span className="uppercase text-[10px] px-1.5 py-0.5 rounded bg-black/40">
                    {headerInfo.expected_format}
                  </span>
                </div>
                <div>Prefix Hex: <code className="text-white font-bold select-all">{headerInfo.current_header_hex}</code></div>
                {headerInfo.expected_magic_hex && (
                  <div>Expected Magic: <code className="text-white font-bold select-all">{headerInfo.expected_magic_hex}</code></div>
                )}
                <div className="text-[11px] text-gray-300">{headerInfo.diagnosis}</div>
              </div>
            )}
          </div>

          <div className="space-y-3 bg-cyber-darker p-4 rounded-lg border border-cyber-border">
            <span className="text-emerald-400 font-bold uppercase block">
              2. 1-Click Magic Byte Fixer & Download
            </span>
            <div>
              <label className="text-gray-400 block mb-1">Target Signature to Inject:</label>
              <select
                value={targetRepairFormat}
                onChange={(e) => setTargetRepairFormat(e.target.value)}
                className="w-full bg-black/60 border border-cyber-border rounded px-3 py-1.5 text-white focus:outline-none focus:border-emerald-500"
              >
                <option value="png">PNG Image (\x89PNG\r\n\x1a\n)</option>
                <option value="jpg">JPEG Image (\xff\xd8\xff\xe0)</option>
                <option value="gif">GIF89a Image (GIF89a)</option>
                <option value="zip">ZIP Archive / Docx / APK (PK\x03\x04)</option>
                <option value="pdf">PDF Document (%PDF-)</option>
                <option value="elf">Linux ELF Executable (\x7fELF)</option>
                <option value="pcap">PCAP Capture (\xd4\xc3\xb2\xa1)</option>
                <option value="pcapng">PCAPNG Capture (\n\r\r\n)</option>
              </select>
            </div>

            <button
              onClick={handleRepairHeader}
              disabled={headerLoading || !file}
              className="w-full py-2 bg-emerald-500/20 border border-emerald-500/50 hover:bg-emerald-500/30 text-emerald-300 font-bold rounded transition-all flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {headerLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
              Inject Signature & Download Repaired File
            </button>

            {repairSuccessMsg && (
              <div className="p-2.5 rounded bg-emerald-950/40 border border-emerald-500/40 text-emerald-300 text-[11px]">
                {repairSuccessMsg}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/50 flex items-start gap-3 text-red-200">
          <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <h4 className="font-semibold text-sm">Analysis Error</h4>
            <p className="text-xs text-red-300 mt-0.5 font-mono">{error}</p>
          </div>
        </div>
      )}

      {/* Results View */}
      {result && (
        <div className="space-y-6">
          {/* Flags Banner */}
          <FlagCard flags={result.flags_found || []} source={`Forensics (${file?.name})`} />

          {/* Extracted Image Preview (Featured in mac-voice-assistant) */}
          {result.extracted_image_data_uri && (
            <div className="border border-cyber-green/40 bg-black/80 rounded-xl p-5 space-y-3 glow-green">
              <div className="flex items-center justify-between text-xs font-mono text-cyber-green font-bold">
                <span className="flex items-center gap-2">
                  <ImageIcon className="w-4 h-4" />
                  DECODED IMAGE ARTIFACT
                </span>
                <span className="text-gray-400">{result.extracted_file?.split('/').pop()}</span>
              </div>
              <div className="flex justify-center bg-black/95 p-4 rounded-lg border border-neutral-800">
                <img 
                  src={result.extracted_image_data_uri} 
                  alt="Extracted Artifact" 
                  className="max-h-80 object-contain rounded border border-cyber-border shadow-lg" 
                />
              </div>
            </div>
          )}

          {/* Hashes & File Meta */}
          {result.file_meta && (
            <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between border-b border-cyber-border pb-2">
                <span className="text-gray-400 uppercase font-bold flex items-center gap-1.5">
                  <Hash className="w-4 h-4 text-cyber-cyan" /> Cryptographic Hashes
                </span>
                <div className="flex items-center gap-3">
                  <a
                    href="http://localhost:8000/api/forensics/download-extracted"
                    download="shadowsolve_carved_artifacts.zip"
                    className="flex items-center gap-1.5 px-3 py-1 rounded bg-cyber-green/10 border border-cyber-green/40 hover:bg-cyber-green/20 text-cyber-green text-xs font-mono transition-all"
                    title="Download all extracted and carved files as a .zip"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download Carved Artifacts (.zip)</span>
                  </a>
                  <span className="text-gray-500">Size: {result.file_meta.size_bytes} bytes</span>
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {['md5', 'sha1', 'sha256'].map((hType) => (
                  <div key={hType} className="bg-cyber-darker p-2.5 rounded border border-cyber-border flex items-center justify-between">
                    <div className="truncate mr-2">
                      <span className="text-gray-500 block text-[10px] uppercase">{hType}</span>
                      <span className="text-gray-300 select-all truncate block">{result.file_meta[hType]}</span>
                    </div>
                    <button
                      onClick={() => handleCopyText(result.file_meta[hType], hType)}
                      className="p-1 text-gray-400 hover:text-white"
                      title="Copy Hash"
                    >
                      {copiedHash === hType ? <Check className="w-3.5 h-3.5 text-cyber-green" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Hints & Recommendations */}
          {result.hints && result.hints.length > 0 && (
            <div className="bg-cyber-card border border-yellow-500/30 rounded-xl p-5">
              <h3 className="text-sm font-bold font-mono text-yellow-400 uppercase tracking-wider mb-2 flex items-center gap-2">
                <span className="px-1.5 py-0.5 rounded bg-yellow-500/20 text-yellow-400 font-mono text-[10px]">[DISCOVERY]</span>
                <span>Pipeline Discoveries & Artifacts</span>
              </h3>
              <ul className="space-y-1.5 text-sm text-gray-300 font-mono">
                {result.hints.map((hint: string, idx: number) => (
                  <li key={idx} className="flex items-start gap-2">
                    <span className="text-yellow-400 font-bold">•</span>
                    <span>{hint}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Sub-Tabs: Pipeline, Hexdump, Strings, Artifacts */}
          <div className="bg-cyber-card border border-cyber-border rounded-xl overflow-hidden">
            <div className="flex border-b border-cyber-border bg-cyber-darker px-4 pt-2 gap-2 overflow-x-auto">
              <button
                onClick={() => setActiveTab('pipeline')}
                className={`px-4 py-2 text-xs font-mono rounded-t-lg transition-colors border-t border-x ${
                  activeTab === 'pipeline'
                    ? 'bg-cyber-card border-cyber-green/50 text-cyber-green font-bold'
                    : 'border-transparent text-gray-400 hover:text-white'
                }`}
              >
                Pipeline Steps ({result.steps?.length || 0})
              </button>
              {result.pcap_dissection && (
                <button
                  onClick={() => setActiveTab('pcap')}
                  className={`px-4 py-2 text-xs font-mono rounded-t-lg transition-colors border-t border-x flex items-center gap-1.5 ${
                    activeTab === 'pcap'
                      ? 'bg-cyber-card border-cyan-500/50 text-cyan-400 font-bold'
                      : 'border-transparent text-gray-400 hover:text-white'
                  }`}
                >
                  <span>[WIRESHARK PCAP] ({result.pcap_dissection.total_packets || 0} pkts)</span>
                </button>
              )}
              {result.stego_analysis && result.stego_analysis.is_image && (
                <button
                  onClick={() => setActiveTab('stego')}
                  className={`px-4 py-2 text-xs font-mono rounded-t-lg transition-colors border-t border-x flex items-center gap-1.5 ${
                    activeTab === 'stego'
                      ? 'bg-cyber-card border-emerald-500/50 text-emerald-400 font-bold'
                      : 'border-transparent text-gray-400 hover:text-white'
                  }`}
                >
                  <ImageIcon className="w-3.5 h-3.5" />
                  <span>[IMAGE STEGO & LSB] ({result.stego_analysis.format})</span>
                </button>
              )}
              {(result.dd_details || result.evtx_summary || result.memory_details) && (
                <button
                  onClick={() => setActiveTab('artifacts')}
                  className={`px-4 py-2 text-xs font-mono rounded-t-lg transition-colors border-t border-x ${
                    activeTab === 'artifacts'
                      ? 'bg-cyber-card border-yellow-500/50 text-yellow-400 font-bold'
                      : 'border-transparent text-gray-400 hover:text-white'
                  }`}
                >
                  Deep Artifacts (Disk/EVTX)
                </button>
              )}
              <button
                onClick={() => setActiveTab('hexdump')}
                className={`px-4 py-2 text-xs font-mono rounded-t-lg transition-colors border-t border-x ${
                  activeTab === 'hexdump'
                    ? 'bg-cyber-card border-cyber-cyan/50 text-cyber-cyan font-bold'
                    : 'border-transparent text-gray-400 hover:text-white'
                }`}
              >
                Hex Dump (1KB)
              </button>
              <button
                onClick={() => setActiveTab('strings')}
                className={`px-4 py-2 text-xs font-mono rounded-t-lg transition-colors border-t border-x ${
                  activeTab === 'strings'
                    ? 'bg-cyber-card border-purple-500/50 text-purple-300 font-bold'
                    : 'border-transparent text-gray-400 hover:text-white'
                }`}
              >
                Extracted Strings ({result.file_meta?.strings_count || 0})
              </button>
            </div>

            <div className="p-5">
              {activeTab === 'pipeline' && (
                <div className="space-y-3">
                  {result.steps?.map((st: any, idx: number) => {
                    const hasFlag = st.result?.flags_found && st.result.flags_found.length > 0;
                    return (
                      <div 
                        key={idx}
                        className={`border rounded-lg p-3.5 bg-cyber-darker/60 font-mono text-xs ${
                          hasFlag ? 'border-cyber-green/50 bg-cyber-green/5' : 'border-cyber-border'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1.5">
                          <span className="text-white font-semibold text-sm flex items-center gap-2">
                            {hasFlag ? (
                              <CheckCircle className="w-4 h-4 text-cyber-green" />
                            ) : (
                              <ChevronRight className="w-4 h-4 text-gray-500" />
                            )}
                            {st.step}
                          </span>
                          {hasFlag && (
                            <span className="bg-cyber-green/20 text-cyber-green px-2 py-0.5 rounded text-[10px] font-bold">
                              FLAG FOUND
                            </span>
                          )}
                        </div>
                        <pre className="text-gray-400 overflow-x-auto p-2 bg-black/40 rounded mt-2 select-all">
                          {typeof st.result === 'object' 
                            ? JSON.stringify(st.result, null, 2) 
                            : String(st.result)}
                        </pre>
                      </div>
                    );
                  })}
                </div>
              )}

              {activeTab === 'pcap' && result.pcap_dissection && (
                <div className="space-y-6 font-mono text-xs">
                  {/* Protocol Distribution */}
                  <div>
                    <h4 className="text-cyan-400 font-bold mb-2 uppercase tracking-wider flex items-center gap-2">
                      <Terminal className="w-4 h-4" /> Protocol Dissection Summary ({result.pcap_dissection.total_packets} Packets)
                    </h4>
                    <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-7 gap-2">
                      {Object.entries(result.pcap_dissection.protocol_stats || {}).map(([proto, count]: [string, any]) => (
                        <div key={proto} className="bg-cyber-darker p-2.5 rounded border border-cyber-border text-center">
                          <span className="text-[10px] text-gray-400 block uppercase">{proto}</span>
                          <span className="text-sm font-bold text-white">{count}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Harvested Credentials */}
                  {result.pcap_dissection.credentials_found?.length > 0 && (
                    <div className="bg-rose-950/20 border border-rose-500/40 rounded-xl p-4 space-y-2">
                      <h4 className="text-rose-400 font-bold uppercase tracking-wider flex items-center gap-2">
                        <AlertCircle className="w-4 h-4 text-rose-400" /> Plaintext Credentials & Sensitive Data Captured
                      </h4>
                      <div className="space-y-2">
                        {result.pcap_dissection.credentials_found.map((c: any, idx: number) => (
                          <div key={idx} className="bg-black/60 p-2.5 rounded border border-rose-500/30 flex flex-col gap-1">
                            <div className="flex items-center justify-between text-[11px]">
                              <span className="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold">{c.type}</span>
                              <span className="text-gray-400">{c.source}</span>
                            </div>
                            {c.decoded && (
                              <div className="text-emerald-400 font-bold select-all">
                                Decoded: {c.decoded}
                              </div>
                            )}
                            {c.parameter_value && (
                              <div className="text-yellow-300 font-bold select-all">
                                Parameter Value: {c.parameter_value}
                              </div>
                            )}
                            {c.raw_snippet && (
                              <pre className="text-[10px] text-gray-400 p-1 bg-black/40 rounded truncate select-all">
                                {c.raw_snippet}
                              </pre>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Top Conversations */}
                  {result.pcap_dissection.top_conversations?.length > 0 && (
                    <div>
                      <h4 className="text-emerald-400 font-bold mb-2 uppercase tracking-wider flex items-center gap-2">
                        <Hash className="w-4 h-4" /> Top Network Conversations & Flows
                      </h4>
                      <div className="overflow-x-auto border border-cyber-border rounded-lg bg-cyber-darker">
                        <table className="w-full text-left text-xs">
                          <thead className="bg-black/40 text-gray-400 border-b border-cyber-border text-[11px] uppercase">
                            <tr>
                              <th className="p-2.5">Endpoint A</th>
                              <th className="p-2.5">Endpoint B</th>
                              <th className="p-2.5">Protocol</th>
                              <th className="p-2.5">Packets</th>
                              <th className="p-2.5">Bytes</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-gray-900/40 text-gray-300">
                            {result.pcap_dissection.top_conversations.map((conv: any, idx: number) => (
                              <tr key={idx} className="hover:bg-black/30 font-mono">
                                <td className="p-2.5 text-cyan-300">{conv.endpoint_a}</td>
                                <td className="p-2.5 text-cyan-300">{conv.endpoint_b}</td>
                                <td className="p-2.5 text-gray-400">{conv.proto}</td>
                                <td className="p-2.5 text-white">{conv.packets}</td>
                                <td className="p-2.5 text-emerald-400 font-bold">{conv.bytes} B</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  {/* Exported HTTP Objects */}
                  {result.pcap_dissection.exported_objects?.length > 0 && (
                    <div>
                      <h4 className="text-yellow-400 font-bold mb-2 uppercase tracking-wider flex items-center gap-2">
                        <Download className="w-4 h-4" /> Carved Transferred HTTP Objects ({result.pcap_dissection.exported_objects.length})
                      </h4>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        {result.pcap_dissection.exported_objects.map((obj: any, idx: number) => (
                          <div key={idx} className="bg-cyber-darker p-3 rounded-lg border border-cyber-border space-y-2">
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-white truncate max-w-[200px]" title={obj.filename}>
                                {obj.filename}
                              </span>
                              <span className="text-[10px] text-gray-400">{obj.size_bytes} bytes</span>
                            </div>
                            <div className="text-[10px] text-cyan-400 truncate">{obj.mime} &bull; SHA256: {obj.sha256}</div>
                            {obj.data_uri && (
                              <img src={obj.data_uri} alt={obj.filename} className="max-h-36 rounded border border-gray-800 object-contain mx-auto" />
                            )}
                            {obj.preview && (
                              <pre className="text-[10px] text-gray-400 p-2 bg-black/60 rounded select-all max-h-24 overflow-y-auto">
                                {obj.preview}
                              </pre>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Follow TCP Streams */}
                  {result.pcap_dissection.tcp_streams && Object.keys(result.pcap_dissection.tcp_streams).length > 0 && (
                    <div>
                      <h4 className="text-purple-400 font-bold mb-2 uppercase tracking-wider flex items-center gap-2">
                        <MessageSquare className="w-4 h-4" /> Follow Reconstructed TCP Streams
                      </h4>
                      <div className="space-y-4">
                        {Object.entries(result.pcap_dissection.tcp_streams).map(([streamKey, packets]: [string, any]) => (
                          <div key={streamKey} className="bg-cyber-darker rounded-lg border border-cyber-border overflow-hidden">
                            <div className="bg-black/60 px-3 py-2 border-b border-cyber-border text-[11px] font-bold text-gray-300 flex items-center justify-between">
                              <span>Stream: {streamKey}</span>
                              <span className="text-gray-500 font-normal">{packets.length} packets</span>
                            </div>
                            <div className="p-3 max-h-64 overflow-y-auto space-y-2 select-all">
                              {packets.map((p: any, pIdx: number) => (
                                <div key={pIdx} className={`p-2 rounded text-[11px] font-mono leading-relaxed ${
                                  p.direction === 'out' 
                                    ? 'bg-cyan-950/20 text-cyan-200 border-l-2 border-cyan-500' 
                                    : 'bg-emerald-950/20 text-emerald-200 border-l-2 border-emerald-500'
                                }`}>
                                  <div className="text-[9px] text-gray-500 mb-0.5">
                                    [Pkt #{p.packet_num}] {p.sender} &rarr; {p.receiver} ({p.size}B)
                                  </div>
                                  <pre className="whitespace-pre-wrap">{p.snippet}</pre>
                                </div>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'artifacts' && (
                <div className="space-y-4 font-mono text-xs">
                  {/* Disk Details */}
                  {result.dd_details && (
                    <div className="space-y-3">
                      <h4 className="text-cyber-green font-bold flex items-center gap-2">
                        <HardDrive className="w-4 h-4" /> Disk Partitions & Files
                      </h4>
                      <div className="bg-cyber-darker p-3 rounded-lg border border-cyber-border space-y-2">
                        <div>Partitions Found: {result.dd_details.partitions?.length || 0}</div>
                        <div className="text-gray-400">
                          {result.dd_details.files_found?.length ? `Extracted Files: ${result.dd_details.files_found.join(', ')}` : 'No loose files extracted.'}
                        </div>
                        {result.dd_details.carved_files?.length > 0 && (
                          <div className="text-yellow-400">
                            Carved Files: {JSON.stringify(result.dd_details.carved_files)}
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* EVTX Summary */}
                  {result.evtx_summary && (
                    <div className="space-y-3">
                      <h4 className="text-cyber-cyan font-bold flex items-center gap-2">
                        <FileSpreadsheet className="w-4 h-4" /> Windows Event Log Summary
                      </h4>
                      <div className="bg-cyber-darker p-3 rounded-lg border border-cyber-border space-y-2">
                        <div>Total Events Parsed: {result.evtx_summary.total_events}</div>
                        {result.evtx_summary.powershell_commands?.length > 0 && (
                          <div>
                            <span className="text-orange-400 block mb-1">PowerShell Commands:</span>
                            <pre className="p-2 bg-black/60 rounded text-gray-300">
                              {JSON.stringify(result.evtx_summary.powershell_commands, null, 2)}
                            </pre>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Steganography & LSB Panel */}
              {activeTab === 'stego' && result.stego_analysis && (
                <div className="space-y-4 font-mono text-xs">
                  {/* Trailing Overlay Alert */}
                  {result.stego_analysis.trailing_overlay?.detected ? (
                    <div className="bg-red-950/40 border border-red-500/50 p-4 rounded-xl space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-red-400 font-bold text-sm uppercase flex items-center gap-2">
                          <AlertCircle className="w-4 h-4 text-red-400" />
                          [CRITICAL FINDING] Appended Trailing Overlay Data ({result.stego_analysis.trailing_overlay.size_bytes} bytes)
                        </span>
                        <span className="px-2 py-0.5 rounded bg-red-900 text-red-200 text-[10px] font-bold">
                          POST-EOF PAYLOAD
                        </span>
                      </div>
                      <p className="text-gray-300 text-xs">
                        Hidden payload appended after the end-of-image terminator (IEND / EOI). Common in CTF forensics.
                      </p>
                      <pre className="bg-black/60 p-2.5 rounded text-red-200 text-xs overflow-x-auto select-all">
                        {result.stego_analysis.trailing_overlay.preview}
                      </pre>
                    </div>
                  ) : (
                    <div className="bg-cyber-darker p-3 rounded-lg border border-cyber-border text-gray-400 flex items-center justify-between">
                      <span>Trailing Overlay Check:</span>
                      <span className="text-emerald-400 font-bold">[OK] Clean EOF (No trailing data detected)</span>
                    </div>
                  )}

                  {/* LSB Channel Extractions */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* RGB Combined LSB */}
                    <div className="bg-cyber-darker p-3.5 rounded-lg border border-cyber-border space-y-2">
                      <div className="flex items-center justify-between border-b border-cyber-border pb-1.5">
                        <span className="text-emerald-400 font-bold uppercase">RGB Combined LSB Bit-Plane</span>
                        <span className="text-gray-500 text-[10px]">Bit 0 (R+G+B)</span>
                      </div>
                      {result.stego_analysis.lsb_analysis?.rgb_combined?.embedded_magics?.length > 0 && (
                        <div className="text-yellow-400 text-[11px] font-bold">
                          Magic Signatures: {result.stego_analysis.lsb_analysis.rgb_combined.embedded_magics.join(', ')}
                        </div>
                      )}
                      <pre className="bg-black/50 p-2 rounded text-gray-300 text-[11px] max-h-36 overflow-y-auto select-all break-all whitespace-pre-wrap">
                        {result.stego_analysis.lsb_analysis?.rgb_combined?.sample_text || 'No data'}
                      </pre>
                    </div>

                    {/* Red Channel LSB */}
                    <div className="bg-cyber-darker p-3.5 rounded-lg border border-cyber-border space-y-2">
                      <div className="flex items-center justify-between border-b border-cyber-border pb-1.5">
                        <span className="text-red-400 font-bold uppercase">Red Channel LSB</span>
                        <span className="text-gray-500 text-[10px]">Bit 0 (R)</span>
                      </div>
                      <pre className="bg-black/50 p-2 rounded text-gray-300 text-[11px] max-h-36 overflow-y-auto select-all break-all whitespace-pre-wrap">
                        {result.stego_analysis.lsb_analysis?.red_channel?.sample_text || 'No data'}
                      </pre>
                    </div>

                    {/* Green Channel LSB */}
                    <div className="bg-cyber-darker p-3.5 rounded-lg border border-cyber-border space-y-2">
                      <div className="flex items-center justify-between border-b border-cyber-border pb-1.5">
                        <span className="text-green-400 font-bold uppercase">Green Channel LSB</span>
                        <span className="text-gray-500 text-[10px]">Bit 0 (G)</span>
                      </div>
                      <pre className="bg-black/50 p-2 rounded text-gray-300 text-[11px] max-h-36 overflow-y-auto select-all break-all whitespace-pre-wrap">
                        {result.stego_analysis.lsb_analysis?.green_channel?.sample_text || 'No data'}
                      </pre>
                    </div>

                    {/* Blue Channel LSB */}
                    <div className="bg-cyber-darker p-3.5 rounded-lg border border-cyber-border space-y-2">
                      <div className="flex items-center justify-between border-b border-cyber-border pb-1.5">
                        <span className="text-cyan-400 font-bold uppercase">Blue Channel LSB</span>
                        <span className="text-gray-500 text-[10px]">Bit 0 (B)</span>
                      </div>
                      <pre className="bg-black/50 p-2 rounded text-gray-300 text-[11px] max-h-36 overflow-y-auto select-all break-all whitespace-pre-wrap">
                        {result.stego_analysis.lsb_analysis?.blue_channel?.sample_text || 'No data'}
                      </pre>
                    </div>
                  </div>
                </div>
              )}

              {activeTab === 'hexdump' && (
                <div>
                  <pre className="bg-black/70 p-4 rounded-lg font-mono text-xs text-cyber-cyan overflow-x-auto select-all leading-relaxed">
                    {result.file_meta?.hexdump || 'No hexdump available'}
                  </pre>
                </div>
              )}

              {activeTab === 'strings' && (
                <div className="space-y-3">
                  <div className="relative">
                    <input
                      type="text"
                      value={stringFilter}
                      onChange={(e) => setStringFilter(e.target.value)}
                      placeholder="Filter strings (e.g. flag, key, admin, pass, http)..."
                      className="w-full bg-cyber-darker border border-cyber-border rounded-lg pl-9 pr-3 py-2 text-xs font-mono text-white placeholder-gray-500 focus:outline-none focus:border-purple-500/60"
                    />
                    <Search className="w-4 h-4 text-gray-500 absolute left-3 top-2.5" />
                  </div>

                  <div className="max-h-96 overflow-y-auto space-y-1 bg-black/60 p-3 rounded-lg border border-cyber-border">
                    {filteredStrings.length === 0 ? (
                      <p className="text-xs font-mono text-gray-500 text-center py-4">No matching strings</p>
                    ) : (
                      filteredStrings.map((s: string, idx: number) => (
                        <div key={idx} className="font-mono text-xs text-gray-300 hover:text-white select-all py-1 px-1 border-b border-gray-900/40 flex items-center justify-between group rounded hover:bg-white/5">
                          <span className="truncate mr-2">{s}</span>
                          <div className="opacity-0 group-hover:opacity-100 flex items-center gap-1.5 shrink-0 transition-opacity">
                            <button
                              onClick={() => sendToTab('crypto', s)}
                              className="px-1.5 py-0.5 rounded bg-emerald-950/80 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-900 text-[10px] cursor-pointer"
                              title="Send to Crypto / CyberChef"
                            >
                              {'[-> Crypto]'}
                            </button>
                            <button
                              onClick={() => sendToTab('hash', s)}
                              className="px-1.5 py-0.5 rounded bg-yellow-950/80 border border-yellow-500/40 text-yellow-300 hover:bg-yellow-900 text-[10px] cursor-pointer"
                              title="Send to Hash Cracker"
                            >
                              {'[-> Hash]'}
                            </button>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
