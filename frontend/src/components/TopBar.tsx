import React, { useState, useEffect } from 'react';
import { 
  Flag, 
  Timer, 
  Play, 
  Pause, 
  RotateCcw, 
  FileTerminal, 
  Volume2, 
  VolumeX, 
  BookOpen,
  ShieldCheck,
  FileText
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import { getLicenseStatus } from '../api/client';
import { LicenseModal } from './LicenseModal';

interface TopBarProps {
  onOpenVault: () => void;
  onOpenConverter: () => void;
}

export const TopBar: React.FC<TopBarProps> = ({ onOpenVault, onOpenConverter }) => {
  const { vault, soundEnabled, setSoundEnabled, targetFlagPrefix, setTargetFlagPrefix, setNotesOpen } = useApp();
  
  const [seconds, setSeconds] = useState<number>(0);
  const [timerRunning, setTimerRunning] = useState<boolean>(false);
  const [licenseInfo, setLicenseInfo] = useState<any>(null);
  const [isLicenseOpen, setIsLicenseOpen] = useState<boolean>(false);

  const fetchLicense = async () => {
    try {
      const data = await getLicenseStatus();
      setLicenseInfo(data);
    } catch {
      // fallback
    }
  };

  useEffect(() => {
    fetchLicense();
  }, []);

  useEffect(() => {
    let interval: any = null;
    if (timerRunning) {
      interval = setInterval(() => {
        setSeconds((s) => s + 1);
      }, 1000);
    } else {
      clearInterval(interval);
    }
    return () => clearInterval(interval);
  }, [timerRunning]);

  const formatTime = (totalSec: number) => {
    const hrs = Math.floor(totalSec / 3600);
    const mins = Math.floor((totalSec % 3600) / 60);
    const secs = totalSec % 60;
    return `${hrs.toString().padStart(2, '0')}:${mins
      .toString()
      .padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  return (
    <header className="h-14 border-b border-slate-800 bg-[#080c14] px-5 flex items-center justify-between shrink-0 z-30 select-none">
      {/* Left: Service Status & Target Flag Filter */}
      <div className="flex items-center gap-4">
        {/* Service status indicator */}
        <div className="flex items-center gap-2 text-xs font-sans text-slate-400">
          <span className="w-2 h-2 rounded-full bg-emerald-500" />
          <span>Local Engine (127.0.0.1:8000)</span>
        </div>

        <div className="h-4 w-px bg-slate-800" />

        {/* Flag Format Setting */}
        <div className="flex items-center gap-2 text-xs font-sans">
          <span className="text-slate-400">Flag Pattern:</span>
          <input
            type="text"
            value={targetFlagPrefix}
            onChange={(e) => setTargetFlagPrefix(e.target.value)}
            placeholder="e.g. TNCW{ or picoCTF{"
            className="bg-slate-900 border border-slate-700/80 focus:border-emerald-500 rounded px-2 py-1 text-slate-200 font-mono text-xs w-36 outline-none transition-colors"
            title="Set target flag prefix to automatically highlight matching flags"
          />
        </div>
      </div>

      {/* Right: Timer & Utilities */}
      <div className="flex items-center gap-3">
        {/* Stopwatch */}
        <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-xs">
          <Timer className="w-3.5 h-3.5 text-slate-400" />
          <span className="text-slate-200 font-mono font-medium">{formatTime(seconds)}</span>
          <button
            onClick={() => setTimerRunning(!timerRunning)}
            className="text-slate-400 hover:text-slate-200 transition-colors p-0.5"
            title={timerRunning ? "Pause" : "Start"}
          >
            {timerRunning ? <Pause className="w-3.5 h-3.5 text-amber-400" /> : <Play className="w-3.5 h-3.5 text-emerald-400" />}
          </button>
          <button
            onClick={() => {
              setTimerRunning(false);
              setSeconds(0);
            }}
            className="text-slate-500 hover:text-slate-300 transition-colors p-0.5"
            title="Reset"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Tactical CTF Notes Drawer Button */}
        <button
          onClick={() => setNotesOpen(true)}
          className="flex items-center gap-1.5 px-3 py-1 rounded bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-300 text-xs font-sans transition-colors cursor-pointer"
          title="Open Tactical CTF Challenge Scratchpad"
        >
          <FileText className="w-3.5 h-3.5 text-yellow-400" />
          <span>CTF Notes</span>
        </button>

        {/* Scratchpad & Log Parser */}
        <button
          onClick={onOpenConverter}
          className="flex items-center gap-1.5 px-3 py-1 rounded bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-300 text-xs font-sans transition-colors"
        >
          <FileTerminal className="w-3.5 h-3.5 text-slate-400" />
          <span>Scratchpad & IOCs</span>
        </button>

        {/* Docs Link */}
        <a
          href="https://thanakorn30006.github.io/docs.html"
          target="_blank"
          rel="noreferrer"
          className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-300 text-xs font-sans transition-colors"
          title="Open SHADOW CAT Technical Documentation Center"
        >
          <BookOpen className="w-3.5 h-3.5 text-slate-400" />
          <span>Docs</span>
        </a>

        {/* Audio notification toggle */}
        <button
          onClick={() => setSoundEnabled(!soundEnabled)}
          className="p-1.5 rounded border border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 transition-colors"
          title={soundEnabled ? "Mute notification chimes" : "Enable notification chimes"}
        >
          {soundEnabled ? <Volume2 className="w-3.5 h-3.5 text-slate-300" /> : <VolumeX className="w-3.5 h-3.5 text-slate-500" />}
        </button>

        {/* Flag Vault Launcher */}
        <button
          onClick={onOpenVault}
          className="flex items-center gap-2 px-3 py-1 rounded bg-emerald-950/40 border border-emerald-800/60 hover:bg-emerald-900/30 text-emerald-400 text-xs font-sans transition-colors"
        >
          <Flag className="w-3.5 h-3.5" />
          <span>Flags ({vault.length})</span>
        </button>

        <div className="h-4 w-px bg-slate-800" />

        {/* License Badge */}
        <button
          onClick={() => setIsLicenseOpen(true)}
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded font-mono text-[11px] font-semibold transition-colors ${
            licenseInfo?.tier === 'PRO_OPERATOR'
              ? 'bg-emerald-950/60 border border-emerald-700/60 text-emerald-400 hover:bg-emerald-900/40'
              : 'bg-slate-900 border border-slate-700/80 text-slate-300 hover:bg-slate-800'
          }`}
          title="Click to view air-gap license status or inject key"
        >
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>{licenseInfo?.tier === 'PRO_OPERATOR' ? 'PRO OPERATOR' : 'COMMUNITY'}</span>
        </button>
      </div>

      <LicenseModal
        isOpen={isLicenseOpen}
        onClose={() => setIsLicenseOpen(false)}
        licenseInfo={licenseInfo}
        onRefresh={fetchLicense}
      />
    </header>
  );
};
