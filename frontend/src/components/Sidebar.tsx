import React from 'react';
import { 
  FileSearch, 
  KeyRound, 
  Binary, 
  Hash, 
  Globe, 
  Terminal, 
  Cpu, 
  BookOpen, 
  MessageSquare,
  Flag,
  FileCode2,
  Ticket,
  Flame,
  ChevronRight
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import { Logo } from './Logo';

export type TabType = 
  | 'forensics' 
  | 'crypto' 
  | 'rsa' 
  | 'hash' 
  | 'web' 
  | 'jwt' 
  | 'binary' 
  | 'payloads' 
  | 'netcat' 
  | 'classify' 
  | 'writeup' 
  | 'chat';

interface SidebarProps {
  currentTab: TabType;
  onSelectTab: (tab: TabType) => void;
  onOpenVault: () => void;
}

interface NavSection {
  title: string;
  items: {
    id: TabType;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
  }[];
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onSelectTab, onOpenVault }) => {
  const { vault } = useApp();

  const sections: NavSection[] = [
    {
      title: 'Offensive Security',
      items: [
        { id: 'payloads', label: 'Payloads & RevShells', icon: Flame },
        { id: 'web', label: 'Web Vulnerabilities', icon: Globe },
        { id: 'jwt', label: 'JWT Token Security', icon: Ticket },
        { id: 'binary', label: 'Binary Checksec & Pwn', icon: FileCode2 },
        { id: 'netcat', label: 'TCP Netcat Solver', icon: Terminal },
      ],
    },
    {
      title: 'Digital Forensics & Crypto',
      items: [
        { id: 'forensics', label: 'Artifact Forensics', icon: FileSearch },
        { id: 'crypto', label: 'Cryptanalysis & Decoder', icon: KeyRound },
        { id: 'rsa', label: 'RSA Mathematical Attacks', icon: Binary },
        { id: 'hash', label: 'Hash Identification', icon: Hash },
      ],
    },
    {
      title: 'Intelligence & Machine Learning',
      items: [
        { id: 'chat', label: 'Security AI Advisor', icon: MessageSquare },
        { id: 'classify', label: 'ML Challenge Classifier', icon: Cpu },
        { id: 'writeup', label: 'Knowledge Base Search', icon: BookOpen },
      ],
    },
  ];

  return (
    <aside className="w-64 bg-[#0a0f18] border-r border-slate-800 flex flex-col h-screen shrink-0 z-40 select-none">
      {/* Brand Header */}
      <div className="p-4 border-b border-slate-800 bg-[#070b12]">
        <Logo size="md" />
      </div>

      {/* Nav Menu */}
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-5 text-xs">
        {sections.map((section, sIdx) => (
          <div key={sIdx} className="space-y-1">
            <div className="px-2 pb-1.5 text-[11px] font-sans font-semibold uppercase tracking-wider text-slate-500">
              {section.title}
            </div>
            {section.items.map((item) => {
              const Icon = item.icon;
              const isActive = currentTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onSelectTab(item.id)}
                  className={`w-full flex items-center justify-between px-2.5 py-2 rounded-md font-sans text-xs transition-colors ${
                    isActive
                      ? 'bg-slate-800/90 text-white font-medium border-l-2 border-emerald-500 pl-2'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                  }`}
                >
                  <div className="flex items-center gap-2.5 truncate">
                    <Icon className={`w-4 h-4 ${isActive ? 'text-emerald-400' : 'text-slate-400'}`} />
                    <span className="truncate">{item.label}</span>
                  </div>
                  {isActive && <ChevronRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />}
                </button>
              );
            })}
          </div>
        ))}
      </nav>

      {/* Flag Vault Summary */}
      <div className="p-3 border-t border-slate-800 bg-[#070b12]">
        <button
          onClick={onOpenVault}
          className="w-full flex items-center justify-between px-3 py-2 rounded-md bg-slate-900 hover:bg-slate-800/80 border border-slate-800 transition-colors font-sans text-xs text-slate-300"
        >
          <div className="flex items-center gap-2">
            <Flag className="w-3.5 h-3.5 text-emerald-400" />
            <span className="font-medium text-slate-200">Flag Vault</span>
          </div>
          <span className="bg-emerald-950/80 text-emerald-400 border border-emerald-800/60 font-mono font-semibold px-2 py-0.5 rounded text-[11px]">
            {vault.length}
          </span>
        </button>
      </div>

      {/* Engine Status */}
      <div className="px-4 py-2.5 border-t border-slate-800 bg-[#05080f] text-[11px] font-mono text-slate-500 flex justify-between items-center">
        <span>Engine v1.2.0</span>
        <span className="flex items-center gap-1.5 text-slate-400 font-sans">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
          Ready
        </span>
      </div>
    </aside>
  );
};
