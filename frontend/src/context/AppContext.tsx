import React, { createContext, useContext, useState, useEffect } from 'react';
import { playFlagChime } from '../utils/sound';

export interface SavedFlag {
  id: string;
  flag: string;
  source: string;
  timestamp: string;
}

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

export interface PipedPayload {
  targetTab: TabType;
  data: string;
  field?: string;
  timestamp: number;
}

interface AppContextType {
  vault: SavedFlag[];
  addFlags: (flags: string[], source: string) => void;
  removeFlag: (id: string) => void;
  clearVault: () => void;
  soundEnabled: boolean;
  setSoundEnabled: (v: boolean) => void;
  targetFlagPrefix: string;
  setTargetFlagPrefix: (prefix: string) => void;
  chatContext: string;
  setChatContext: (ctx: string) => void;

  // Inter-tool Piping
  currentTab: TabType;
  setCurrentTab: (tab: TabType) => void;
  pipedData: PipedPayload | null;
  sendToTab: (targetTab: TabType, data: string, field?: string) => void;
  clearPipedData: () => void;

  // Tactical CTF Scratchpad
  notesOpen: boolean;
  setNotesOpen: (open: boolean) => void;
}

const AppContext = createContext<AppContextType | undefined>(undefined);

export const AppProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [vault, setVault] = useState<SavedFlag[]>(() => {
    try {
      const saved = localStorage.getItem('shadowsolve_vault');
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  const [soundEnabled, setSoundEnabled] = useState<boolean>(() => {
    const s = localStorage.getItem('shadowsolve_sound');
    return s !== 'false';
  });

  const [targetFlagPrefix, setTargetFlagPrefix] = useState<string>(() => {
    return localStorage.getItem('shadowsolve_flag_prefix') || 'picoCTF{';
  });

  const [chatContext, setChatContext] = useState<string>('');

  useEffect(() => {
    localStorage.setItem('shadowsolve_vault', JSON.stringify(vault));
  }, [vault]);

  useEffect(() => {
    localStorage.setItem('shadowsolve_sound', String(soundEnabled));
  }, [soundEnabled]);

  useEffect(() => {
    localStorage.setItem('shadowsolve_flag_prefix', targetFlagPrefix);
  }, [targetFlagPrefix]);

  const addFlags = (newFlags: string[], source: string) => {
    if (!newFlags || newFlags.length === 0) return;
    
    let addedCount = 0;
    setVault((prev) => {
      const existing = new Set(prev.map((f) => f.flag));
      const toAdd: SavedFlag[] = [];
      
      newFlags.forEach((f) => {
        const clean = f.trim();
        if (clean && !existing.has(clean)) {
          existing.add(clean);
          toAdd.push({
            id: Math.random().toString(36).substring(2, 9),
            flag: clean,
            source,
            timestamp: new Date().toLocaleTimeString(),
          });
          addedCount++;
        }
      });

      return [...toAdd, ...prev];
    });

    if (addedCount > 0 && soundEnabled) {
      playFlagChime();
    }
  };

  const removeFlag = (id: string) => {
    setVault((prev) => prev.filter((f) => f.id !== id));
  };

  const clearVault = () => {
    setVault([]);
  };

  const [currentTab, setCurrentTab] = useState<TabType>('forensics');
  const [pipedData, setPipedData] = useState<PipedPayload | null>(null);
  const [notesOpen, setNotesOpen] = useState<boolean>(false);

  const sendToTab = (targetTab: TabType, data: string, field?: string) => {
    setPipedData({
      targetTab,
      data,
      field,
      timestamp: Date.now()
    });
    setCurrentTab(targetTab);
  };

  const clearPipedData = () => {
    setPipedData(null);
  };

  return (
    <AppContext.Provider
      value={{
        vault,
        addFlags,
        removeFlag,
        clearVault,
        soundEnabled,
        setSoundEnabled,
        targetFlagPrefix,
        setTargetFlagPrefix,
        chatContext,
        setChatContext,
        currentTab,
        setCurrentTab,
        pipedData,
        sendToTab,
        clearPipedData,
        notesOpen,
        setNotesOpen,
      }}
    >
      {children}
    </AppContext.Provider>
  );
};

export const useApp = () => {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('useApp must be used within AppProvider');
  return ctx;
};
