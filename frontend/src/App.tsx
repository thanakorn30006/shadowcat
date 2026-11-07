import React, { useState, useEffect } from 'react';
import { AppProvider, useApp, TabType } from './context/AppContext';
import { Sidebar } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { FlagVaultModal } from './components/FlagVaultModal';
import { QuickConverterModal } from './components/QuickConverterModal';
import { NotesDrawer } from './components/NotesDrawer';
import { Forensics } from './pages/Forensics';
import { Crypto } from './pages/Crypto';
import { RSA } from './pages/RSA';
import { HashCrack } from './pages/HashCrack';
import { WebHunt } from './pages/WebHunt';
import { JWTStudio } from './pages/JWTStudio';
import { BinaryPwn } from './pages/BinaryPwn';
import { PayloadHub } from './pages/PayloadHub';
import { Netcat } from './pages/Netcat';
import { Classify } from './pages/Classify';
import { Writeups } from './pages/Writeups';
import { Chat } from './pages/Chat';

function MainLayout() {
  const { currentTab, setCurrentTab, notesOpen, setNotesOpen } = useApp();
  const [vaultOpen, setVaultOpen] = useState(false);
  const [converterOpen, setConverterOpen] = useState(false);

  // Lazy-mount & Keep-Alive visited tabs to preserve in-progress operations
  const [mountedTabs, setMountedTabs] = useState<Set<TabType>>(() => new Set([currentTab]));

  useEffect(() => {
    setMountedTabs(prev => {
      if (prev.has(currentTab)) return prev;
      const next = new Set(prev);
      next.add(currentTab);
      return next;
    });
  }, [currentTab]);

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-cyber-darker text-gray-200">
      {/* Navigation Sidebar */}
      <Sidebar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        onOpenVault={() => setVaultOpen(true)}
      />

      {/* Main Container */}
      <div className="flex-1 flex flex-col h-screen overflow-hidden">
        {/* Top Navbar */}
        <TopBar
          onOpenVault={() => setVaultOpen(true)}
          onOpenConverter={() => setConverterOpen(true)}
        />

        {/* Workspace Canvas with Keep-Alive Tabs */}
        <main className="flex-1 overflow-y-auto p-6 bg-[#090d16]">
          {mountedTabs.has('forensics') && (
            <div className={currentTab === 'forensics' ? 'block' : 'hidden'}>
              <Forensics onNavigateToChat={() => setCurrentTab('chat')} />
            </div>
          )}
          {mountedTabs.has('crypto') && (
            <div className={currentTab === 'crypto' ? 'block' : 'hidden'}>
              <Crypto />
            </div>
          )}
          {mountedTabs.has('rsa') && (
            <div className={currentTab === 'rsa' ? 'block' : 'hidden'}>
              <RSA />
            </div>
          )}
          {mountedTabs.has('hash') && (
            <div className={currentTab === 'hash' ? 'block' : 'hidden'}>
              <HashCrack />
            </div>
          )}
          {mountedTabs.has('web') && (
            <div className={currentTab === 'web' ? 'block' : 'hidden'}>
              <WebHunt />
            </div>
          )}
          {mountedTabs.has('jwt') && (
            <div className={currentTab === 'jwt' ? 'block' : 'hidden'}>
              <JWTStudio />
            </div>
          )}
          {mountedTabs.has('binary') && (
            <div className={currentTab === 'binary' ? 'block' : 'hidden'}>
              <BinaryPwn />
            </div>
          )}
          {mountedTabs.has('payloads') && (
            <div className={currentTab === 'payloads' ? 'block' : 'hidden'}>
              <PayloadHub />
            </div>
          )}
          {mountedTabs.has('netcat') && (
            <div className={currentTab === 'netcat' ? 'block' : 'hidden'}>
              <Netcat />
            </div>
          )}
          {mountedTabs.has('classify') && (
            <div className={currentTab === 'classify' ? 'block' : 'hidden'}>
              <Classify />
            </div>
          )}
          {mountedTabs.has('writeup') && (
            <div className={currentTab === 'writeup' ? 'block' : 'hidden'}>
              <Writeups />
            </div>
          )}
          {mountedTabs.has('chat') && (
            <div className={currentTab === 'chat' ? 'block' : 'hidden'}>
              <Chat />
            </div>
          )}
        </main>
      </div>

      {/* Flag Vault Dialog */}
      <FlagVaultModal isOpen={vaultOpen} onClose={() => setVaultOpen(false)} />

      {/* Quick Scratchpad Dialog */}
      <QuickConverterModal isOpen={converterOpen} onClose={() => setConverterOpen(false)} />

      {/* Tactical CTF Notes Drawer */}
      <NotesDrawer isOpen={notesOpen} onClose={() => setNotesOpen(false)} />
    </div>
  );
}

export function App() {
  return (
    <AppProvider>
      <MainLayout />
    </AppProvider>
  );
}
export default App;
