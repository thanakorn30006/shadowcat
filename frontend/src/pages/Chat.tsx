import React, { useState, useRef, useEffect } from 'react';
import { MessageSquare, Send, RefreshCw, Bot, User, Trash2, FileText, X } from 'lucide-react';
import { sendChatMessage } from '../api/client';
import { useApp } from '../context/AppContext';

interface Message {
  role: 'user' | 'assistant';
  content: string;
}

export const Chat: React.FC = () => {
  const { chatContext, setChatContext } = useApp();

  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content: "[ONLINE] **SHADOW CAT AI Advisor Online**.\nReady to tackle any CTF problem (Forensics, Crypto, Web, Pwn, Rev, Misc).\nPaste any challenge prompt, code, disassembled snippet, or payload to start!"
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading]);

  const handleSend = async () => {
    if (!input.trim() || loading) return;

    const userMessage: Message = { role: 'user', content: input.trim() };
    const newMessages = [...messages, userMessage];
    setMessages(newMessages);
    setInput('');
    setLoading(true);

    try {
      const data = await sendChatMessage(newMessages, chatContext || undefined);
      setMessages([...newMessages, { role: 'assistant', content: data.reply || 'No response.' }]);
    } catch (err: any) {
      setMessages([
        ...newMessages,
        { role: 'assistant', content: `[!] Error contacting AI: ${err.message}` }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setMessages([
      {
        role: 'assistant',
        content: "Chat history cleared. What challenge are we hacking now?"
      }
    ]);
  };

  const quickPrompts = [
    "How to analyze a PCAP file in Wireshark for credentials?",
    "Give me common SQLite authentication bypass payloads",
    "Explain how to exploit e=3 RSA low public exponent",
    "How does LSB steganography work in PNG files?"
  ];

  return (
    <div className="max-w-5xl mx-auto flex flex-col h-[calc(100vh-8.5rem)]">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-800 shrink-0">
        <div>
          <h2 className="text-xl font-semibold font-sans text-slate-100 flex items-center gap-2">
            <MessageSquare className="w-5 h-5 text-emerald-400" />
            Security Copilot & Technical Advisor
          </h2>
          <p className="text-slate-400 text-xs font-sans mt-0.5">
            Automated multi-provider AI copilot (Gemini / PSU AI) configured with offensive and defensive security engineering guidelines.
          </p>
        </div>
        <button
          onClick={handleClear}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-slate-800 hover:bg-slate-800 text-slate-400 hover:text-slate-200 text-xs font-sans transition-colors"
        >
          <Trash2 className="w-3.5 h-3.5" />
          Clear Session
        </button>
      </div>

      {/* Active Context Banner */}
      {chatContext && (
        <div className="mt-3 p-3 rounded-lg bg-purple-950/40 border border-purple-500/40 flex items-center justify-between text-xs font-mono text-purple-200 shrink-0">
          <div className="flex items-center gap-2 truncate mr-2">
            <FileText className="w-4 h-4 text-purple-400 shrink-0" />
            <span className="font-bold text-purple-300">Active Challenge Context Attached:</span>
            <span className="text-gray-400 truncate">{chatContext.replace(/\n/g, ' ')}</span>
          </div>
          <button
            onClick={() => setChatContext('')}
            className="p-1 hover:text-white transition-colors"
            title="Detach context"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Message List */}
      <div className="flex-1 overflow-y-auto py-4 space-y-4 pr-2">
        {messages.map((m, idx) => (
          <div
            key={idx}
            className={`flex gap-3 ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}
          >
            {m.role === 'assistant' && (
              <div className="w-8 h-8 rounded-lg bg-cyber-green/10 border border-cyber-green/30 flex items-center justify-center text-cyber-green shrink-0 mt-1">
                <Bot className="w-4 h-4" />
              </div>
            )}

            <div
              className={`max-w-3xl rounded-xl p-4 font-mono text-xs leading-relaxed ${
                m.role === 'user'
                  ? 'bg-cyber-card border border-cyber-cyan/30 text-white'
                  : 'bg-cyber-darker border border-cyber-border text-gray-200'
              }`}
            >
              <div className="whitespace-pre-wrap select-all">{m.content}</div>
            </div>

            {m.role === 'user' && (
              <div className="w-8 h-8 rounded-lg bg-cyber-cyan/10 border border-cyber-cyan/30 flex items-center justify-center text-cyber-cyan shrink-0 mt-1">
                <User className="w-4 h-4" />
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex gap-3 justify-start">
            <div className="w-8 h-8 rounded-lg bg-cyber-green/10 border border-cyber-green/30 flex items-center justify-center text-cyber-green shrink-0 mt-1">
              <Bot className="w-4 h-4" />
            </div>
            <div className="bg-cyber-darker border border-cyber-border rounded-xl p-4 flex items-center gap-2 text-cyber-green font-mono text-xs">
              <RefreshCw className="w-4 h-4 animate-spin" />
              SHADOW CAT AI is calculating tactics & exploit vectors...
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Quick Prompts */}
      <div className="pt-2 pb-3 flex gap-2 overflow-x-auto shrink-0">
        {quickPrompts.map((p, idx) => (
          <button
            key={idx}
            onClick={() => setInput(p)}
            className="text-[11px] font-mono px-2.5 py-1 rounded bg-cyber-dark border border-cyber-border hover:border-cyber-green/40 text-gray-400 hover:text-white shrink-0 transition-colors"
          >
            {p}
          </button>
        ))}
      </div>

      {/* Input Form */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-3 flex items-center gap-3 shrink-0">
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              handleSend();
            }
          }}
          placeholder="Ask tactical question or paste challenge script... (Enter to send)"
          rows={1}
          className="flex-1 bg-transparent text-xs font-mono text-white placeholder-gray-500 focus:outline-none resize-none"
        />
        <button
          onClick={handleSend}
          disabled={loading || !input.trim()}
          className="p-2.5 rounded-lg bg-cyber-green text-black font-semibold hover:bg-cyber-green/90 disabled:opacity-50 transition-all shrink-0"
        >
          <Send className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
};
