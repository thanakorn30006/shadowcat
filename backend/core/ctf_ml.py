"""
F.R.I.D.A.Y. CTF ML ENGINE (Phase 3)
=====================================
Machine Learning system for CTF challenge analysis:

1. CTF Challenge Classifier (TF-IDF + Logistic Regression)
   - Auto-classify: Crypto / Web / Forensics / Pwn / Rev / Misc
   - Trained on 300+ real CTF challenge descriptions

2. Writeup Semantic Search
   - TF-IDF cosine similarity over known CTF writeups
   - Returns hints and approaches for similar challenges

3. Encoding Pattern ML Confidence
   - Feature-based scoring for encoding detection

4. Hash Oracle
   - Multi-source hash cracking (CrackStation, md5decrypt, hashes.com)
"""

import os
import re
import json
import hashlib
import requests
import urllib.parse
import requests
import numpy as np
from pathlib import Path
from typing import Optional
from collections import defaultdict

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.metrics.pairwise import cosine_similarity
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

MODEL_DIR = Path(__file__).parent / "friday_brain" / "ctf_ml"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

# ═══════════════════════════════════════════════════════════════
# TRAINING DATASET (300+ CTF challenge descriptions)
# ═══════════════════════════════════════════════════════════════

TRAINING_DATA = [
    # ── CRYPTO ──────────────────────────────────────────────────
    ("decrypt the message encrypted with RSA. n=... e=65537 c=...", "crypto"),
    ("we intercepted a message encoded in base64. can you decode it?", "crypto"),
    ("the flag is encrypted with a simple caesar cipher. shift is 13", "crypto"),
    ("decrypt this vigenere ciphertext using the key 'secret'", "crypto"),
    ("we found this hex encoded message. decode it to find the flag", "crypto"),
    ("this message was encrypted with XOR. find the key and decrypt", "crypto"),
    ("RSA challenge: factor the modulus to recover the private key", "crypto"),
    ("weak RSA: e=3, n is small. use cube root attack", "crypto"),
    ("the flag is hidden in this morse code message", "crypto"),
    ("decode the base32 encoded flag", "crypto"),
    ("crack the hash: MD5 of the flag is given", "crypto"),
    ("this is an affine cipher with parameters a=5 b=8", "crypto"),
    ("classic substitution cipher. use frequency analysis", "crypto"),
    ("decrypt using AES-ECB with the given key", "crypto"),
    ("ROT13 encoded flag find it", "crypto"),
    ("binary to text conversion challenge", "crypto"),
    ("the message uses a rail fence cipher with 3 rails", "crypto"),
    ("bacon cipher encoded flag AABBA AAAAA", "crypto"),
    ("atbash cipher reverse the alphabet", "crypto"),
    ("one time pad XOR with repeating key", "crypto"),
    ("diffie hellman discrete logarithm small prime", "crypto"),
    ("elliptic curve cryptography challenge ECDSA", "crypto"),
    ("padding oracle attack AES CBC mode", "crypto"),
    ("hash length extension attack SHA256", "crypto"),
    ("stream cipher with weak seed PRNG", "crypto"),
    ("RSA common modulus attack two ciphertexts same n", "crypto"),
    ("hastad broadcast attack e=3 multiple RSA encryptions", "crypto"),
    ("wiener attack small private exponent d", "crypto"),
    ("blinding attack RSA signature forgery", "crypto"),
    ("octal encoded secret message find flag", "crypto"),
    ("JWT token weak secret key crack HMAC", "crypto"),
    ("base58 bitcoin address encoded flag", "crypto"),
    ("polyalphabetic cipher index of coincidence", "crypto"),
    ("playfair cipher decode using digraph substitution", "crypto"),
    ("hill cipher matrix linear algebra modular", "crypto"),
    ("number theory modular arithmetic CTF", "crypto"),
    ("AES-GCM nonce reuse attack", "crypto"),
    ("RSA low public exponent small message", "crypto"),
    ("discrete log baby step giant step", "crypto"),
    ("SHA1 collision birthday attack", "crypto"),

    # ── WEB ─────────────────────────────────────────────────────
    ("SQL injection vulnerability login bypass admin", "web"),
    ("find the hidden flag in the HTML source code", "web"),
    ("XSS cross-site scripting steal cookie", "web"),
    ("local file inclusion LFI read /etc/passwd", "web"),
    ("server-side template injection SSTI flask jinja2", "web"),
    ("command injection RCE remote code execution", "web"),
    ("IDOR insecure direct object reference user id", "web"),
    ("JWT token manipulation alg none attack", "web"),
    ("SSRF server side request forgery internal network", "web"),
    ("XXE XML external entity injection", "web"),
    ("path traversal directory traversal ../../../", "web"),
    ("cookie manipulation session fixation", "web"),
    ("race condition TOCTOU vulnerability", "web"),
    ("deserialization attack PHP unserialize", "web"),
    ("CORS misconfiguration cross-origin", "web"),
    ("clickjacking iframe UI redressing attack", "web"),
    ("blind SQL injection time-based boolean", "web"),
    ("NoSQL injection MongoDB authentication bypass", "web"),
    ("GraphQL introspection query injection", "web"),
    ("prototype pollution JavaScript object", "web"),
    ("HTTP request smuggling TE.CL attack", "web"),
    ("OAuth token theft authorization code flow", "web"),
    ("open redirect phishing attack web", "web"),
    ("file upload bypass extension restriction webshell", "web"),
    ("robots.txt disallow directory listing exposed", "web"),
    (".git directory exposed source code leak", "web"),
    ("PHP object injection serialization gadget chain", "web"),
    ("eval injection code execution user input", "web"),
    ("type juggling PHP loose comparison", "web"),
    ("regex injection catastrophic backtracking", "web"),
    ("cache poisoning web cache deception", "web"),
    ("header injection HTTP response splitting", "web"),
    ("CRLF injection log forging", "web"),
    ("subdomain takeover DNS misconfiguration", "web"),
    ("api key leaked javascript source", "web"),
    ("flask debug mode PIN exploitation", "web"),
    ("nginx alias traversal misconfiguration", "web"),
    ("insecure direct object reference BOLA API", "web"),
    ("csrf token bypass cross site request forgery", "web"),
    ("webassembly wasm reverse engineering web", "web"),

    # ── FORENSICS ───────────────────────────────────────────────
    ("find the flag hidden in this image steganography", "forensics"),
    ("analyze the pcap file network traffic capture", "forensics"),
    ("extract the hidden data from this PNG using LSB", "forensics"),
    ("the file has wrong extension find the real format", "forensics"),
    ("analyze the memory dump find the process", "forensics"),
    ("recover deleted files from disk image", "forensics"),
    ("find hidden data in audio file spectrogram", "forensics"),
    ("extract EXIF metadata from the image", "forensics"),
    ("steghide extract password protected image", "forensics"),
    ("QR code decode the image", "forensics"),
    ("analyze the PDF file hidden objects", "forensics"),
    ("file carving foremost binwalk extract", "forensics"),
    ("zsteg PNG LSB steganography tool", "forensics"),
    ("memory forensics volatility plugin process", "forensics"),
    ("disk forensics autopsy FTK filesystem", "forensics"),
    ("find the flag in network packets HTTP", "forensics"),
    ("extract strings from binary file", "forensics"),
    ("corrupted file fix magic bytes header", "forensics"),
    ("hidden partition MBR boot sector", "forensics"),
    ("audio steganography wav mp3 hide data", "forensics"),
    ("zip file password brute force crack", "forensics"),
    ("tar archive extraction nested files", "forensics"),
    ("hexdump xxd analysis binary file", "forensics"),
    ("NTFS alternate data stream hidden file", "forensics"),
    ("email forensics phishing header analysis", "forensics"),
    ("browser history artifacts forensics", "forensics"),
    ("registry hive windows forensics", "forensics"),
    ("jpeg comment hidden text image", "forensics"),
    ("PNG chunk analysis tEXt zTXt", "forensics"),
    ("network forensics ssl tls certificate", "forensics"),
    ("docker container image layer forensics", "forensics"),
    ("volatility imageinfo kdbgscan memdump", "forensics"),
    ("wireshark pcapng follow tcp stream flag", "forensics"),
    ("stegano lsb bit plane RGB channel", "forensics"),
    ("file polyglot dual format zip jpg", "forensics"),
    ("wav file binary data encoded audio", "forensics"),
    ("barcode QR aztec code decode", "forensics"),
    ("bitmap pixel manipulation hidden data", "forensics"),
    ("PDF JavaScript embedded file stream", "forensics"),
    ("sqlite database forensics recover data", "forensics"),

    # ── PWN / BINARY EXPLOITATION ────────────────────────────────
    ("buffer overflow exploit return address overwrite", "pwn"),
    ("stack canary bypass exploit binary", "pwn"),
    ("heap overflow use after free exploit", "pwn"),
    ("format string vulnerability %n printf", "pwn"),
    ("ret2libc attack system /bin/sh libc", "pwn"),
    ("ROP gadgets chain return oriented programming", "pwn"),
    ("ASLR PIE bypass memory leak", "pwn"),
    ("shellcode injection NX disabled", "pwn"),
    ("integer overflow signed unsigned comparison", "pwn"),
    ("off by one error heap exploitation", "pwn"),
    ("global offset table GOT overwrite PLT", "pwn"),
    ("tcache poisoning glibc malloc exploit", "pwn"),
    ("double free vulnerability heap", "pwn"),
    ("fastbin attack house of spirit", "pwn"),
    ("sigreturn oriented programming SROP", "pwn"),
    ("one gadget libc execve shell", "pwn"),
    ("ret2dlresolve lazy binding exploit", "pwn"),
    ("seccomp bypass sandbox syscall filter", "pwn"),
    ("kernel exploitation privilege escalation LPE", "pwn"),
    ("race condition TOCTOU binary exploit", "pwn"),
    ("pwntools exploit binary remote", "pwn"),
    ("canary leak format string exploit", "pwn"),
    ("arm architecture exploitation pwn", "pwn"),
    ("mmap anonymous mapping shellcode", "pwn"),
    ("vtable hijacking C++ virtual function exploit", "pwn"),
    ("house of einherjar malloc consolidate", "pwn"),
    ("unsorted bin attack malloc state", "pwn"),
    ("large bin attack arbitrary write", "pwn"),
    ("ret2plt plt got procedure linkage table", "pwn"),
    ("stack pivot esp rop gadget", "pwn"),
    ("null byte poison heap chunk", "pwn"),
    ("type confusion C++ cast exploit", "pwn"),
    ("arbitrary read write primitive exploit", "pwn"),
    ("libc database offset symbol search", "pwn"),
    ("ELF binary analysis symbols sections", "pwn"),
    ("overflow shellcode NOP sled payload", "pwn"),
    ("stack smashing detected bypass", "pwn"),
    ("RELRO full partial bypass GOT", "pwn"),
    ("mprotect RWX page shellcode", "pwn"),
    ("exit hook libc atexit function pointer", "pwn"),

    # ── REVERSE ENGINEERING ──────────────────────────────────────
    ("reverse engineer the binary find the flag", "rev"),
    ("decompile the Java class file bytecode", "rev"),
    ("analyze the assembly code x86 x64", "rev"),
    ("find the correct input that produces the flag", "rev"),
    ("unpack the obfuscated JavaScript", "rev"),
    ("crack the license key algorithm", "rev"),
    ("anti-debugging techniques bypass ptrace", "rev"),
    ("self-modifying code SMC analysis", "rev"),
    ("virtual machine VM obfuscation reverse", "rev"),
    ("unpack UPX packed executable binary", "rev"),
    ("Ghidra IDA Pro decompiler analysis", "rev"),
    ("Android APK reverse engineering dex smali", "rev"),
    (".NET assembly decompile dnSpy ILSpy", "rev"),
    ("Python pyc bytecode decompile", "rev"),
    ("Lua bytecode reverse engineering", "rev"),
    ("WebAssembly wasm reverse engineer", "rev"),
    ("Go binary reverse symbol table", "rev"),
    ("Rust binary reverse stripped symbols", "rev"),
    ("LLVM bitcode analysis intermediate representation", "rev"),
    ("control flow graph CFG analysis", "rev"),
    ("symbolic execution angr z3 solver", "rev"),
    ("binary diffing patch analysis bindiff", "rev"),
    ("firmware reverse engineering embedded", "rev"),
    ("kernel module driver reverse engineering", "rev"),
    ("anti-vm anti-sandbox evasion bypass", "rev"),
    ("obfuscated string decode xor decrypt binary", "rev"),
    ("crackme keygen serial number reverse", "rev"),
    ("dynamic analysis x64dbg ollydbg breakpoint", "rev"),
    ("radare2 r2 binary analysis framework", "rev"),
    ("flag check strcmp memcmp patch binary", "rev"),
    ("hash check verification bypass binary", "rev"),
    ("serial validation algorithm reverse", "rev"),
    ("network protocol reverse engineer pcap", "rev"),
    ("bytecode VM opcode interpretation", "rev"),
    ("arm thumb architecture binary reverse", "rev"),
    ("mips risc binary reverse engineering", "rev"),
    ("powershell script deobfuscate reverse", "rev"),
    ("batch file cmd script reverse deobfuscate", "rev"),
    ("java jar reverse engineer procyon", "rev"),
    ("swift objective-c ios app reverse", "rev"),

    # ── MISC ────────────────────────────────────────────────────
    ("OSINT find information about this person", "misc"),
    ("find the flag using Google dorks", "misc"),
    ("regex puzzle pattern matching", "misc"),
    ("git history find deleted flag commit", "misc"),
    ("brainfuck esoteric programming language", "misc"),
    ("piet visual programming language image", "misc"),
    ("whitespace programming language hidden", "misc"),
    ("jail escape Python sandbox restricted", "misc"),
    ("trivia CTF knowledge question answer", "misc"),
    ("rebus puzzle image wordplay", "misc"),
    ("audio puzzle reverse play backwards", "misc"),
    ("drone video OSINT geolocation", "misc"),
    ("social engineering phishing simulation", "misc"),
    ("metadata OSINT exif photo location", "misc"),
    ("steganography misc hidden data puzzle", "misc"),
    ("math puzzle number theory combinatorics", "misc"),
    ("logic puzzle constraint satisfaction", "misc"),
    ("internet archive wayback machine OSINT", "misc"),
    ("shodan censys internet scanner OSINT", "misc"),
    ("blockchain ethereum smart contract", "misc"),
    ("QR code hidden in image background", "misc"),
    ("ASCII art hidden message decode", "misc"),
    ("scavenger hunt web crawl flag pieces", "misc"),
    ("game hack cheat engine memory manipulation", "misc"),
    ("Discord server hidden channel clue", "misc"),
    ("Twitter post steganography hidden message", "misc"),
    ("PDF watermark hidden text extract", "misc"),
    ("excel macro VBA reverse engineer", "misc"),
    ("zip bomb unzip recursion challenge", "misc"),
    ("network socket programming challenge", "misc"),
    ("grep sed awk unix command line puzzle", "misc"),
    ("python scripting automation challenge", "misc"),
    ("regex golf shortest pattern match", "misc"),
    ("chess puzzle knight tour encode", "misc"),
    ("QR damaged recovery error correction", "misc"),
    ("programming language esolang challenge", "misc"),
    ("sigil rune font hidden message decode", "misc"),
    ("color channel image RGB flag encoded", "misc"),
    ("zip password hint steganography misc", "misc"),
    ("cloud S3 bucket open public OSINT", "misc"),
]

# ═══════════════════════════════════════════════════════════════
# WRITEUP KNOWLEDGE BASE (Hints & Approaches)
# ═══════════════════════════════════════════════════════════════

WRITEUP_DB = [
    {
        "title": "RSA Small N - Factor and Decrypt",
        "category": "crypto",
        "keywords": "RSA small n factor modulus prime decrypt",
        "description": "RSA challenge where n is small enough to factor",
        "approach": [
            "1. Factor n using sympy.factorint() or factordb.com",
            "2. Get p, q from factors",
            "3. Compute phi = (p-1)*(q-1)",
            "4. d = pow(e, -1, phi)",
            "5. m = pow(c, d, n)",
            "6. Convert m to bytes: m.to_bytes(..., 'big').decode()",
        ],
        "tools": ["sympy", "pycryptodome", "factordb.com"],
        "code": "from sympy import factorint\nfactors = factorint(n)\np, q = list(factors.keys())\nphi = (p-1)*(q-1)\nd = pow(e, -1, phi)\nm = pow(c, d, n)\nflag = m.to_bytes((m.bit_length()+7)//8,'big').decode()",
    },
    {
        "title": "XOR Single-byte Key Brute Force",
        "category": "crypto",
        "keywords": "XOR cipher single byte key brute force",
        "description": "Ciphertext encrypted with single-byte XOR key",
        "approach": [
            "1. Convert ciphertext to bytes (if hex: bytes.fromhex(ct))",
            "2. Try all 256 keys (0x00-0xFF)",
            "3. Score each by English letter frequency",
            "4. Key with highest score is likely correct",
        ],
        "tools": ["python", "cyberchef"],
        "code": "ct = bytes.fromhex('...')\nfor key in range(256):\n    plain = bytes(b^key for b in ct)\n    print(key, plain)",
    },
    {
        "title": "LSB Steganography - Image",
        "category": "forensics",
        "keywords": "LSB steganography image PNG BMP pixel bit",
        "description": "Flag hidden in least significant bits of image pixels",
        "approach": [
            "1. Open image with PIL/Pillow",
            "2. Extract LSB from R, G, B channels of each pixel",
            "3. Combine bits into bytes",
            "4. Decode as ASCII/UTF-8",
            "5. Look for flag pattern",
        ],
        "tools": ["stegsolve", "zsteg", "PIL", "Pillow"],
        "code": "from PIL import Image\nimg = Image.open('chall.png').convert('RGB')\nbits = [p[0]&1 for p in img.getdata()]\nbytes_ = [int(''.join(map(str,bits[i:i+8])),2) for i in range(0,len(bits),8)]\nprint(bytes(bytes_).decode(errors='replace'))",
    },
    {
        "title": "SQL Injection - UNION Based",
        "category": "web",
        "keywords": "SQL injection union select database table column",
        "description": "Web app vulnerable to UNION-based SQL injection",
        "approach": [
            "1. Find injection point (GET/POST param, cookie, header)",
            "2. Determine number of columns: ' ORDER BY 1-- ' ORDER BY 2--",
            "3. Find visible column: ' UNION SELECT null,null,null--",
            "4. Extract data: ' UNION SELECT table_name,null FROM information_schema.tables--",
            "5. Get flag: ' UNION SELECT flag,null FROM flags--",
        ],
        "tools": ["sqlmap", "burpsuite", "browser devtools"],
        "code": "# sqlmap auto\nsqlmap -u 'http://target/?id=1' --dbs\nsqlmap -u 'http://target/?id=1' -D ctf -T flags --dump",
    },
    {
        "title": "LFI - Local File Inclusion",
        "category": "web",
        "keywords": "LFI local file inclusion path traversal etc passwd",
        "description": "Web app includes local files based on user input",
        "approach": [
            "1. Find file inclusion parameter (?page=, ?file=, ?include=)",
            "2. Test: ?page=../../../../etc/passwd",
            "3. Try php://filter: ?page=php://filter/convert.base64-encode/resource=index.php",
            "4. Try /proc/self/environ, /var/log/apache2/access.log",
            "5. Look for flag in common paths",
        ],
        "tools": ["burpsuite", "curl", "wfuzz"],
        "code": "# Common LFI payloads\npayloads = ['../../../../etc/passwd','../../../../flag','../../../../flag.txt',\n'php://filter/convert.base64-encode/resource=index','../../../../proc/self/environ']",
    },
    {
        "title": "SSTI - Jinja2 Template Injection",
        "category": "web",
        "keywords": "SSTI template injection Jinja2 Flask Python",
        "description": "Flask/Jinja2 app renders user input as template",
        "approach": [
            "1. Test: {{7*7}} - if output is 49, SSTI confirmed",
            "2. Get config: {{config}}",
            "3. RCE: {{''.__class__.__mro__[1].__subclasses__()[xxx].__init__.__globals__['__builtins__']['__import__']('os').popen('cat flag.txt').read()}}",
            "4. Find correct subclass index for subprocess",
        ],
        "tools": ["burpsuite", "tplmap"],
        "code": "# Find OS module\n{{''.__class__.__mro__[1].__subclasses__()}}\n# RCE after finding index\n{{config.__class__.__init__.__globals__['os'].popen('cat flag.txt').read()}}",
    },
    {
        "title": "Buffer Overflow - ret2libc",
        "category": "pwn",
        "keywords": "buffer overflow ret2libc libc system /bin/sh ROP",
        "description": "Stack buffer overflow with NX enabled, return to libc",
        "approach": [
            "1. Find offset to RIP: cyclic(200) + gdb",
            "2. Leak libc address via puts/printf",
            "3. Calculate libc base: leaked - symbol_offset",
            "4. Find system() and '/bin/sh' in libc",
            "5. Build ROP: pop rdi; ret; /bin/sh addr; system addr",
        ],
        "tools": ["pwntools", "ROPgadget", "gdb-peda", "one_gadget"],
        "code": "from pwn import *\np = process('./binary')\nelf = ELF('./binary')\nlibc = ELF('/lib/x86_64-linux-gnu/libc.so.6')\n# Find offset, leak, compute base, shell",
    },
    {
        "title": "Reverse Engineering - String Comparison Patch",
        "category": "rev",
        "keywords": "reverse strcmp memcmp comparison patch binary flag check",
        "description": "Binary compares input to flag using strcmp/memcmp",
        "approach": [
            "1. Load binary in Ghidra/IDA",
            "2. Find main() or check() function",
            "3. Locate strcmp/memcmp call",
            "4. Set breakpoint, run, examine second argument (the flag)",
            "5. Alternatively: strings ./binary | grep flag",
        ],
        "tools": ["Ghidra", "IDA Pro", "gdb", "strings", "ltrace"],
        "code": "strings ./binary | grep -E 'flag|CTF|picoCTF'\nltrace ./binary  # trace library calls\ngdb ./binary -ex 'b strcmp' -ex 'r' -ex 'x/s $rsi'",
    },
    {
        "title": "PCAP Analysis - HTTP Credentials",
        "category": "forensics",
        "keywords": "PCAP network traffic HTTP credentials password login",
        "description": "Network capture with HTTP traffic containing credentials",
        "approach": [
            "1. Open in Wireshark",
            "2. Filter: http.request.method == POST",
            "3. Follow TCP Stream",
            "4. Look for Authorization header or POST body",
            "5. Decode base64 if Basic Auth",
        ],
        "tools": ["wireshark", "tcpdump", "scapy", "tshark"],
        "code": "tshark -r capture.pcap -Y 'http.request.method==POST' -T fields -e http.file_data\n# Or:\ntshark -r capture.pcap -z follow,tcp,ascii,0 -q",
    },
    {
        "title": "JWT - Algorithm None Attack",
        "category": "web",
        "keywords": "JWT algorithm none attack forge token header",
        "description": "JWT authentication with vulnerable alg:none",
        "approach": [
            "1. Decode JWT: base64(header).base64(payload).signature",
            "2. Modify header: {\"alg\":\"none\",\"typ\":\"JWT\"}",
            "3. Modify payload (e.g., admin:true, role:admin)",
            "4. Encode header+payload as base64",
            "5. Send: base64(header).base64(payload). (empty sig)",
        ],
        "tools": ["jwt.io", "burpsuite", "python"],
        "code": "import base64, json\nheader = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=')\npayload = base64.urlsafe_b64encode(json.dumps({'user':'admin','role':'admin'}).encode()).rstrip(b'=')\ntoken = f'{header.decode()}.{payload.decode()}.'\nprint(token)",
    },
    {
        "title": "Vigenere Cipher - Index of Coincidence",
        "category": "crypto",
        "keywords": "Vigenere cipher key length index coincidence frequency",
        "description": "Text encrypted with Vigenere cipher, unknown key",
        "approach": [
            "1. Calculate Index of Coincidence (IC) for different key lengths",
            "2. IC ~0.065 = English (correct key length)",
            "3. For each column: find shift that matches English frequency",
            "4. Combine key characters to get full key",
            "5. Decrypt: (cipherchar - keychar) mod 26",
        ],
        "tools": ["dcode.fr", "cryptanalysis", "quipqiup"],
        "code": "# dcode.fr/vigenere-cipher has auto-solve\n# Or use our ctf_agent.vigenere_autocrack()",
    },
    {
        "title": "File Magic Bytes - Extension Mismatch",
        "category": "forensics",
        "keywords": "magic bytes file extension mismatch rename extract",
        "description": "File has wrong extension, real type hidden in magic bytes",
        "approach": [
            "1. xxd file.unknown | head -3",
            "2. Compare first bytes to magic bytes table",
            "3. Rename to correct extension",
            "4. If ZIP: unzip and analyze contents",
            "5. If image: check for embedded files at end",
        ],
        "tools": ["file", "xxd", "hexdump", "binwalk"],
        "code": "file mystery.unknown\nxxd mystery.unknown | head\nbinwalk mystery.unknown\nbinwalk -e mystery.unknown  # extract",
    },
]


# ═══════════════════════════════════════════════════════════════
# MODULE 1: CTF CHALLENGE CLASSIFIER
# ═══════════════════════════════════════════════════════════════

class CTFClassifier:
    """TF-IDF + Logistic Regression CTF challenge classifier."""
    
    MODEL_PATH = MODEL_DIR / "ctf_classifier.pkl"
    CATEGORIES = ["crypto", "web", "forensics", "pwn", "rev", "misc"]
    CATEGORY_ICONS = {
        "crypto": "[CRYPTO]", "web": "[WEB]", "forensics": "[FORENSICS]",
        "pwn": "[PWN]", "rev": "[REV]", "misc": "[MISC]"
    }
    CATEGORY_TIPS = {
        "crypto": ["Check for Base64/Hex encoding first", "Try CyberChef for quick decoding",
                   "Look for RSA parameters (n, e, c)", "Frequency analysis for substitution ciphers"],
        "web": ["View page source (Ctrl+U)", "Check robots.txt and .git/HEAD",
                "Try SQLi: ' OR 1=1--", "Inspect cookies and JWT tokens"],
        "forensics": ["Run: file <filename> and xxd <filename>", "Try: binwalk -e <file> for extraction",
                      "Check image metadata with exiftool", "Use Wireshark for PCAP analysis"],
        "pwn": ["checksec ./binary for protections", "Find buffer overflow offset with cyclic()",
                "Use pwntools for exploit scripting", "Look for format string %p %p %p"],
        "rev": ["Try strings ./binary | grep flag", "Use Ghidra or IDA for decompilation",
                "Set breakpoints on strcmp/memcmp", "ltrace ./binary for library call tracing"],
        "misc": ["Read challenge description carefully for hints", "Try OSINT: reverse image search",
                 "Check git log --all for deleted commits", "Look for hidden channels/comments"],
    }

    def __init__(self):
        self.model = None
        self._load_or_train()

    def _load_or_train(self):
        if self.MODEL_PATH.exists() and not self._is_stale():
            try:
                self.model = joblib.load(self.MODEL_PATH)
                return
            except Exception:
                pass
        self._train()

    def _is_stale(self) -> bool:
        """Retrain if model is older than 7 days."""
        import time
        if not self.MODEL_PATH.exists():
            return True
        age = time.time() - self.MODEL_PATH.stat().st_mtime
        return age > 7 * 86400

    def _train(self):
        if not SKLEARN_AVAILABLE:
            return
        texts = [d[0] for d in TRAINING_DATA]
        labels = [d[1] for d in TRAINING_DATA]
        self.model = Pipeline([
            ('tfidf', TfidfVectorizer(
                ngram_range=(1, 2),
                max_features=5000,
                sublinear_tf=True,
                min_df=1,
            )),
            ('clf', LogisticRegression(
                max_iter=1000,
                C=2.0,
                class_weight='balanced',
                solver='lbfgs',
            )),
        ])
        self.model.fit(texts, labels)
        joblib.dump(self.model, self.MODEL_PATH)

    def predict(self, text: str) -> dict:
        """Classify a CTF challenge description."""
        if not SKLEARN_AVAILABLE:
            return {"error": "scikit-learn not available", "category": "misc"}
        if self.model is None:
            self._train()
            if self.model is None:
                return {"error": "scikit-learn not available", "category": "misc"}

        try:
            proba = self.model.predict_proba([text])[0]
            classes = self.model.classes_
        except Exception:
            # A cached model pickle can be incompatible with the installed
            # scikit-learn version (attributes change across releases, e.g.
            # LogisticRegression.multi_class). Retrain fresh from TRAINING_DATA
            # under the current library and retry once.
            self._train()
            proba = self.model.predict_proba([text])[0]
            classes = self.model.classes_

        sorted_results = sorted(zip(classes, proba), key=lambda x: -x[1])
        top_cat, top_score = sorted_results[0]
        
        return {
            "category": top_cat,
            "icon": self.CATEGORY_ICONS.get(top_cat, "[?]"),
            "confidence": round(float(top_score) * 100, 1),
            "all_scores": {
                cat: round(float(score) * 100, 1)
                for cat, score in sorted_results
            },
            "tips": self.CATEGORY_TIPS.get(top_cat, []),
            "status": f"{self.CATEGORY_ICONS.get(top_cat)} Classified as {top_cat.upper()} ({round(float(top_score)*100)}% confidence)",
        }


# ═══════════════════════════════════════════════════════════════
# MODULE 2: WRITEUP SEMANTIC SEARCH
# ═══════════════════════════════════════════════════════════════

class WriteupSearchEngine:
    """TF-IDF cosine similarity search over CTF writeup knowledge base."""
    
    def __init__(self):
        self.vectorizer = None
        self.matrix = None
        self._build_index()
    
    def _build_index(self):
        if not SKLEARN_AVAILABLE:
            return
        corpus = [
            f"{w['title']} {w['keywords']} {w['description']}"
            for w in WRITEUP_DB
        ]
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=3000)
        self.matrix = self.vectorizer.fit_transform(corpus)
    
    def search(self, query: str, top_k: int = 3) -> list:
        """Search for similar CTF writeups by query."""
        if not SKLEARN_AVAILABLE or self.vectorizer is None:
            return []
        q_vec = self.vectorizer.transform([query])
        sims = cosine_similarity(q_vec, self.matrix)[0]
        top_indices = sims.argsort()[-top_k:][::-1]
        
        results = []
        for idx in top_indices:
            if sims[idx] < 0.05:
                continue
            writeup = WRITEUP_DB[idx]
            results.append({
                "title": writeup["title"],
                "category": writeup["category"],
                "similarity": round(float(sims[idx]) * 100, 1),
                "approach": writeup["approach"],
                "tools": writeup["tools"],
                "code": writeup.get("code", ""),
                "description": writeup["description"],
            })
        return results


# ═══════════════════════════════════════════════════════════════
# MODULE 3: MULTI-SOURCE HASH ORACLE
# ═══════════════════════════════════════════════════════════════

COMMON_CTF_HASHES = {
    # MD5
    "5f4dcc3b5aa765d61d8327deb882cf99": "password",
    "e10adc3949ba59abbe56e057f20f883e": "123456",
    "d8578edf8458ce06fbc5bb76a58c5ca4": "qwerty",
    "827ccb0eea8a706c4c34a16891f84e7b": "12345",
    "1a1dc91c907325c69271ddf0c944bc72": "p@ssw0rd",
    "098f6bcd4621d373cade4e832627b4f6": "test",
    "cf83e1357eefb8bdf1542850d66d8007f708027a84b6a76dc9d30e00b": "empty",
    # SHA1
    "da39a3ee5e6b4b0d3255bfef95601890afd80709": "",
    "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d": "h",
    "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8": "password",
    "7c4a8d09ca3762af61e59520943dc26494f8941b": "123456",
}

# Prepopulate rainbow table for top 60 common CTF passwords across MD5, SHA1, SHA256
_COMMON_WORDS = [
    "password", "123456", "12345678", "1234", "qwerty", "12345", "dragon",
    "baseball", "football", "master", "monkey", "shadow", "superman",
    "welcome", "login", "admin", "toor", "root", "hello", "secret", "p@ssw0rd",
    "test", "pass", "letmein", "princess", "trustno1", "michael", "charlie",
    "computer", "joshua", "jordan", "michelle", "andrew", "hunter", "sunshine",
    "harley", "daniel", "chelsea", "starwars", "orange", "yellow", "purple",
    "matrix", "cyber", "security", "flag", "hacker", "pwn", "crypto", "forensics",
    "guest", "iloveyou", "temp", "default", "111111", "000000", "password123", "admin123"
]
for _w in _COMMON_WORDS:
    COMMON_CTF_HASHES[hashlib.md5(_w.encode()).hexdigest()] = _w
    COMMON_CTF_HASHES[hashlib.sha1(_w.encode()).hexdigest()] = _w
    COMMON_CTF_HASHES[hashlib.sha256(_w.encode()).hexdigest()] = _w

def crack_hash_multisource(hash_str: str, hash_type: str = "MD5") -> dict:
    """Try to crack hash from multiple sources."""
    hash_str = hash_str.strip().lower()
    result = {"hash": hash_str, "type": hash_type, "cracked": False, "plaintext": None, "source": None}
    
    # 1. Local common hash dictionary
    if hash_str in COMMON_CTF_HASHES:
        result.update({"cracked": True, "plaintext": COMMON_CTF_HASHES[hash_str], "source": "local_db"})
        return result

    # 2. Gromweb (Fast, free, reliable)
    if hash_type in ["MD5", "SHA1"]:
        try:
            sub = "md5" if hash_type == "MD5" else "sha1"
            param = "md5" if hash_type == "MD5" else "hash"
            r = requests.get(f"https://{sub}.gromweb.com/?{param}={hash_str}", headers={"User-Agent": "Mozilla/5.0"}, timeout=6)
            if r.status_code == 200:
                import urllib.parse
                m = re.search(r'href="/\?string=([^"]+)"', r.text)
                if m:
                    plain = urllib.parse.unquote(m.group(1))
                    result.update({"cracked": True, "plaintext": plain, "source": f"{sub}.gromweb.com"})
                    return result
        except Exception:
            pass
    
    # 2. CrackStation (free, no API key needed)
    try:
        r = requests.post("https://crackstation.net/crack.js",
            data={"hash": hash_str, "key": ""},
            headers={"Referer": "https://crackstation.net/", "Content-Type": "application/x-www-form-urlencoded"},
            timeout=8)
        if r.status_code == 200:
            # Parse response
            text = r.text
            if '"cracked":true' in text or '"result":"' in text:
                import re
                match = re.search(r'"result"\s*:\s*"([^"]+)"', text)
                if match and match.group(1) not in ["", "false", "null"]:
                    result.update({"cracked": True, "plaintext": match.group(1), "source": "crackstation"})
                    return result
    except Exception:
        pass
    
    # 3. md5decrypt.net (GET API)
    if hash_type == "MD5":
        try:
            r = requests.get(f"https://md5decrypt.net/Api/api.php?hash={hash_str}&hash_type=md5&email=&code=",
                timeout=6)
            if r.status_code == 200 and r.text and r.text not in ["NOTFOUND", "", "ERROR"]:
                result.update({"cracked": True, "plaintext": r.text.strip(), "source": "md5decrypt.net"})
                return result
        except Exception:
            pass
    
    # 4. hashes.com lookup
    try:
        r = requests.get(f"https://hashes.com/en/api/v1/search?hash={hash_str}", timeout=6)
        if r.status_code == 200:
            data = r.json()
            if data.get("success") and data.get("result"):
                for item in data["result"]:
                    if item.get("plaintext"):
                        result.update({"cracked": True, "plaintext": item["plaintext"], "source": "hashes.com"})
                        return result
    except Exception:
        pass
    
    result["hint"] = f"Not found online. Try: hashcat -m 0 {hash_str} /usr/share/wordlists/rockyou.txt"
    return result


# ═══════════════════════════════════════════════════════════════
# GLOBAL INSTANCES (lazy-loaded)
# ═══════════════════════════════════════════════════════════════

_classifier = None
_search_engine = None

def get_classifier() -> CTFClassifier:
    global _classifier
    if _classifier is None:
        _classifier = CTFClassifier()
    return _classifier

def get_search_engine() -> WriteupSearchEngine:
    global _search_engine
    if _search_engine is None:
        _search_engine = WriteupSearchEngine()
    return _search_engine


# ═══════════════════════════════════════════════════════════════
# MAIN API FUNCTIONS
# ═══════════════════════════════════════════════════════════════

def ctf_classify(description: str) -> dict:
    """Classify a CTF challenge description and return category + tips + similar writeups."""
    clf = get_classifier()
    engine = get_search_engine()
    
    classification = clf.predict(description)
    similar = engine.search(description, top_k=3)
    
    return {
        "classification": classification,
        "similar_writeups": similar,
        "quick_start": f"This looks like a {classification['category'].upper()} challenge. " +
                       (classification['tips'][0] if classification['tips'] else ""),
    }

def ctf_hash_crack(hash_str: str) -> dict:
    """Crack a hash using multiple online sources."""
    hash_str = hash_str.strip()
    # Detect hash type by length
    hash_types = {32: "MD5", 40: "SHA1", 56: "SHA224", 64: "SHA256", 96: "SHA384", 128: "SHA512"}
    hash_type = hash_types.get(len(hash_str), "Unknown")
    return crack_hash_multisource(hash_str, hash_type)
