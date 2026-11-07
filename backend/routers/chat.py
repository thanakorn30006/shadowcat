import sys, json, asyncio
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.config import (
    GEMINI_API_KEY, PRIMARY_MODEL,
    PSU_AI_API_KEY, PSU_AI_BASE_URL, PSU_AI_MODEL, PREFERRED_AI_PROVIDER
)

router = APIRouter()

CTF_SYSTEM_PROMPT = """You are ShadowSolve, an expert elite CTF (Capture The Flag) AI assistant.
You specialize in all CTF categories:
- Crypto: ciphers, encoding, RSA, hash cracking, lattice, discrete log
- Forensics: file analysis, steganography, PCAP traffic, memory dumps, EVTX logs, MBR/FAT/NTFS carving
- Web: SQLi, XSS, LFI, SSTI, JWT, SSRF, XXE, deserialization, request smuggling
- Pwn: buffer overflow, ROP chains, format string, heap exploitation (tcache, fastbin)
- Rev: binary reversing, decompilation, anti-debug, angr, Z3, assembly
- Misc: OSINT, esoteric languages, jail escape, scripting

Be concise, practical, and provide immediate working code or terminal commands.
Always think step-by-step. If given a cipher or payload, analyze and attack it.
Flag format examples: picoCTF{...}, flag{...}, HTB{...}, CTF{...}, etc."""

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    context: Optional[str] = None

def _sync_chat_gemini(messages: List[ChatMessage], context: Optional[str] = None) -> str:
    """Chat via Gemini API with timeout protection."""
    from google import genai
    client = genai.Client(api_key=GEMINI_API_KEY)
    
    sys_content = CTF_SYSTEM_PROMPT
    if context:
        sys_content += f"\n\nCURRENT CHALLENGE CONTEXT:\n{context}"

    contents = []
    for m in messages:
        role = "user" if m.role == "user" else "model"
        contents.append({"role": role, "parts": [{"text": m.content}]})

    config = {"system_instruction": sys_content}
    response = client.models.generate_content(
        model=PRIMARY_MODEL,
        contents=contents,
        config=config,
    )
    return response.text or ""

def _sync_chat_psu(messages: List[ChatMessage], context: Optional[str] = None) -> str:
    """Chat via PSU AI (OpenAI-compatible) with timeout protection."""
    from openai import OpenAI
    client = OpenAI(api_key=PSU_AI_API_KEY, base_url=PSU_AI_BASE_URL, timeout=15.0)
    
    sys_content = CTF_SYSTEM_PROMPT
    if context:
        sys_content += f"\n\nCURRENT CHALLENGE CONTEXT:\n{context}"
    
    msgs = [{"role": "system", "content": sys_content}]
    for m in messages:
        msgs.append({"role": m.role, "content": m.content})
    
    response = client.chat.completions.create(model=PSU_AI_MODEL, messages=msgs)
    return response.choices[0].message.content or ""

@router.post("")
async def chat(req: ChatRequest):
    """AI chat for CTF help with automatic dual-provider fallback and non-blocking worker threads."""
    errors = []
    providers = []

    # Build provider priority list
    if PREFERRED_AI_PROVIDER == "psu_ai" and PSU_AI_API_KEY:
        providers.append(("psu_ai", _sync_chat_psu))
        if GEMINI_API_KEY:
            providers.append(("gemini", _sync_chat_gemini))
    elif GEMINI_API_KEY:
        providers.append(("gemini", _sync_chat_gemini))
        if PSU_AI_API_KEY:
            providers.append(("psu_ai", _sync_chat_psu))
    elif PSU_AI_API_KEY:
        providers.append(("psu_ai", _sync_chat_psu))

    for name, fn in providers:
        try:
            reply = await asyncio.wait_for(asyncio.to_thread(fn, req.messages, req.context), timeout=25.0)
            if reply:
                return {"reply": reply, "provider": name}
        except asyncio.TimeoutError:
            errors.append(f"{name}: Request timed out after 25 seconds")
        except Exception as e:
            errors.append(f"{name}: {str(e)[:200]}")

    # Offline fallback when no AI provider works
    if errors:
        return {
            "reply": f"[OFFLINE MODE] AI providers unavailable. Errors:\n" + "\n".join(errors) + "\n\nTip: You can still use all other tools (Crypto, Forensics, Web, RSA, JWT, etc.) fully offline.",
            "provider": "offline_fallback"
        }
    return {
        "reply": "[OFFLINE MODE] No AI API key configured. Add GEMINI_API_KEY or PSU_AI_API_KEY to backend/.env file.\n\nAll other tools (Crypto, Forensics, Web, RSA, JWT, Binary, Netcat, etc.) work fully offline without any API key.",
        "provider": "offline_fallback"
    }
