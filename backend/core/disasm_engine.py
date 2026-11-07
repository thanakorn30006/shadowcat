"""
SHADOW CAT — Binary Disassembly & Function Analysis Engine
Uses Apple LLVM / GNU objdump to disassemble ELF, PE, and Mach-O binaries.
Extracts function symbols (main, vuln, win), instructions, addresses, and call references.
"""

import subprocess
import shutil
import re
import os
from pathlib import Path
from typing import Dict, List, Any, Optional

OBJDUMP_PATH = shutil.which("objdump") or "/usr/bin/objdump"

TARGET_ROUTINES = [
    "main", "vuln", "target", "win", "flag", "secret", "pwn", 
    "check", "auth", "validate", "solve", "execute", "shell", "get_flag"
]

DANGEROUS_FUNCS = {"system", "execve", "gets", "strcpy", "sprintf", "printf", "ptrace", "mprotect"}

def disassemble_binary(filepath: str, max_lines_per_func: int = 150) -> Dict[str, Any]:
    """
    Disassembles the given binary and organizes instructions by function or routine.
    """
    if not os.path.exists(filepath):
        return {"success": False, "error": f"File not found: {filepath}"}

    # Attempt disassembly with various flags
    cmd_candidates = [
        [OBJDUMP_PATH, "-d", "--x86-asm-syntax=intel", filepath],
        [OBJDUMP_PATH, "-d", filepath],
        ["objdump", "-d", filepath]
    ]

    disasm_output = ""
    used_cmd = ""
    for cmd in cmd_candidates:
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=12)
            if res.returncode == 0 and len(res.stdout) > 50:
                disasm_output = res.stdout
                used_cmd = " ".join(cmd[:2])
                break
        except Exception:
            continue

    if not disasm_output:
        return {
            "success": False,
            "error": "Could not disassemble binary. Binary might be packed, corrupted, or unsupported architecture.",
            "functions_found": [],
            "functions": {},
            "raw_preview": ""
        }

    # Regex for function header: e.g. "0000000000001149 <main>:" or "00000001000004c0 <_main>:" or "_main:"
    func_header_re = re.compile(r'^[0-9a-fA-F]+\s+<([^>]+)>:|^_?([A-Za-z0-9_]{2,40}):')
    
    # Instruction line regex supporting tabs and spaces
    # Example: "1000004c0:\t55\tpushq\t%rbp" or " 1149:\t55 \tpush   rbp"
    inst_line_re = re.compile(r'^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F\s]{2,24})\s+([a-zA-Z0-9.]+)(?:\s+(.*))?$')

    functions: Dict[str, List[Dict[str, str]]] = {}
    current_func: str = "entrypoint"
    functions[current_func] = []
    dangerous_calls: List[Dict[str, str]] = []

    for line in disasm_output.splitlines():
        line_clean = line.strip()
        if not line_clean:
            continue

        # Check for section header
        if "section" in line_clean and ("text" in line_clean.lower() or "CODE" in line_clean):
            current_func = "text_section"
            if current_func not in functions:
                functions[current_func] = []
            continue

        # Check function header
        header_match = func_header_re.match(line_clean)
        if header_match:
            raw_name = header_match.group(1) or header_match.group(2)
            cleaned_name = raw_name.lstrip('_')
            current_func = cleaned_name
            functions[current_func] = []
            continue

        # Check instruction line
        parts = line_clean.split('\t')
        if len(parts) >= 3 and parts[0].endswith(':'):
            addr_str = parts[0][:-1].strip()
            raw_bytes = parts[1].strip()
            mnemonic = parts[2].strip()
            operands = parts[3].strip() if len(parts) > 3 else ""

            # Check symbol annotations in comment (e.g. ## symbol stub for: _getenv)
            comment = ""
            if "##" in operands:
                op_parts = operands.split("##", 1)
                operands = op_parts[0].strip()
                comment = op_parts[1].strip()
            elif "#" in operands:
                op_parts = operands.split("#", 1)
                operands = op_parts[0].strip()
                comment = op_parts[1].strip()

            entry = {
                "address": "0x" + addr_str.lstrip("0") if addr_str != "0" else "0x0",
                "bytes": raw_bytes,
                "mnemonic": mnemonic,
                "operands": operands,
                "comment": comment
            }

            if len(functions[current_func]) < max_lines_per_func:
                functions[current_func].append(entry)

            # Check for dangerous or critical function calls
            if "call" in mnemonic.lower() or "bl" in mnemonic.lower():
                target_name = (operands + " " + comment).lower()
                for danger in DANGEROUS_FUNCS:
                    if danger in target_name:
                        dangerous_calls.append({
                            "caller": current_func,
                            "address": entry["address"],
                            "callee": danger,
                            "instruction": f"{mnemonic} {operands} {comment}".strip()
                        })
            continue

        # Fallback regex match for formats without tabs
        m = inst_line_re.match(line_clean)
        if m and len(functions[current_func]) < max_lines_per_func:
            addr = m.group(1)
            raw_bytes = m.group(2).strip()
            mnemonic = m.group(3)
            operands = (m.group(4) or "").strip()

            entry = {
                "address": "0x" + addr.lstrip("0") if addr != "0" else "0x0",
                "bytes": raw_bytes,
                "mnemonic": mnemonic,
                "operands": operands,
                "comment": ""
            }
            functions[current_func].append(entry)

    # Clean out empty pseudo-functions
    functions = {k: v for k, v in functions.items() if len(v) > 0}
    if not functions:
        functions["raw_stream"] = []
        for line in disasm_output.splitlines()[:100]:
            if line.strip():
                functions["raw_stream"].append({"address": "", "bytes": "", "mnemonic": line.strip(), "operands": "", "comment": ""})

    # Rank priority functions (main, vuln, win, etc.)
    priority_funcs = []
    other_funcs = []

    for f in functions.keys():
        low = f.lower()
        if any(t in low for t in TARGET_ROUTINES):
            priority_funcs.append(f)
        else:
            other_funcs.append(f)

    all_sorted = priority_funcs + other_funcs

    # Generate raw preview
    preview_blocks = []
    for f in all_sorted[:5]:
        preview_blocks.append(f"<{f}>:")
        for inst in functions[f][:20]:
            comm = f" ; {inst['comment']}" if inst.get('comment') else ""
            preview_blocks.append(f"  {inst['address']:<12} {inst['mnemonic']:<8} {inst['operands']}{comm}")
        if len(functions[f]) > 20:
            preview_blocks.append(f"  ... (+{len(functions[f]) - 20} instructions)")
        preview_blocks.append("")

    return {
        "success": True,
        "used_tool": used_cmd,
        "functions_found": all_sorted,
        "priority_functions": priority_funcs,
        "functions": {k: functions[k] for k in all_sorted[:15]},
        "dangerous_calls": dangerous_calls,
        "raw_preview": "\n".join(preview_blocks).strip()
    }
