"""
SHADOW CAT — Deep Wireshark-Grade PCAP / PCAPNG Analyzer
Provides protocol breakdown, conversation matrix, HTTP object carving,
credential hunting, DNS tunneling detection, and TCP stream following.
"""

import os
import re
import base64
import hashlib
from typing import Dict, List, Any, Optional

def deep_analyze_pcap(filepath: str) -> Dict[str, Any]:
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, Raw, DNS, ICMP, ARP
    except ImportError:
        return {"error": "Scapy is not installed in the environment."}

    try:
        packets = rdpcap(filepath)
    except Exception as e:
        return {"error": f"Failed to parse PCAP file: {str(e)}"}

    total_packets = len(packets)
    if total_packets == 0:
        return {"total_packets": 0, "message": "PCAP file is empty."}

    # 1. Protocol Breakdown
    protocols: Dict[str, int] = {
        "HTTP": 0,
        "DNS": 0,
        "TCP": 0,
        "UDP": 0,
        "ICMP": 0,
        "ARP": 0,
        "TLS/SSL": 0,
        "Other": 0
    }

    # 2. Conversations & Endpoints
    conversations: Dict[str, Dict[str, Any]] = {}
    ips: set = set()

    # 3. HTTP Objects & TCP Streams
    tcp_streams: Dict[str, List[Dict[str, Any]]] = {}
    exported_objects: List[Dict[str, Any]] = []
    credentials: List[Dict[str, str]] = []
    dns_queries: List[str] = []
    dns_subdomains: List[str] = []
    flags_found: set = set()

    # Flag Regex Pattern
    FLAG_REGEX = re.compile(r'(?:flag|ctf|picoctf|htb|thcon|seccon|defcon)\{[a-zA-Z0-9_\-\.\!@#\$\%^&*+=]+\}', re.IGNORECASE)

    for idx, pkt in enumerate(packets):
        # Protocol classification
        matched_proto = False
        if ARP in pkt:
            protocols["ARP"] += 1
            matched_proto = True
        elif ICMP in pkt:
            protocols["ICMP"] += 1
            matched_proto = True

        src_ip, dst_ip = "Unknown", "Unknown"
        if IP in pkt:
            src_ip = str(pkt[IP].src)
            dst_ip = str(pkt[IP].dst)
            ips.add(src_ip)
            ips.add(dst_ip)

        # DNS Inspection
        if DNS in pkt and pkt[DNS].qd:
            protocols["DNS"] += 1
            matched_proto = True
            try:
                qname = pkt[DNS].qd.qname.decode(errors="replace").rstrip(".")
                dns_queries.append(qname)
                for f in FLAG_REGEX.findall(qname):
                    flags_found.add(f)
                
                parts = qname.split(".")
                if len(parts) > 1 and len(parts[0]) >= 4:
                    dns_subdomains.append(parts[0])
            except Exception:
                pass

        # TCP / UDP Flow Tracking
        src_port, dst_port = 0, 0
        is_tcp = TCP in pkt
        is_udp = UDP in pkt

        if is_tcp:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            if not matched_proto:
                if src_port in (443, 8443) or dst_port in (443, 8443):
                    protocols["TLS/SSL"] += 1
                elif src_port in (80, 8080, 8000, 3000, 5000) or dst_port in (80, 8080, 8000, 3000, 5000):
                    protocols["HTTP"] += 1
                else:
                    protocols["TCP"] += 1
                matched_proto = True
        elif is_udp and not matched_proto:
            protocols["UDP"] += 1
            matched_proto = True

        if not matched_proto:
            protocols["Other"] += 1

        # Track Conversation (normalized bidirectional key)
        if src_ip != "Unknown" and dst_ip != "Unknown":
            conv_key = " <-> ".join(sorted([f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}"]))
            if conv_key not in conversations:
                conversations[conv_key] = {
                    "endpoint_a": f"{src_ip}:{src_port}",
                    "endpoint_b": f"{dst_ip}:{dst_port}",
                    "packets": 0,
                    "bytes": 0,
                    "proto": "TCP" if is_tcp else "UDP" if is_udp else "IP"
                }
            conversations[conv_key]["packets"] += 1
            conversations[conv_key]["bytes"] += len(pkt)

        # Raw Payload Examination (HTTP, Credentials, Files)
        if Raw in pkt:
            raw_bytes = pkt[Raw].load
            payload_text = raw_bytes.decode("latin-1", errors="replace")

            # Search flags in payload
            for f in FLAG_REGEX.findall(payload_text):
                flags_found.add(f)

            # Reconstruct TCP stream segments
            if is_tcp:
                stream_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                rev_stream_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
                primary_id = stream_id if stream_id in tcp_streams else rev_stream_id
                
                if primary_id not in tcp_streams:
                    if len(tcp_streams) < 25: # Cap top 25 streams
                        tcp_streams[primary_id] = []
                        primary_id = stream_id

                if primary_id in tcp_streams and len(tcp_streams[primary_id]) < 50:
                    tcp_streams[primary_id].append({
                        "packet_num": idx + 1,
                        "direction": "out" if primary_id == stream_id else "in",
                        "sender": f"{src_ip}:{src_port}",
                        "receiver": f"{dst_ip}:{dst_port}",
                        "size": len(raw_bytes),
                        "snippet": payload_text[:1200]
                    })

            # Credential Hunting
            # A. HTTP Basic Auth
            if "Authorization: Basic " in payload_text:
                for match in re.findall(r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', payload_text, re.IGNORECASE):
                    try:
                        decoded_cred = base64.b64decode(match).decode("latin-1", errors="replace")
                        credentials.append({
                            "type": "HTTP Basic Auth",
                            "source": f"{src_ip} -> {dst_ip}",
                            "raw_token": match,
                            "decoded": decoded_cred
                        })
                    except Exception:
                        pass

            # B. Plaintext POST Parameters
            if "POST " in payload_text or "password=" in payload_text.lower():
                cred_matches = re.findall(r'(?:username|user|login|email|passwd|password|pwd|token|api_key)=([^&\s\r\n]{3,60})', payload_text, re.IGNORECASE)
                if cred_matches:
                    for val in cred_matches[:4]:
                        credentials.append({
                            "type": "Form / Query Parameter",
                            "source": f"{src_ip} -> {dst_ip}",
                            "parameter_value": val,
                            "raw_snippet": payload_text[:300].strip()
                        })

            # Export Objects / Transferred Files Carving
            if "HTTP/1." in payload_text and "\r\n\r\n" in payload_text:
                headers, body_str = payload_text.split("\r\n\r\n", 1)
                body_bytes = raw_bytes[len(headers.encode("latin-1")) + 4:] if len(raw_bytes) > len(headers) else b""

                filename = "carved_object"
                uri_match = re.search(r'(?:GET|POST)\s+([^\s\?]+)', headers)
                if uri_match:
                    uri_path = uri_match.group(1).rstrip('/')
                    filename = os.path.basename(uri_path) or "index.html"

                mime = "application/octet-stream"
                mime_match = re.search(r'Content-Type:\s*([^\s;\r\n]+)', headers, re.IGNORECASE)
                if mime_match:
                    mime = mime_match.group(1).lower()

                if len(body_bytes) > 20 and len(exported_objects) < 20:
                    sha256 = hashlib.sha256(body_bytes).hexdigest()
                    obj_item = {
                        "filename": filename,
                        "mime": mime,
                        "size_bytes": len(body_bytes),
                        "sha256": sha256[:16] + "...",
                        "source": f"{src_ip} -> {dst_ip}",
                        "preview": body_str[:250].strip()
                    }
                    if mime.startswith("image/") and len(body_bytes) < 500000:
                        obj_item["data_uri"] = f"data:{mime};base64,{base64.b64encode(body_bytes).decode('utf-8')}"
                    
                    exported_objects.append(obj_item)

    # DNS Exfiltration Assembly
    dns_exfiltration_data = None
    if len(dns_subdomains) >= 3:
        joined_dns = "".join(dns_subdomains)
        dns_exfiltration_data = {
            "query_count": len(dns_subdomains),
            "joined_subdomains": joined_dns[:200] + ("..." if len(joined_dns) > 200 else ""),
        }
        for f in FLAG_REGEX.findall(joined_dns):
            flags_found.add(f)
        try:
            dec = base64.b64decode(joined_dns).decode("latin-1", errors="ignore")
            for f in FLAG_REGEX.findall(dec):
                flags_found.add(f)
            dns_exfiltration_data["base64_decoded"] = dec[:200]
        except Exception:
            pass

    # Sort conversations by highest byte transfer
    sorted_convs = sorted(conversations.values(), key=lambda x: x["bytes"], reverse=True)[:15]

    return {
        "total_packets": total_packets,
        "protocol_stats": protocols,
        "unique_ips": sorted(list(ips)),
        "top_conversations": sorted_convs,
        "exported_objects": exported_objects,
        "credentials_found": credentials,
        "dns_queries_sample": list(set(dns_queries))[:30],
        "dns_exfiltration": dns_exfiltration_data,
        "tcp_streams_count": len(tcp_streams),
        "tcp_streams": {k: v for k, v in list(tcp_streams.items())[:6]},
        "flags_found": sorted(list(flags_found))
    }
