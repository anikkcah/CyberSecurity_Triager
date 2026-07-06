import os
import sys
import json
import re
import sqlite3
import asyncio
import subprocess
from typing import Any
from pathlib import Path
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify, render_template

# Ensure the project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import google.genai as genai
from google.genai import types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Email parsing
from email import policy
from email.parser import BytesParser

# DB location
DB_FILE = str(PROJECT_ROOT / "lookups.db")

# YAML parser helper (to read frontmatter of SKILL.md without external yaml dependency)
def parse_yaml_frontmatter(content: str) -> dict:
    metadata = {}
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n", content, re.DOTALL | re.MULTILINE)
    if match:
        frontmatter = match.group(1)
        for line in frontmatter.split("\n"):
            if ":" in line:
                key, val = line.split(":", 1)
                key = key.strip()
                val = val.strip()
                # Clean strings or lists
                if val.startswith("[") and val.endswith("]"):
                    val = [item.strip().strip("'\"") for item in val[1:-1].split(",")]
                else:
                    val = val.strip("'\"")
                metadata[key] = val
    return metadata

# Function to read all three agentic skills
def get_agentic_skills() -> dict:
    skills = {}
    skill_dirs = ["artifact_extraction", "threat_intel_investigation", "triage_report_generation"]
    for sd in skill_dirs:
        skill_path = PROJECT_ROOT / sd / "SKILL.md"
        if skill_path.exists():
            content = skill_path.read_text(encoding="utf-8")
            meta = parse_yaml_frontmatter(content)
            # Remove frontmatter to get the body
            body = re.sub(r"^---\s*\n.*?\n---\s*\n", "", content, flags=re.DOTALL | re.MULTILINE)
            skills[sd] = {
                "name": meta.get("name", sd),
                "description": meta.get("description", "No description provided."),
                "version": meta.get("version", "1.0.0"),
                "allowed_tools": meta.get("allowed-tools", []),
                "details": body.strip()
            }
        else:
            skills[sd] = {
                "name": sd,
                "description": f"Skill folder exists but SKILL.md was not found at {skill_path}",
                "version": "0.0.0",
                "allowed_tools": [],
                "details": ""
            }
    return skills

# ═══════════════════════════════════════════════════════════════════════════════
# Email header parsing helpers
# ═══════════════════════════════════════════════════════════════════════════════
def _parse_auth_results(msg) -> dict:
    auth = msg.get("Authentication-Results", "") or ""
    result = {"spf": "missing", "dkim": "missing", "dmarc": "missing"}
    auth_lower = auth.lower()
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"{mechanism}\s*=\s*(\w+)", auth_lower)
        if match:
            result[mechanism] = match.group(1)
    return result

def _parse_received_hops(msg) -> list:
    hops = []
    for hdr in msg.get_all("Received") or []:
        from_match = re.search(r"from\s+(\S+)", hdr, re.I)
        by_match = re.search(r"by\s+(\S+)", hdr, re.I)
        date_match = re.search(r";\s*(.+)$", hdr.strip())
        hops.append({
            "from": from_match.group(1) if from_match else "unknown",
            "by": by_match.group(1) if by_match else "unknown",
            "date": date_match.group(1).strip() if date_match else "",
            "raw": hdr.strip(),
        })
    hops.reverse()
    return hops

def _parse_email_headers(raw_bytes: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    return {
        "subject": msg.get("Subject", ""),
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "date": msg.get("Date", ""),
        "return_path": msg.get("Return-Path", ""),
        "message_id": msg.get("Message-ID", ""),
        "x_mailer": msg.get("X-Mailer", ""),
        "authentication": _parse_auth_results(msg),
        "received_hops": _parse_received_hops(msg),
    }

def _extract_body(raw_bytes: bytes) -> str:
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    parts.append(part.get_content())
                except Exception:
                    pass
        return "\n".join(parts) if parts else ""
    return msg.get_content() or ""

# ═══════════════════════════════════════════════════════════════════════════════
# Pipeline Step Helpers
# ═══════════════════════════════════════════════════════════════════════════════
async def call_mcp_tool(session: ClientSession, tool_name: str, args: dict) -> Any:
    result = await session.call_tool(tool_name, args)
    if result.content:
        try:
            return json.loads(result.content[0].text)
        except Exception:
            return result.content[0].text
    return None

def extract_iocs_via_script(email_text: str) -> dict:
    """Runs artifact_extraction/scripts/parse_artifacts.py via subprocess."""
    script_path = PROJECT_ROOT / "artifact_extraction" / "scripts" / "parse_artifacts.py"
    if not script_path.exists():
        # Fallback to direct Python import or standard regex if script missing
        import re
        patterns = {
            "ips": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            "domains": r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
            "urls": r'https?://[^\s<>"]+|ftp://[^\s<>"]+',
            "hashes": r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b'
        }
        results = {}
        for category, pattern in patterns.items():
            found = set(re.findall(pattern, email_text, re.IGNORECASE))
            results[category] = sorted(list(found))
        return results

    try:
        proc = subprocess.run(
            [sys.executable, str(script_path)],
            input=email_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True
        )
        return json.loads(proc.stdout)
    except Exception as e:
        print(f"[ERROR] Failed to run parse_artifacts.py: {e}")
        # Fallback to empty structure
        return {"ips": [], "domains": [], "urls": [], "hashes": []}

def calculate_reputation(ioc_type: str, data: Any) -> dict:
    """Applies references/reputation_rubric.md logic to threat intel data."""
    verdict = "Clean"
    risk_score = 0
    flags = "0/0"
    age = "Unknown"

    if not data or "error" in data:
        return {"verdict": "Unknown", "risk_score": 0, "flags": "N/A", "age": "Unknown"}

    if ioc_type == "ip":
        malicious = data.get("malicious_votes", 0)
        harmless = data.get("harmless_votes", 0)
        suspicious = data.get("suspicious_votes", 0)
        total = malicious + harmless + suspicious
        flags = f"{malicious}/{total}" if total > 0 else "0/0"
        
        if malicious > 10:
            verdict = "Malicious (Critical)"
            risk_score = 10
        elif malicious >= 4:
            verdict = "Suspicious (High)"
            risk_score = 7
        elif malicious >= 1 or suspicious >= 2:
            verdict = "Suspicious (Medium)"
            risk_score = 4
        else:
            verdict = "Clean (Low)"
            risk_score = 1
        
        # Simple age representation or owner
        age = data.get("owner", "Unknown Owner")

    elif ioc_type == "domain":
        # Check WHOIS output for patterns
        whois_output = data.get("whois_output", "")
        if whois_output:
            # Check for creation date
            creation_match = re.search(
                r'(?:Creation Date|Created On|Create Date|Registration Time):\s*(.+)', 
                whois_output, 
                re.IGNORECASE
            )
            if creation_match:
                age = creation_match.group(1).strip()
            
            # Simple heuristic flags based on terms in whois
            if any(term in whois_output.lower() for term in ["abuse", "malicious", "phish"]):
                verdict = "Suspicious (Medium)"
                risk_score = 4
            else:
                verdict = "Clean (Low)"
                risk_score = 1

    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "flags": flags,
        "age": age
    }

async def run_threat_intel_investigation(iocs: dict, session: ClientSession) -> list:
    """Enriches the extracted IOCs using the MCP client tools."""
    enriched = []
    
    # Helper to process an artifact
    async def process_item(ioc_type: str, artifact: str):
        # 1. Search lookups history (last 24 hours)
        cache_res = await call_mcp_tool(session, "search_lookups", {"query": artifact})
        
        use_cached = False
        cached_data = None
        if isinstance(cache_res, list) and cache_res and "error" not in cache_res[0]:
            # Look for recent matches
            for record in cache_res:
                if record.get("artifact") == artifact:
                    # Parse timestamp
                    try:
                        ts = datetime.fromisoformat(record.get("timestamp"))
                        if datetime.now(timezone.utc) - ts < timedelta(hours=24):
                            use_cached = True
                            cached_data = json.loads(record.get("results"))
                            break
                    except Exception:
                        pass
        
        if use_cached:
            intel = {"source": "cache", "data": cached_data}
        else:
            # Query external API
            if ioc_type == "ip":
                if os.getenv("VT_API_KEY"):
                    vt_data = await call_mcp_tool(session, "virustotal_ip_lookup", {"ip_addr": artifact})
                    intel = {"source": "virustotal", "data": vt_data}
                else:
                    intel = {"source": "virustotal", "data": {"error": "VT_API_KEY not set"}}
            elif ioc_type == "domain":
                try:
                    whois_data = await call_mcp_tool(session, "whois_lookup", {"domain": artifact})
                    intel = {"source": "whois", "data": whois_data}
                except Exception as e:
                    intel = {"source": "whois", "data": {"error": f"WHOIS failed: {str(e)}"}}
            else:
                intel = {"source": "none", "data": {"note": "No direct external lookup tools defined for this type"}}
            
            # Save lookup result
            try:
                await call_mcp_tool(
                    session,
                    "save_lookup",
                    {
                        "ioc_type": ioc_type,
                        "artifact": artifact,
                        "results": json.dumps(intel["data"])
                    }
                )
            except Exception as e:
                print(f"[WARN] Failed to save lookup for {artifact}: {e}")

        # Map to Reputation Rubric
        rep = calculate_reputation(ioc_type, intel["data"])
        
        enriched.append({
            "ioc_type": ioc_type,
            "artifact": artifact,
            "threat_intel": intel,
            "reputation": rep
        })

    # Process all categories
    for ip in iocs.get("ips", []):
        await process_item("ip", ip)
    for domain in iocs.get("domains", []):
        await process_item("domain", domain)
    for url in iocs.get("urls", []):
        # Extract hostname from URL for WHOIS lookups
        hostname = url.split("//")[-1].split("/")[0].split(":")[0]
        await process_item("domain", hostname)
    for hsh in iocs.get("hashes", []):
        await process_item("hash", hsh)
        
    return enriched

async def generate_triage_report(enriched_iocs: list, email_headers: dict) -> tuple:
    """Uses Gemini API to fill the report template based on enriched IOCs."""
    template_path = PROJECT_ROOT / "triage_report_generation" / "assets" / "report_template.md"
    template_content = ""
    if template_path.exists():
        template_content = template_path.read_text(encoding="utf-8")
    else:
        template_content = "# Security Triage Investigation Report\n\n**Date:** {{INVESTIGATION_DATE}}\n\n## 1. Executive Summary\n{{EXECUTIVE_SUMMARY}}\n\n## 2. Risk Assessment\n**Overall Risk Level:** {{RISK_LEVEL}}\n"

    # Derive overall risk level
    highest_score = 0
    verdicts = []
    for item in enriched_iocs:
        score = item.get("reputation", {}).get("risk_score", 0)
        if score > highest_score:
            highest_score = score
        verdicts.append(item.get("reputation", {}).get("verdict", "Clean"))
    
    if highest_score >= 10:
        overall_risk = "CRITICAL"
    elif highest_score >= 7:
        overall_risk = "HIGH"
    elif highest_score >= 4:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    # Formulate a structured prompt for Gemini
    client = genai.Client()
    
    enriched_json = json.dumps(enriched_iocs, indent=2)
    headers_json = json.dumps(email_headers, indent=2)
    
    prompt = f"""
You are a Cyber Security Reporter Agent. Your job is to fill out the following report template based on the provided email headers and enriched threat intelligence findings.

EMAIL HEADERS:
{headers_json}

ENRICHED THREAT INTEL:
{enriched_json}

REPORT TEMPLATE:
{template_content}

INSTRUCTIONS:
1. Replace all double curly brace placeholders (like {{INVESTIGATION_DATE}}, {{EXECUTIVE_SUMMARY}}, {{RISK_LEVEL}}, {{KEY_FINDING_1}}, etc.) with high-quality, professional descriptions.
2. In section 3, construct a markdown table row for EACH enriched indicator of compromise. The table template shows:
   | {{TYPE}} | `{{INDICATOR}}` | {{VERDICT}} | {{SCORE}} | {{FLAGS}} | {{AGE}} |
   Replace this template row with actual rows for all indicators.
3. Make sure to provide a realistic Case Reference ID (e.g. CASE-2026-XXXX).
4. Provide a sound rationale for the Risk Assessment.
5. Provide actionable next steps (remediation/incident response) for the next steps section.
6. Return ONLY the final populated markdown text. Do not wrap in extra explanation.
"""
    try:
        response = await client.aio.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction="You are a strict cybersecurity reporter. Return ONLY the populated markdown text of the triage report.",
            )
        )
        return response.text, overall_risk
    except Exception as e:
        print(f"[ERROR] Gemini report generation failed: {e}")
        # Fallback manual completion
        report = template_content
        report = report.replace("{{INVESTIGATION_DATE}}", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        report = report.replace("{{CASE_REFERENCE_ID}}", "CASE-FALLBACK")
        report = report.replace("{{EXECUTIVE_SUMMARY}}", "Automated triage completed with errors in AI reporting module.")
        report = report.replace("{{RISK_LEVEL}}", overall_risk)
        return report, overall_risk

# ═══════════════════════════════════════════════════════════════════════════════
# App Factory and Routes
# ═══════════════════════════════════════════════════════════════════════════════
def create_app():
    base_dir = Path(__file__).resolve().parent
    app = Flask(
        __name__,
        template_folder=str(base_dir / "templates"),
        static_folder=str(base_dir / "static"),
    )

    # ── Page Route ────────────────────────────────────────────────────────
    @app.route("/")
    def index():
        return render_template("index.html")

    # ── Get Active Skills ──────────────────────────────────────────────────
    @app.route("/api/skills")
    def get_skills():
        try:
            skills = get_agentic_skills()
            return jsonify(skills)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── Unified Triage Pipeline Endpoint ──────────────────────────────────
    @app.route("/api/triage", methods=["POST"])
    def triage():
        email_text = ""
        email_headers = {}
        
        # Check if it's a file upload or JSON raw text
        if "eml_file" in request.files:
            file = request.files["eml_file"]
            if file.filename == "":
                return jsonify({"error": "Empty file name"}), 400
            
            raw_bytes = file.read()
            email_headers = _parse_email_headers(raw_bytes)
            email_text = _extract_body(raw_bytes)
        else:
            data = request.get_json(force=True)
            email_text = data.get("email_text", "").strip()
            email_headers = {
                "subject": "Raw Text Analysis",
                "from": "Unknown Sender",
                "to": "Recipient",
                "date": datetime.now(timezone.utc).isoformat(),
                "authentication": {"spf": "N/A", "dkim": "N/A", "dmarc": "N/A"},
                "received_hops": []
            }
            
        if not email_text or not email_text.strip():
            return jsonify({"error": "No email body text extracted or provided"}), 400

        # Define an inner async function to run the pipeline steps
        async def run_pipeline():
            # Step 1: Artifact Extraction
            iocs = extract_iocs_via_script(email_text)
            
            # Step 2: Initialize MCP server subprocess and client session
            python_exe = sys.executable
            server_script = os.path.abspath(str(PROJECT_ROOT / "mcp_server.py"))
            
            server_params = StdioServerParameters(
                command=python_exe,
                args=[server_script],
                env=dict(os.environ),
            )
            
            enriched = []
            async with stdio_client(server_params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    
                    # Step 3: Threat Intel Investigation
                    enriched = await run_threat_intel_investigation(iocs, session)
            
            # Step 4: Triage Report Generation
            report_md, risk_level = await generate_triage_report(enriched, email_headers)
            
            return {
                "headers": email_headers,
                "iocs": iocs,
                "enriched": enriched,
                "report": report_md,
                "risk_level": risk_level,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

        try:
            result = asyncio.run(run_pipeline())
            
            # Save the final report locally for reference
            try:
                (PROJECT_ROOT / "triage_report.md").write_text(result["report"], encoding="utf-8")
            except Exception as e:
                print(f"[WARN] Failed to write triage_report.md: {e}")
                
            return jsonify(result)
        except Exception as e:
            import traceback
            traceback.print_exc()
            return jsonify({"error": str(e)}), 500

    # ── Fetch History ─────────────────────────────────────────────────────
    @app.route("/api/history")
    def get_history():
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, timestamp, ioc_type, artifact, results
                FROM lookup_history
                ORDER BY timestamp DESC
                LIMIT 100
                """
            )
            rows = cursor.fetchall()
            conn.close()
            
            items = []
            for r in rows:
                items.append({
                    "id": r[0],
                    "timestamp": r[1],
                    "ioc_type": r[2],
                    "artifact": r[3],
                    "results": r[4]
                })
            return jsonify(items)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=True)
