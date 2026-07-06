# server.py
from mcp.server.fastmcp import FastMCP
from datetime import datetime, timedelta
import requests
import os
import subprocess
import json
import sqlite3

mcp = FastMCP("ThreatIntel_MCP")

DB_FILE = "lookups.db"  # Acts as our Zero-Parsing Shared Memory cache

def init_db():
    """
    Initializes a local SQLite database to store agent analysis history.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
                   CREATE TABLE IF NOT EXISTS  lookup_history (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   timestamp TEXT NOT NULL,
                   ioc_type TEXT NOT NULL,
                   artifact TEXT NOT NULL,
                   results TEXT NOT NULL)
                   ''')
    conn.commit()
    conn.close()

# Ensure the database exists on startup
init_db()




@mcp.tool()
def virustotal_ip_lookup(ip_addr: str) -> dict:
    """
    Queries VirusTotal for IP reputation.
    Agents should use this when investigating extracted IPv4/IPv6 addresses.
    """
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return {"error":"VT_API_KEY encironment variable is not set."}
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_addr}"

    headers = {
        "accept":"application/json",
        "x-apikey":api_key
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            # extract just the relevant fields to save LLM context window limits
            stats = data.get('data',{}).get('attributes',{}).get('last_analysis_stats',{})
            owner = data.get('data',{}).get('attributes',{}).get('as_owner','Unknown')

            return {
                "ip":ip_addr,
                "malicious_votes": stats.get('malicious',0),
                "harmless_votes": stats.get('harmless',0),
                "suspicious_votes": stats.get('suspicious',0),
                "owner":owner
            }
        else:
            return {"error":f"Failed to query VT. Status: {response.status_code}"}
        
    except Exception as e:

        return {"error":f"An error occurred during VT lookup:{str(e)}"}
    
@mcp.tool()
def whois_lookup(domain: str) -> dict:
    """Performs a WHOIS lookup on a given domain using the system `whois` command.
    Returns a dict with the raw WHOIS text or an error message.
    """
    try:
        result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15)
        return {
            "domain": domain,
            "whois_output": result.stdout,
        }
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {str(e)}"}    


@mcp.tool()
def save_lookup(ioc_type: str, artifact: str, results: str) -> dict:
    """
    Saves the threat intelligence or triage results for a specific artifact to the local database.
    Args:
        ioc_type: The type of artifact (e.g., 'ip', 'domain', 'url', 'hash', 'email_report').
        artifact: The actual value (e.g., '1.1.1.1', 'malicious-site.com').
        results: A string or stringified JSON of the analysis report/verdict to store.
    
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        timestamp = datetime.utcnow().isoformat()

        cursor.execute('''
                       INSERT INTO lookup_history (timestamp, ioc_type, artifact, results) VALUES (?,?,?,?)
                       ''', (timestamp, ioc_type.lower(), artifact, results)
                    )
        
        conn.commit()
        conn.close()

        return {"status":"success","message":f"Successfully saved record for {artifact}"}
    
    except Exception as e:
        return {"status": "error","message":f"Failed to save lookup: {str(e)}"}

@mcp.tool()

def search_lookups(query: str) -> list:
    """
    Searches the historical lookup database for matching artifacts
    or prior findings. Use this tool before performing external lookups to see
    if an entity was evaluated before.

    Args:
        query: A string search query (e.g., an IP, domain, or keyword like 'malicious').
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # SQL wildcard search across artifact value and prior result text
        cursor.execute(
            '''
            SELECT timestamp, ioc_type, artifact, results
            FROM lookup_history
            WHERE artifact LIKE ? OR results LIKE ?
            ORDER BY timestamp DESC
            ''', (f"%{query}%", f"%{query}%")
        )

        rows = cursor.fetchall()
        conn.close()


        results = []
        for row in rows:
            results.append({
                "timestamp": row[0],
                "ioc_type": row[1],
                "artifact": row[2],
                "results": row[3]
            })

        return results if results else [{"message": "No historical lookups matched your query."}]
    
    except Exception as e:
        return [{"error": f"Failed to search lookups: {str(e)}"}]
    

    
if __name__ == "__main__":
    # start the server using the default stdio transport
    mcp.run()


