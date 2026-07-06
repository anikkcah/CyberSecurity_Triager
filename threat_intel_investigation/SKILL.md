---

name: threat-intel-investigation

description: |

  Queries external databases (VirusTotal, Whois) to determine artifact reputation.
  Use when you have a list of IOCs and need risk scores or vendor flags. 
  Do NOT use for initial extraction or final reporting.

version: 1.0.0

allowed-tools: [mcp_virustotal_ip, mcp_urlscan, mcp_whois]

---



# Threat Intel Investigation

## Workflow

1. Check the local cache (last 24 hours) via `search_lookups` before calling APIs.
2. Query the allowed tools for any new artifacts.
3. Consult the `references/reputation_rubric.md` to map the tool output to a specific level.
4. Append the findings to the artifact's `threat_intel` object.

