# Cyber Security Triager - Architecture & Flow Walkthrough

This document outlines the architecture, components, and data flow of the **Cyber Security Triager** web application, showcasing how the sequential agentic skills pipeline operates.

---

## 1. High-Level Architecture

The application is structured into three main layers: the **Frontend Dashboard**, the **Flask Web App Controller**, and the **Model Context Protocol (MCP) Server**. A local **SQLite Cache** handles past lookup histories and acts as an agentic memory cache.

```mermaid
graph TD
    subgraph Client [Frontend UI - Browser]
        A[Dashboard Dashboard] -->|Drag & Drop EML| B(Uploader)
        C[Skills Viewer]
        D[Triage Inspector]
    end

    subgraph Controller [Flask Backend App - web/app.py]
        E[EML parser]
        F[Skills Parser]
        G[Pipeline Orchestrator]
    end

    subgraph Agents [Agentic Skills]
        H[Artifact Extractor - parse_artifacts.py]
        I[Investigator - MCP Client]
        J[Reporter - Gemini API]
    end

    subgraph OSINT [External Services]
        K[(SQLite Cache - lookups.db)]
        L[MCP Server - mcp_server.py]
        M[VirusTotal API]
        N[System WHOIS CLI]
    end

    %% Routing Hops
    A -->|GET /api/skills| F
    B -->|POST /api/triage| E
    E --> G
    G -->|Step 1| H
    G -->|Step 2| I
    G -->|Step 3| J
    I -->|Query Cache| K
    I -->|JSON RPC| L
    L -->|VT Lookup| M
    L -->|WHOIS query| N
    L -->|Save Lookup| K
    J -->|Prompt & Template| O[Gemini 2.5 Flash]
    O -->|Markdown Report| G
    G -->|JSON response| D
```

---

## 2. Sequential Pipeline Data Flow

When a security analyst uploads an `.eml` file, the backend processes it sequentially through the defined agentic skills:

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as Security Analyst
    participant Web as Web Server (app.py)
    participant Extractor as Extractor Skill
    participant MCP as MCP Client/Server
    participant DB as SQLite Cache (lookups.db)
    participant Gemini as Gemini Reporter (AI)

    Analyst->>Web: Uploads email.eml
    activate Web
    Web->>Web: Parse Email Headers & Extract Body Text
    
    Note over Web, Extractor: Step 1: Artifact Extraction
    Web->>Extractor: Pass body text via stdin (parse_artifacts.py)
    activate Extractor
    Extractor-->>Web: Return JSON of IOCs (ips, domains, urls, hashes)
    deactivate Extractor

    Note over Web, MCP: Step 2: Threat Intel Investigation
    Web->>MCP: Initialize MCP Server Subprocess & Client Session
    activate MCP
    loop For each extracted IOC
        MCP->>DB: search_lookups (Check Cache last 24h)
        alt Cache Hit
            DB-->>MCP: Return Cached Reputation
        else Cache Miss
            alt IOC is IP
                MCP->>MCP: Query VirusTotal IP Reputation Tool
            else IOC is Domain/URL
                MCP->>MCP: Run System WHOIS Lookup Tool
            end
            MCP->>DB: save_lookup (Save findings to Cache)
        end
    end
    MCP-->>Web: Return Enriched JSON (Intel & Rubric Risk Scores)
    deactivate MCP

    Note over Web, Gemini: Step 3: Triage Report Generation
    Web->>Gemini: Send Enriched JSON + report_template.md
    activate Gemini
    Gemini->>Gemini: Populate markdown fields (Executive Summary, IOC Table, Remediation Steps)
    Gemini-->>Web: Return Final Markdown Report
    deactivate Gemini

    Web-->>Analyst: Send Response (Headers, IOCs, Enriched Details, MD Report)
    deactivate Web
```

---

## 3. Core Component Breakdown

### 📂 1. Agentic Skills Definitions
The application reads **Yaml frontmatter** from the `SKILL.md` files in the project to dynamically present information on the dashboard:
*   **`artifact_extraction`**: Extracts IPs, domains, URLs, and hashes. Leverages `scripts/parse_artifacts.py`, a deterministic script that parses raw strings via optimized regex patterns.
*   **`threat_intel_investigation`**: Queries cache and external APIs. Governed by a reputational rubric mapped from VirusTotal votes and WHOIS domain ages to risk levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
*   **`triage_report_generation`**: Generates the final Incident Report utilizing `assets/report_template.md` as the template filled by Gemini.

### 🌐 2. FastMCP Server (`mcp_server.py`)
A model-context protocol server that exposes standard interfaces (tools) to the backend agent:
1.  `search_lookups(query)`: Performs SQL checks inside `lookups.db` to prevent double-querying external APIs.
2.  `virustotal_ip_lookup(ip_addr)`: Hits the VirusTotal API using the `VT_API_KEY` to collect malicious votes and owner information.
3.  `whois_lookup(domain)`: Queries domain registrar creation dates.
4.  `save_lookup(ioc_type, artifact, results)`: Commits lookup items with timestamps.

### 🎨 3. Dashboard Interface (`web/templates/index.html`)
An analyst-centric workspace styling vanilla CSS custom properties:
*   **Stepped Progress Tracker**: Visual representation of the three sequential steps lighting up as the backend finishes processing.
*   **Email Headers & Hop Map**: Decodes authentication checks (SPF/DKIM/DMARC) and renders hops sequentially.
*   **Extracted IOC Badges**: Dynamic chips displaying indicators by categories.
*   **Triage Report Canvas**: Embedded markdown report converted to rich HTML in real time with quick-action export buttons (copy markdown or download report).
