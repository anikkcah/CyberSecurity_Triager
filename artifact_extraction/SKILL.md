---

name: artifact-extraction

description: |
   Extracts IPs, domains, URLs and hashes from text or email 
   headers. Use when raw logs or emails need to be parsed into structured JSON. 
   Do NOT use for investigating the reputation of these artifacts.

version: 1.0.0

---



# Artifact Extraction

## Workflow

1. Pass the input text to `scripts/parse\_artifacts.py`
2. Ensure the output is a strict JSON object with arrays for ips, domains, urls and hashes.



