import json
import re
import sys

def extract_artifacts(input_text):
    """
    Strict deterministic parser to extract IOCs from raw text or logs.
    This shifts intelligence 'left' into code, reducing context debt [1].
    """
    
    # Regex patterns for deterministic extraction
    patterns = {
        "ips": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        "domains": r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
        "urls": r'https?://[^\s<>"]+|ftp://[^\s<>"]+',
        "hashes": r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b'
    }

    results = {
        "ips": [],
        "domains": [],
        "urls": [],
        "hashes": []
    }

    # Perform extraction across all categories
    for category, pattern in patterns.items():
        # Use set to automatically deduplicate within the script
        found = set(re.findall(pattern, input_text, re.IGNORECASE))
        results[category] = sorted(list(found))

    return results

if __name__ == "__main__":
    # Read from stdin to support non-interactive access [7, 8]
    try:
        raw_data = sys.stdin.read()
        if not raw_data:
            print(json.dumps({"ips": [], "domains": [], "urls": [], "hashes": []}))
            sys.exit(0)
            
        extracted_data = extract_artifacts(raw_data)
        
        # Return ONLY valid JSON as required by the Extractor role [9]
        print(json.dumps(extracted_data, indent=2))
        
    except Exception as e:
        # Prevent leaking system paths in error messages for security
        print(json.dumps({"error": "Failed to parse artifacts"}))
        sys.exit(1)