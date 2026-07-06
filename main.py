import asyncio
from pathlib import Path
import processor

async def main():
    # Load email text
    email_path = Path(__file__).parent / "extracted_email.txt"
    email_text = email_path.read_text(encoding="utf-8")

    # Run the full processing pipeline (returns dict with iocs, enriched, report, risk_level, timestamp)
    result = await processor.process_email_full(email_text)

    # Pretty‑print key sections for CLI use
    print("\n--- IOC Extraction ---")
    print(result["iocs"])
    print("\n--- Enriched IOCs ---")
    for item in result["enriched"]:
        print(item)
    print("\n--- Report ---")
    print(result["report"])
    print(f"\nRisk Level: {result['risk_level']}")
    print(f"Timestamp  : {result['timestamp']}")

    # Write the markdown report to disk for the web UI
    report_path = Path(__file__).parent / "triage_report.md"
    report_path.write_text(result["report"], encoding="utf-8")
    print(f"\n[+] Report written to {report_path}")

if __name__ == "__main__":
    asyncio.run(main())
