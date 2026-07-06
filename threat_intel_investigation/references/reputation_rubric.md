Reputation Rubric: Risk Scoring Definitions



This document provides the logic and rationale for determining artifact risk levels. Give the reason, not just the rule, to help the model generalize across different OSINT tool outputs.



Risk Level: LOW



* Definition: The artifact shows no signs of malicious intent and has a stable history.
* Criteria:

&#x09;- Vendor Flags: 0 detections across all queried engines (e.g., VirusTotal, URLScan)

&#x09;- Registration Age: Domain/IP has been active for > 1 year with stable Whois data

&#x09;- Context: Commonly known legitimate services or infrastructure with no recent reported abuse.



Risk Level: MEDIUM



* Definition: The artifact is suspicious but lacks conclusive evidence of a current threat.
* Registration Age: New domain/IP registered within the last 30-90 days.
* Rationale: Young domains are often used for "burnable" infrastructure. While not inherently malicious, their lack of history warrants caution.



Risk Level: HIGH



* Definition: There is a high probability that the artifact is associated with malicious activity.
* Criteria: 

&#x09;- Vendor Flags: 4-10 detections from reputable security vendors.

&#x09;- Registration Age: Extremely young (registered in the last < 30 days) or uses a privacy-protected registrar often associated with threat actors.

&#x09;- Rationale: Multiple independent vendor flags combined with a lack of "longevity" suggest active exploitation or phishing infrastructure.



Risk Level: CRITICAL



* Definition: Confirmed active threat requiring immediate SOC response.
* Criteria: 

&#x09;- Vendor Flags: >10 detections OR specific flags for "Malware","C2", or "Ransomware"

&#x09;- Registration Age: Often "Domain Generation Algorithm" (DGA) patterns or registered within the last 48 hours.

&#x09;- Context: Direct association with known campaign indicators or active malware delivery URLs.

