# --- Test file for URLHaus Live API Testing --- #
# This test suite validates the functionality of the URLHausCheck against the live URLHaus API.
# It uses real URLs marked as "online" from the URLHaus database to ensure that the check correctly identifies them as malicious.
# WARNING: The URLs used in this test are real malware links
# DO NOT CLICK ON THEM! Copy only the text and use it in the test data.

import pytest
from security_shield.backend.engine import SecurityEngine

"""
INSTRUCTIONS FOR TESTING:
1. Go to: https://urlhaus.abuse.ch/browse/
2. Look for URLs marked as "online".
3. Copy a few URLs and paste them into the 'malicious_urls' list below.

WARNING: 
The URLs on the website above are REAL MALWARE links. 
DO NOT CLICK ON THEM! Copy only the text.
"""

def test_url_haus_live_api():
    engine = SecurityEngine()
    
    # PASTE YOUR MALICIOUS URLs HERE
    # WARNING: DO NOT CLICK THESE LINKS IN YOUR BROWSER!
    malicious_urls = [
        "http://125.41.6.93:51971/bin.sh",                      # Online Malicious URL from URLHaus
        #"https://mod.openlogmgr.pics/c2cb43a1-3db9-486a-...",   # Online Malicious URL from URLHaus
        #"https://refid.bitflowapp.pics/73922b30-d888-4af...",   # Online Malicious URL from URLHaus
        #"http://src.openlogmgr.pics/c2cb43a1-3db9-486a-a..."   # Offline Malicious URL from URLHaus (for testing non-malicious classification)
    ]
    
    for url in malicious_urls:
        email_data = {
            "body": f"Urgent: Please update your system by clicking here: {url}",
            "sender": "security-alert@untrusted-source.com",
            "subject": "Security Update Required"
        }
        
        print(f"\n--- Testing Live URL: {url} ---")
        result = engine.execute_analysis(email_data)
        
        # Classification Logic:
        # If the URL is found and online, URLHausCheck returns priority 10.
        # The engine labels priority 9-10 as 'malicious'.
        print(f"Result Label: {result['label']} (Score: {result['score']})")
        
        # We expect it to be malicious if the URL is still active in URLHaus database
        assert result['label'] == "malicious"
        assert result['score'] == 10
