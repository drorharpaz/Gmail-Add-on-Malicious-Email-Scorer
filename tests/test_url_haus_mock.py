# --- Test file for URLHaus Mock API Testing --- #
# This test suite validates the functionality of the URLHausCheck logic without making real internet requests.
# It uses 'requests_mock' to simulate a positive response from the API, allowing us to test the check's behavior in a controlled environment.
# This is crucial for ensuring that our tests are reliable and do not depend on external factors like network connectivity or changes in the URLHaus database.

import pytest
import os
from dotenv import load_dotenv
from security_shield.engine import SecurityEngine

"""
This test validates the URLHausCheck logic WITHOUT making real internet requests.
It uses 'requests_mock' to simulate a positive response from the API.
"""

load_dotenv()

def test_url_haus_logic_with_mock(requests_mock):
    # Mocking the URLHaus API response with a fake CSV content
    auth_key = os.getenv("URLHAUS_AUTH_KEY")
    if not auth_key:
        pytest.fail("URLHAUS_AUTH_KEY not found in environment variables")

    fake_csv_content = (
        "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
        "1,2026-05-09,http://fake-malicious-site.com/virus.exe,online,active,malware_download,test,link,dror"
    )
    
    # The URLHausCheck will attempt to download the recent CSV using the auth key.
    # We need to mock that specific URL. The auth key in the URL should match the
    requests_mock.get(
        f"https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv", 
        text=fake_csv_content
    )

    # Initialize the Security Engine (which will load the URLHausCheck and update its blacklist)
    engine = SecurityEngine()
    
    # Create test email data containing the malicious URL that we mocked in the CSV
    fake_url = "http://fake-malicious-site.com/virus.exe"
    email_data = {
        "body": f"Click here: {fake_url}",
        "sender": "scammer@fake.com"
    }
    
    # Run the analysis and print results
    print(f"\n--- Testing URLHaus with LOCAL DB Mock ---")
    result = engine.execute_analysis(email_data)
    
    # Assertions
    assert result['score'] == 10
    assert result['label'] == "malicious"
    print(f"Mock test successful! Detected via local blacklist.")