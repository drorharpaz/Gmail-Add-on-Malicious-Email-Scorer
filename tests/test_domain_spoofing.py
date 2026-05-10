# --- Test file for Domain Spoofing Detection --- #
# This test suite validates the functionality of the DomainSpoofingCheck,
# which is designed to identify attempts to spoof high-profile brand names in email sender information.
# The tests cover various scenarios, including clear spoofing attempts, suspicious cases, and legitimate emails

import pytest
from security_shield.backend.engine import SecurityEngine
from security_shield.backend.base_check import BaseCheck

@pytest.fixture
def engine():
    """
    Fixture to provide a clean SecurityEngine instance for each test.
    This is the 'pytest way' to handle setup.
    """
    return SecurityEngine()

def test_malicious_brand_impersonation(engine):
    """
    Case: Sender uses 'PayPal' in name but a generic gmail address.
    Expect: Malicious label (10)
    """
    email_data = {
        "sender": "PayPal Official Support <urgent-fix@gmail.com>",
        "subject": "Your account is locked",
        "body": "Please click here to verify your identity."
    }
    
    result = engine.execute_analysis(email_data)
    
    assert result['label'] == "malicious"
    assert result['score'] == 10
    # Additionally, we can check that the specific check was triggered in the findings
    assert any(f['check'] == "DOMAIN_SPOOFING_DETECTION" for f in result['findings'])

def test_suspicious_bank_keyword(engine):
    """
    Case: Sender uses 'Bank' keyword from a public domain.
    Expect: Suspicious label (3)
    """
    email_data = {
        "sender": "Global Bank Security <alert@hotmail.com>",
        "subject": "New login detected",
        "body": "A login was detected from a new device."
    }
    
    result = engine.execute_analysis(email_data)
    
    assert result['label'] == "suspicious"
    assert result['score'] == 3

def test_legitimate_brand_email(engine):
    """
    Case: Sender uses 'PayPal' name and actual 'paypal.com' domain.
    Expect: Safe label (0)
    """
    email_data = {
        "sender": "PayPal <service@paypal.com>",
        "subject": "Receipt for your payment",
        "body": "You sent a payment of $50.00."
    }
    
    result = engine.execute_analysis(email_data)
    
    assert result['label'] == "safe"
    assert result['score'] == 0
