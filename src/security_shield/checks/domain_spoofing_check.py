# --------- Domain Spoofing Check: checks/domain_spoofing_check.py --------- #
# This file implements the DomainSpoofingCheck class, which detects attempts to spoof
# high-profile brand names in the sender's display name while using an unrelated email domain.

from security_shield.backend.base_check import BaseCheck

class DomainSpoofingCheck(BaseCheck):
    """
    Checks if a high-profile brand name is used in the sender's display name
    while the actual email address originates from an unrelated domain.
    """

    @property
    def name(self):
        return "DOMAIN_SPOOFING_DETECTION"

    @property
    def description(self):
        return "Detects inconsistencies between the sender's display name and their actual email domain."

    @property
    def is_active(self):
        return True

    def run(self, email_data):
        # The 'sender' field usually looks like: "PayPal Support <scammer@gmail.com>"
        sender_full = email_data.get('sender', '').lower()
        
        # A list of high-profile brands that are commonly spoofed
        # In a production system, this could be loaded from a database or external list
        trusted_brands = {
            "paypal": "paypal.com",
            "google": "google.com",
            "microsoft": "microsoft.com",
            "apple": "apple.com",
            "netflix": "netflix.com",
            "bank": None, # 'Bank' in name is generally suspicious if not from a known bank domain
            "security": None
        }

        # Check if any brand name appears in the display name
        for brand, trusted_domain in trusted_brands.items():
            if brand in sender_full:
                # If a trusted domain is defined, verify the email ends with it
                # Example: If "paypal" is in the name, the email MUST contain "@paypal.com"
                if trusted_domain and (f"@{trusted_domain}" not in sender_full):
                    # Clear spoofing attempt found
                    return True, 10 # VETO!
                
                # Special case: Generic terms like 'Bank' or 'Security' coming from public domains
                if not trusted_domain:
                    public_domains = ['@gmail.com', '@outlook.com', '@yahoo.com', '@hotmail.com']
                    if any(pub in sender_full for pub in public_domains):
                        return True, 3 # suspicious, but not a hard Veto
        
        return False, 0
