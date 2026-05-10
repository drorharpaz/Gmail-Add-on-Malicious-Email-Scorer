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
        
        # High-profile brands (keyword in display name -> expected From domain).
        # None = generic bait terms: flag only when combined with consumer webmail below.
        # In production, load from config/DB and tune for your tenant.
        trusted_brands = {
            # Payments & commerce
            "paypal": "paypal.com",
            "stripe": "stripe.com",
            "square": "squareup.com",
            "venmo": "venmo.com",
            "zelle": "zellepay.com",
            # Big tech & workspace
            "google": "google.com",
            "gmail": "google.com",
            "microsoft": "microsoft.com",
            "outlook": "microsoft.com",
            "apple": "apple.com",
            "icloud": "icloud.com",
            "amazon": "amazon.com",
            "aws": "amazon.com",
            "meta": "meta.com",
            "facebook": "meta.com",
            "instagram": "meta.com",
            "whatsapp": "whatsapp.com",
            "linkedin": "linkedin.com",
            "twitter": "x.com",
            "x.com": "x.com",
            "adobe": "adobe.com",
            "dropbox": "dropbox.com",
            "zoom": "zoom.us",
            "salesforce": "salesforce.com",
            "oracle": "oracle.com",
            "samsung": "samsung.com",
            "sony": "sony.com",
            # Streaming & entertainment
            "netflix": "netflix.com",
            "spotify": "spotify.com",
            "hulu": "hulu.com",
            "disney": "disney.com",
            "playstation": "playstation.com",
            "xbox": "xbox.com",
            "steam": "steampowered.com",
            "epic games": "epicgames.com",
            # Shipping & logistics
            "dhl": "dhl.com",
            "fedex": "fedex.com",
            "ups": "ups.com",
            "usps": "usps.com",
            # US & global banks / cards (display-name spoofing)
            "chase": "chase.com",
            "jpmorgan": "jpmorgan.com",
            "bank of america": "bankofamerica.com",
            "wells fargo": "wellsfargo.com",
            "citi": "citi.com",
            "citibank": "citi.com",
            "capital one": "capitalone.com",
            "amex": "americanexpress.com",
            "american express": "americanexpress.com",
            "discover": "discover.com",
            "barclays": "barclays.com",
            "hsbc": "hsbc.com",
            "santander": "santander.com",
            "deutsche bank": "db.com",
            "ing bank": "ing.com",
            "nubank": "nubank.com.br",
            # Crypto (often spoofed)
            "coinbase": "coinbase.com",
            "binance": "binance.com",
            "kraken": "kraken.com",
            "crypto.com": "crypto.com",
            # Government / tax (impersonation)
            "irs": "irs.gov",
            "hmrc": "gov.uk",
            "gov.uk": "gov.uk",
            # Generic high-risk bait (webmail + these words in display name)
            "bank": None,
            "security": None,
            "invoice": None,
            "billing": None,
            "payment notice": None,
            "account alert": None,
            "account suspended": None,
            "verify account": None,
            "fraud alert": None,
            "package": None,
            "delivery": None,
            "shipping": None,
            "payroll": None,
            "hr department": None,
            "it department": None,
            "help desk": None,
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
                    public_domains = [
                        '@gmail.com',
                        '@googlemail.com',
                        '@outlook.com',
                        '@hotmail.com',
                        '@live.com',
                        '@msn.com',
                        '@yahoo.com',
                        '@ymail.com',
                        '@icloud.com',
                        '@me.com',
                        '@mac.com',
                        '@protonmail.com',
                        '@proton.me',
                        '@aol.com',
                        '@gmx.com',
                        '@mail.com',
                    ]
                    if any(pub in sender_full for pub in public_domains):
                        return True, 3 # suspicious, but not a hard Veto
        
        return False, 0
