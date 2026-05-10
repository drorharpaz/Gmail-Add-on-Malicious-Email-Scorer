import requests
import os
import io
import csv
from dotenv import load_dotenv
from security_shield.backend.base_check import BaseCheck

# Load environment variables from .env file
load_dotenv()

class URLHausCheck(BaseCheck):
    @property
    def name(self):
        return "URL_HAUS_LOCAL_DB"

    @property
    def is_active(self):
        return True
    
    @property
    def description(self):
        return "Matches URLs against a locally cached URLHaus active threat list."

    def __init__(self):
        super().__init__()
        self.auth_key = os.getenv("URLHAUS_AUTH_KEY")
        # The endpoint to download the recent active URLs in CSV format
        self.download_url = f"https://urlhaus-api.abuse.ch/v2/files/exports/{self.auth_key}/recent.csv"
        self.malicious_set = set()
        self._update_blacklist()

    def _update_blacklist(self):
        """Downloads the latest CSV dump and stores URLs in a set."""
        print(f"[*] Updating URLHaus blacklist...")
        try:
            response = requests.get(self.download_url, timeout=15)
            if response.status_code == 200:
                # Use io.StringIO to read the text as a file
                csv_reader = csv.reader(io.StringIO(response.text))
                for row in csv_reader:
                    # Skip comments and header rows (starting with #)
                    if row and not row[0].startswith("#"):
                        # Usually, the URL is in the 3rd column (index 2)
                        # but check URLHaus documentation for CSV structure
                        if len(row) > 2:
                            self.malicious_set.add(row[2].strip())
                print(f"[*] URLHaus database updated: {len(self.malicious_set)} active threats loaded.")
            else:
                print(f"[!] Failed to download URLHaus dump. Status: {response.status_code}")
        except Exception as e:
            print(f"[!] Error updating blacklist: {e}")

    def run(self, email_data):
        """Quickly check if any extracted URL exists in our local set."""
        import re
        body = email_data.get("body", "")
        urls = re.findall(r'(https?://[^\s>]+)', body)
        
        for url in urls:
            clean_url = url.strip('.,()[]{}"\'')
            if clean_url in self.malicious_set:
                print(f"[!] Match Found in Local Blacklist: {clean_url}")
                return True, 10
                
        return False, 0