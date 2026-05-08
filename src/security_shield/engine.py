# ---------- Security Engine: src/security_shield/engine.py ---------- #
# This file defines the SecurityEngine class, which dynamically discovers
# and executes security checks from the 'checks' directory. It serves as the core
# component of the backend, orchestrating the analysis of incoming email metadata
# and determining the appropriate security label based on the results of the checks.

import os
import pkgutil
import importlib
import inspect
import datetime
from security_shield.base_check import BaseCheck

class SecurityEngine:
    def __init__(self):
        self.checks = []
        self._discover_checks()

    def _discover_checks(self):
        print(f"--- [System] Starting Automatic Check Discovery ---")
        
        # Define the path to the 'checks' package
        # Assumes 'checks' is a directory in the same folder as engine.py
        checks_path = os.path.join(os.path.dirname(__file__), 'checks')
        
        if not os.path.exists(checks_path):
            print(f"[!] Error: 'checks' directory not found at {checks_path}")
            return

        for loader, module_name, is_pkg in pkgutil.iter_modules([checks_path]):
            try:
                # The full module name should include the package path (e.g., 'security_shield.checks.ip_check')
                full_module_name = f'security_shield.checks.{module_name}'
                module = importlib.import_module(full_module_name)
                
                for name, obj in inspect.getmembers(module):
                    if inspect.isclass(obj) and issubclass(obj, BaseCheck) and obj is not BaseCheck:
                        check_instance = obj()
                        
                        if check_instance.is_active:
                            self.checks.append(check_instance)
                            print(f"[*] Registered Active Check: {check_instance.name}")
                        else:
                            print(f"[ ] Skipping Inactive Check: {name} (is_active=False)")
                            
            except Exception as e:
                # Log the error but continue with other modules to ensure maximum checks are loaded
                print(f"[!] Failed to load module {module_name}: {str(e)}")

        print(f"--- [System] Discovery Complete. {len(self.checks)} checks active. ---")

    def execute_analysis(self, email_data):
        max_priority = 0
        findings = []

        print(f"--- Analysis Started: {datetime.datetime.now()} ---")

        for check in self.checks:
            is_threat, priority = check.run(email_data)
            
            if is_threat:
                print(f"[!] Threat Detected: {check.name} (Priority: {priority})")
                findings.append({
                    "check": check.name,
                    "description": check.description,
                    "priority": priority
                })
                
                if priority > max_priority:
                    max_priority = priority
                
                if max_priority >= 10:
                    print(f"[!] Veto Triggered by {check.name}. Terminating further checks.")
                    break

        if max_priority >= 9:
            label = "malicious"
        elif 3 <= max_priority <= 8:
            label = "suspicious"
        else:
            label = "safe"

        print(f"--- Final Result: {label.upper()} (Score: {max_priority}) ---")

        return {
            "score": max_priority,
            "label": label,
            "findings": findings,
            "timestamp": str(datetime.datetime.now())
        }