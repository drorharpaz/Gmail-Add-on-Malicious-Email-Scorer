# ---------- Security Engine: security-backend/engine.py ---------- #
# This file defines the SecurityEngine class, which dynamically discovers
# and executes security checks from the 'checks' directory.

import os
import pkgutil
import importlib
import inspect
import datetime
from base_check import BaseCheck

class SecurityEngine:
    """
    The central engine that manages and executes multiple security checks.
    It automatically discovers active checks in the 'checks' package.
    """

    def __init__(self):
        """
        Initializes the engine and triggers the automatic discovery of 
        security check modules located in the 'checks' directory.
        """
        self.checks = []
        self._discover_checks()

    def _discover_checks(self):
        """
        Dynamically scans the 'checks' directory, imports modules, 
        and instantiates classes that inherit from BaseCheck and are marked active.
        """
        print(f"--- [System] Starting Automatic Check Discovery ---")
        
        # Define the path to the 'checks' package
        # Assumes 'checks' is a directory in the same folder as engine.py
        checks_path = os.path.join(os.path.dirname(__file__), 'checks')
        
        if not os.path.exists(checks_path):
            print(f"[!] Error: 'checks' directory not found at {checks_path}")
            return

        # Iterate through all modules in the 'checks' package
        for loader, module_name, is_pkg in pkgutil.iter_modules([checks_path]):
            try:
                # Import the module dynamically (e.g., 'checks.ip_check')
                full_module_name = f'checks.{module_name}'
                module = importlib.import_module(full_module_name)
                
                # Inspect all members of the imported module
                for name, obj in inspect.getmembers(module):
                    # We are looking for:
                    # 1. Classes
                    # 2. That inherit from BaseCheck
                    # 3. That are not the BaseCheck class itself
                    if inspect.isclass(obj) and issubclass(obj, BaseCheck) and obj is not BaseCheck:
                        check_instance = obj()
                        
                        # Only register the check if the developer marked it as active
                        if check_instance.is_active:
                            self.checks.append(check_instance)
                            print(f"[*] Registered Active Check: {check_instance.name}")
                        else:
                            print(f"[ ] Skipping Inactive Check: {name} (is_active=False)")
                            
            except Exception as e:
                print(f"[!] Failed to load module {module_name}: {str(e)}")

        print(f"--- [System] Discovery Complete. {len(self.checks)} checks active. ---")

    def execute_analysis(self, email_data):
        """
        Runs all discovered active checks against the provided email data.
        
        Logic:
        - Score 9-10: Malicious (Veto)
        - Score 3-8: Suspicious
        - Score 0-2: Safe
        """
        max_priority = 0
        findings = []

        print(f"--- Analysis Started: {datetime.datetime.now()} ---")

        for check in self.checks:
            # Run the specific logic of the check
            is_threat, priority = check.run(email_data)
            
            if is_threat:
                print(f"[!] Threat Detected: {check.name} (Priority: {priority})")
                findings.append({
                    "check": check.name,
                    "description": check.description,
                    "priority": priority
                })
                
                # Maintain the highest priority found
                if priority > max_priority:
                    max_priority = priority
                
                # Veto Logic: If a priority 10 (Veto) is found, terminate analysis early
                if max_priority >= 10:
                    print(f"[!] Veto Triggered by {check.name}. Terminating further checks.")
                    break

        # Classification based on user-defined priority thresholds
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