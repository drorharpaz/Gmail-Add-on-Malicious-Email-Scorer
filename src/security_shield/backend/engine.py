# ---------- Security Engine: src/security_shield/backend/engine.py ---------- #
# This file defines the SecurityEngine class, which dynamically discovers
# and executes security checks from the 'checks' package. It serves as the core
# component of the backend, orchestrating the analysis of incoming email metadata
# and determining the appropriate security label based on the results of the checks.

import pkgutil
import importlib
import inspect
import datetime
from security_shield.backend.base_check import BaseCheck


class SecurityEngine:
    def __init__(self):
        self.checks = []
        self._discover_checks()

    def _manual_register_fallback(self):
        """If dynamic discovery loads nothing, register known checks explicitly."""
        print("[!] Manual registration fallback: importing DomainSpoofingCheck and URLHausCheck.")
        try:
            from security_shield.checks.domain_spoofing_check import DomainSpoofingCheck
            from security_shield.checks.url_haus_check import URLHausCheck
        except ImportError as e:
            print(f"[!] Fallback import failed: {e}")
            return

        for cls in (DomainSpoofingCheck, URLHausCheck):
            try:
                inst = cls()
                if inst.is_active:
                    self.checks.append(inst)
                    print(f"[*] Fallback registered active check: {inst.name}")
            except Exception as e:
                print(f"[!] Fallback could not instantiate {cls.__name__}: {e}")

    def _discover_checks(self):
        print(f"--- [System] Starting Automatic Check Discovery ---")

        checks_path = None
        try:
            checks_pkg = importlib.import_module("security_shield.checks")
            checks_path = list(checks_pkg.__path__)
            print(f"[*] checks_path: {checks_path}")

            for _finder, module_name, is_pkg in pkgutil.iter_modules(
                checks_pkg.__path__, prefix=checks_pkg.__name__ + "."
            ):
                if is_pkg:
                    continue
                try:
                    module = importlib.import_module(module_name)
                except Exception as e:
                    print(f"[!] Failed to load module {module_name}: {str(e)}")
                    continue

                for name, obj in inspect.getmembers(module):
                    if inspect.isclass(obj) and issubclass(obj, BaseCheck) and obj is not BaseCheck:
                        check_instance = obj()

                        if check_instance.is_active:
                            self.checks.append(check_instance)
                            print(f"[*] Registered Active Check: {check_instance.name}")
                        else:
                            print(f"[ ] Skipping Inactive Check: {name} (is_active=False)")

        except ImportError as e:
            print(f"[!] Error: could not import security_shield.checks: {e}")
            print("[*] checks_path: <unavailable — package import failed>")

        print(f"[*] Dynamic discovery pass: {len(self.checks)} check(s) loaded.")

        if len(self.checks) == 0:
            self._manual_register_fallback()

        print(f"--- [System] Discovery Complete. {len(self.checks)} checks active. ---")
        print(f"[*] Final checks successfully loaded count: {len(self.checks)}")

    def execute_analysis(self, email_data):
        total_score = 0
        findings = []
        veto_triggered = False

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
                total_score += priority

                if total_score >= 10:
                    print(f"[!] Veto Triggered by {check.name}. Terminating further checks.")
                    veto_triggered = True
                    break

        if total_score >= 9 or veto_triggered:
            label = "malicious"
        elif 3 <= total_score <= 8:
            label = "suspicious"
        else:
            label = "safe"

        print(f"--- Final Result: {label.upper()} (Score: {total_score}) ---")

        return {
            "score": total_score,
            "label": label,
            "findings": findings,
            "timestamp": str(datetime.datetime.now())
        }
