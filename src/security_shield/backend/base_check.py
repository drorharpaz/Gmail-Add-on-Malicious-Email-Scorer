# ---------- Base Check Class: security-backend/base_check.py ---------- #
# This file defines the BaseCheck class,
# which serves as an abstract base for all security checks implemented in the backend.

from abc import ABC, abstractmethod

class BaseCheck(ABC):
    """
    Abstract Base Class for all security checks.
    Ensures that every check follows the same contract for the SecurityEngine.
    """

    @property
    @abstractmethod
    def name(self):
        """Returns a unique identifier for the check (e.g., 'IP_LINK_DETECTION')."""
        pass

    @property
    @abstractmethod
    def is_active(self):
        """Returns True if the check is ready for production."""
        pass
    
    @property
    @abstractmethod
    def description(self):
        """Returns a brief explanation of what the check validates."""
        pass

    @abstractmethod
    def run(self, email_data):
        """
        Executes the specific security logic.
        
        Args:
            email_data (dict): The full email metadata received from Gmail.
            
        Returns:
            tuple: (is_threat: bool, priority_score: int)
            - priority_score: 1-10 (10 = Veto/Critical, 3 = Medium, 0-2 = Low).
        """
        pass
