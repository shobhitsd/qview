"""
QView Base Scanner Interface
"""

from abc import ABC, abstractmethod
from typing import List
from core.models import CryptoFinding


class BaseScanner(ABC):
    """Abstract Base Class for all QView Discovery Scanners."""

    @abstractmethod
    def scan_file(self, file_path: str) -> List[CryptoFinding]:
        """Scan an individual file and return cryptographic findings."""
        pass
