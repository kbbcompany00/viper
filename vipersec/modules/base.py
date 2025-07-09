"""
Base class for security testing modules
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any
import logging

from ..core.config import Target
from ..core.scanner import SecurityScanner


class BaseModule(ABC):
    """Base class for all security testing modules"""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.logger = logging.getLogger(f"vipersec.modules.{name}")
        
        # Module statistics
        self.stats = {
            'requests_made': 0,
            'vulnerabilities_found': 0,
            'payloads_tested': 0
        }
    
    @abstractmethod
    async def scan(self, target: Target, scanner: SecurityScanner) -> Dict[str, Any]:
        """
        Perform security scan on target
        
        Args:
            target: Target configuration
            scanner: HTTP scanner instance
            
        Returns:
            Dictionary containing scan results
        """
        pass
    
    def create_vulnerability(
        self,
        title: str,
        severity: str,
        description: str,
        evidence: Dict[str, Any],
        recommendation: str = "",
        cwe_id: str = "",
        owasp_category: str = ""
    ) -> Dict[str, Any]:
        """Create standardized vulnerability report"""
        
        return {
            'id': f"{self.name}_{len(self.get_vulnerabilities()) + 1}",
            'module': self.name,
            'title': title,
            'severity': severity.upper(),
            'description': description,
            'evidence': evidence,
            'recommendation': recommendation,
            'cwe_id': cwe_id,
            'owasp_category': owasp_category,
            'timestamp': None  # Will be set by engine
        }
    
    def get_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Get vulnerabilities found by this module"""
        return getattr(self, '_vulnerabilities', [])
    
    def add_vulnerability(self, vulnerability: Dict[str, Any]):
        """Add vulnerability to module results"""
        if not hasattr(self, '_vulnerabilities'):
            self._vulnerabilities = []
        
        self._vulnerabilities.append(vulnerability)
        self.stats['vulnerabilities_found'] += 1
    
    def get_statistics(self) -> Dict[str, int]:
        """Get module statistics"""
        return self.stats.copy()


class PayloadModule(BaseModule):
    """Base class for payload-based testing modules"""
    
    def __init__(self, name: str, description: str, payloads: List[str] = None):
        super().__init__(name, description)
        self.payloads = payloads or []
    
    async def test_payloads(
        self,
        target: Target,
        scanner: SecurityScanner,
        parameter: str,
        method: str = 'GET'
    ) -> List[Dict[str, Any]]:
        """Test all payloads against a parameter"""
        
        results = await scanner.test_multiple_payloads(
            target, self.payloads, parameter, method
        )
        
        self.stats['payloads_tested'] += len(self.payloads)
        self.stats['requests_made'] += len(results)
        
        return results
    
    @abstractmethod
    def analyze_response(self, result: Dict[str, Any]) -> bool:
        """
        Analyze response to determine if vulnerability exists
        
        Args:
            result: Response data from payload test
            
        Returns:
            True if vulnerability detected, False otherwise
        """
        pass