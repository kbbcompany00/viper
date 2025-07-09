"""
AI-powered response classification for vulnerability detection
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
import re

from ..core.config import AIConfig


class ResponseClassifier:
    """AI-powered response classifier for vulnerability detection"""
    
    def __init__(self, config: AIConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize models (simplified - in practice would load actual ML models)
        self.models_loaded = False
        self._load_models()
    
    def _load_models(self):
        """Load AI/ML models"""
        try:
            # In a real implementation, this would load actual models
            # For now, we'll use rule-based classification
            self.models_loaded = True
            self.logger.info("AI models loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to load AI models: {e}")
            self.models_loaded = False
    
    async def classify_response(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify response for vulnerability indicators
        
        Args:
            response_data: Response data to classify
            
        Returns:
            Classification results
        """
        
        if not self.models_loaded:
            return {'classification': 'unknown', 'confidence': 0.0}
        
        content = response_data.get('content', '')
        status_code = response_data.get('status_code', 200)
        headers = response_data.get('headers', {})
        
        # Perform classification
        classification_result = {
            'vulnerability_type': None,
            'confidence': 0.0,
            'indicators': [],
            'severity': 'info',
            'explanation': ''
        }
        
        # SQL Injection classification
        sqli_result = await self._classify_sqli(content, status_code)
        if sqli_result['confidence'] > classification_result['confidence']:
            classification_result.update(sqli_result)
        
        # XSS classification
        xss_result = await self._classify_xss(content, status_code)
        if xss_result['confidence'] > classification_result['confidence']:
            classification_result.update(xss_result)
        
        # Error-based classification
        error_result = await self._classify_errors(content, status_code, headers)
        if error_result['confidence'] > classification_result['confidence']:
            classification_result.update(error_result)
        
        return classification_result
    
    async def _classify_sqli(self, content: str, status_code: int) -> Dict[str, Any]:
        """Classify SQL injection indicators"""
        
        sqli_patterns = [
            (r'you have an error in your sql syntax', 0.9, 'MySQL syntax error'),
            (r'warning.*mysql_', 0.8, 'MySQL warning'),
            (r'ora-\d{5}', 0.9, 'Oracle error'),
            (r'postgresql.*error', 0.8, 'PostgreSQL error'),
            (r'microsoft ole db provider', 0.7, 'MSSQL error'),
            (r'sqlite.*exception', 0.8, 'SQLite error'),
            (r'sql.*syntax.*error', 0.7, 'Generic SQL syntax error'),
            (r'unclosed quotation mark', 0.6, 'SQL quotation error')
        ]
        
        indicators = []
        max_confidence = 0.0
        
        content_lower = content.lower()
        
        for pattern, confidence, description in sqli_patterns:
            if re.search(pattern, content_lower):
                indicators.append(description)
                max_confidence = max(max_confidence, confidence)
        
        if max_confidence > 0.5:
            return {
                'vulnerability_type': 'sql_injection',
                'confidence': max_confidence,
                'indicators': indicators,
                'severity': 'critical' if max_confidence > 0.8 else 'high',
                'explanation': f'SQL injection detected with {len(indicators)} indicators'
            }
        
        return {'confidence': 0.0}
    
    async def _classify_xss(self, content: str, status_code: int) -> Dict[str, Any]:
        """Classify XSS indicators"""
        
        xss_patterns = [
            (r'<script[^>]*>.*?alert.*?</script>', 0.9, 'Script tag with alert'),
            (r'<img[^>]*onerror[^>]*>', 0.8, 'Image with onerror handler'),
            (r'<svg[^>]*onload[^>]*>', 0.8, 'SVG with onload handler'),
            (r'javascript:.*?alert', 0.7, 'JavaScript protocol with alert'),
            (r'on\w+\s*=.*?alert', 0.6, 'Event handler with alert')
        ]
        
        indicators = []
        max_confidence = 0.0
        
        for pattern, confidence, description in xss_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                indicators.append(description)
                max_confidence = max(max_confidence, confidence)
        
        if max_confidence > 0.5:
            return {
                'vulnerability_type': 'xss',
                'confidence': max_confidence,
                'indicators': indicators,
                'severity': 'high' if max_confidence > 0.7 else 'medium',
                'explanation': f'XSS detected with {len(indicators)} indicators'
            }
        
        return {'confidence': 0.0}
    
    async def _classify_errors(self, content: str, status_code: int, headers: Dict[str, str]) -> Dict[str, Any]:
        """Classify general error conditions"""
        
        error_patterns = [
            (r'stack trace', 0.7, 'Stack trace exposed'),
            (r'internal server error', 0.6, 'Internal server error'),
            (r'database.*error', 0.8, 'Database error'),
            (r'exception.*at.*line', 0.7, 'Exception with line number'),
            (r'fatal error', 0.8, 'Fatal error'),
            (r'warning.*in.*on line', 0.6, 'PHP warning with line number')
        ]
        
        indicators = []
        max_confidence = 0.0
        
        content_lower = content.lower()
        
        # Check status code
        if status_code >= 500:
            indicators.append(f'HTTP {status_code} error')
            max_confidence = 0.5
        
        # Check content patterns
        for pattern, confidence, description in error_patterns:
            if re.search(pattern, content_lower):
                indicators.append(description)
                max_confidence = max(max_confidence, confidence)
        
        # Check headers for error indicators
        server_header = headers.get('server', '').lower()
        if 'error' in server_header:
            indicators.append('Error in server header')
            max_confidence = max(max_confidence, 0.4)
        
        if max_confidence > 0.3:
            return {
                'vulnerability_type': 'information_disclosure',
                'confidence': max_confidence,
                'indicators': indicators,
                'severity': 'medium' if max_confidence > 0.6 else 'low',
                'explanation': f'Information disclosure detected with {len(indicators)} indicators'
            }
        
        return {'confidence': 0.0}
    
    async def generate_insights(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate AI insights from vulnerability data"""
        
        if not vulnerabilities:
            return {
                'summary': 'No vulnerabilities detected',
                'recommendations': [],
                'risk_score': 0.0
            }
        
        # Analyze vulnerability patterns
        vuln_types = {}
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('module', 'unknown')
            severity = vuln.get('severity', 'info').lower()
            
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Calculate risk score
        risk_score = (
            severity_counts['critical'] * 10 +
            severity_counts['high'] * 7 +
            severity_counts['medium'] * 4 +
            severity_counts['low'] * 2 +
            severity_counts['info'] * 1
        ) / max(len(vulnerabilities), 1)
        
        # Generate recommendations
        recommendations = []
        
        if 'sqli' in vuln_types:
            recommendations.append("Implement parameterized queries to prevent SQL injection")
        
        if 'xss' in vuln_types:
            recommendations.append("Implement proper input validation and output encoding")
        
        if 'csrf' in vuln_types:
            recommendations.append("Implement CSRF tokens for all state-changing operations")
        
        if 'auth' in vuln_types:
            recommendations.append("Strengthen authentication mechanisms and password policies")
        
        if severity_counts['critical'] > 0:
            recommendations.append("Address critical vulnerabilities immediately")
        
        # Generate summary
        total_vulns = len(vulnerabilities)
        most_common_type = max(vuln_types.items(), key=lambda x: x[1])[0] if vuln_types else 'none'
        
        summary = f"Found {total_vulns} vulnerabilities. Most common type: {most_common_type}. "
        summary += f"Risk score: {risk_score:.1f}/10"
        
        return {
            'summary': summary,
            'vulnerability_types': vuln_types,
            'severity_distribution': severity_counts,
            'risk_score': risk_score,
            'recommendations': recommendations,
            'total_vulnerabilities': total_vulns
        }
    
    async def enhance_vulnerability(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance vulnerability with AI analysis"""
        
        if not self.models_loaded:
            return vulnerability
        
        # Add AI-generated remediation advice
        vuln_type = vulnerability.get('module', '')
        severity = vulnerability.get('severity', 'info').lower()
        
        enhanced_vuln = vulnerability.copy()
        
        # Generate detailed remediation
        remediation = self._generate_remediation(vuln_type, vulnerability)
        if remediation:
            enhanced_vuln['ai_remediation'] = remediation
        
        # Add risk assessment
        risk_factors = self._assess_risk_factors(vulnerability)
        enhanced_vuln['risk_factors'] = risk_factors
        
        # Add exploit likelihood
        exploit_likelihood = self._assess_exploit_likelihood(vulnerability)
        enhanced_vuln['exploit_likelihood'] = exploit_likelihood
        
        return enhanced_vuln
    
    def _generate_remediation(self, vuln_type: str, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed remediation advice"""
        
        remediation_templates = {
            'xss': {
                'immediate': [
                    'Sanitize all user input before processing',
                    'Implement Content Security Policy (CSP)',
                    'Use output encoding for dynamic content'
                ],
                'long_term': [
                    'Implement automated security testing in CI/CD',
                    'Train developers on secure coding practices',
                    'Regular security code reviews'
                ]
            },
            'sqli': {
                'immediate': [
                    'Use parameterized queries/prepared statements',
                    'Validate and sanitize all input',
                    'Apply principle of least privilege to database accounts'
                ],
                'long_term': [
                    'Implement database activity monitoring',
                    'Regular database security audits',
                    'Use ORM frameworks with built-in protection'
                ]
            },
            'csrf': {
                'immediate': [
                    'Implement CSRF tokens for all forms',
                    'Verify referrer headers',
                    'Use SameSite cookie attributes'
                ],
                'long_term': [
                    'Implement double-submit cookie pattern',
                    'Regular security testing of forms',
                    'User education on CSRF risks'
                ]
            }
        }
        
        return remediation_templates.get(vuln_type, {
            'immediate': ['Review and validate input handling'],
            'long_term': ['Implement comprehensive security testing']
        })
    
    def _assess_risk_factors(self, vulnerability: Dict[str, Any]) -> List[str]:
        """Assess risk factors for vulnerability"""
        
        risk_factors = []
        
        severity = vulnerability.get('severity', 'info').lower()
        if severity in ['critical', 'high']:
            risk_factors.append('High severity impact')
        
        evidence = vulnerability.get('evidence', {})
        if 'payload' in evidence:
            risk_factors.append('Exploitable with simple payload')
        
        if 'response_status' in evidence and evidence['response_status'] == 200:
            risk_factors.append('Successful exploitation confirmed')
        
        vuln_type = vulnerability.get('module', '')
        if vuln_type in ['sqli', 'xss']:
            risk_factors.append('Common attack vector')
        
        return risk_factors
    
    def _assess_exploit_likelihood(self, vulnerability: Dict[str, Any]) -> str:
        """Assess likelihood of exploitation"""
        
        severity = vulnerability.get('severity', 'info').lower()
        vuln_type = vulnerability.get('module', '')
        
        if severity == 'critical' and vuln_type in ['sqli', 'auth']:
            return 'Very High'
        elif severity == 'high':
            return 'High'
        elif severity == 'medium':
            return 'Medium'
        elif severity == 'low':
            return 'Low'
        else:
            return 'Very Low'