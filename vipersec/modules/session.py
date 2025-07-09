"""
Session management testing module
"""

from typing import Dict, List, Any, Optional
import re

from .base import BaseModule
from ..core.config import Target
from ..core.scanner import SecurityScanner


class SessionModule(BaseModule):
    """Session management vulnerability detection module"""
    
    def __init__(self):
        super().__init__(
            name="session",
            description="Session management security testing"
        )
    
    async def scan(self, target: Target, scanner: SecurityScanner) -> Dict[str, Any]:
        """Scan for session management vulnerabilities"""
        
        self.logger.info(f"Starting session management scan for {target.url}")
        
        results = {
            'module': self.name,
            'vulnerabilities': [],
            'requests_made': 0
        }
        
        async with scanner:
            # Test session cookie security
            await self._test_session_cookie_security(target, scanner)
            
            # Test session timeout
            await self._test_session_timeout(target, scanner)
            
            # Test session invalidation
            await self._test_session_invalidation(target, scanner)
            
            # Test concurrent sessions
            await self._test_concurrent_sessions(target, scanner)
        
        # Compile results
        results['vulnerabilities'] = self.get_vulnerabilities()
        results['requests_made'] = self.stats['requests_made']
        
        self.logger.info(f"Session management scan completed. Found {len(results['vulnerabilities'])} vulnerabilities")
        
        return results
    
    async def _test_session_cookie_security(self, target: Target, scanner: SecurityScanner):
        """Test session cookie security attributes"""
        
        response = await scanner._make_request('GET', target.url, target)
        self.stats['requests_made'] += 1
        
        if not response:
            return
        
        # Analyze session cookies
        for cookie in response.cookies:
            if self._is_session_cookie(cookie.name):
                issues = []
                
                # Check Secure flag
                if not cookie.secure and target.url.startswith('https'):
                    issues.append("Missing Secure flag")
                
                # Check HttpOnly flag
                if not hasattr(cookie, 'httponly') or not cookie.httponly:
                    issues.append("Missing HttpOnly flag")
                
                # Check SameSite attribute
                samesite = getattr(cookie, 'samesite', None)
                if not samesite or samesite.lower() == 'none':
                    issues.append("Missing or weak SameSite attribute")
                
                # Check cookie value entropy
                if len(cookie.value) < 16:
                    issues.append("Low entropy session ID")
                
                if issues:
                    vulnerability = self.create_vulnerability(
                        title=f"Insecure Session Cookie: {cookie.name}",
                        severity="MEDIUM",
                        description=f"Session cookie has security issues: {', '.join(issues)}",
                        evidence={
                            'cookie_name': cookie.name,
                            'cookie_value': cookie.value[:10] + "...",
                            'secure': cookie.secure,
                            'httponly': getattr(cookie, 'httponly', False),
                            'samesite': samesite,
                            'issues': issues
                        },
                        recommendation="Set Secure, HttpOnly, and SameSite attributes on session cookies",
                        cwe_id="CWE-614",
                        owasp_category="A07:2021 – Identification and Authentication Failures"
                    )
                    
                    self.add_vulnerability(vulnerability)
    
    async def _test_session_timeout(self, target: Target, scanner: SecurityScanner):
        """Test session timeout mechanisms"""
        
        # This is a simplified test - in practice, you'd need to wait for actual timeout
        response = await scanner._make_request('GET', target.url, target)
        self.stats['requests_made'] += 1
        
        if not response:
            return
        
        # Check for session timeout configuration in response headers or content
        cache_control = response.headers.get('cache-control', '').lower()
        expires = response.headers.get('expires', '')
        
        # Look for session timeout indicators
        if 'no-cache' not in cache_control and 'no-store' not in cache_control:
            vulnerability = self.create_vulnerability(
                title="Missing Cache Control Headers",
                severity="LOW",
                description="Response lacks proper cache control headers for session management",
                evidence={
                    'cache_control': cache_control,
                    'expires': expires,
                    'headers': dict(response.headers)
                },
                recommendation="Implement proper cache control headers (no-cache, no-store)",
                cwe_id="CWE-525",
                owasp_category="A07:2021 – Identification and Authentication Failures"
            )
            
            self.add_vulnerability(vulnerability)
    
    async def _test_session_invalidation(self, target: Target, scanner: SecurityScanner):
        """Test session invalidation on logout"""
        
        # Look for logout functionality
        response = await scanner._make_request('GET', target.url, target)
        self.stats['requests_made'] += 1
        
        if not response:
            return
        
        # Search for logout links/forms
        logout_urls = self._find_logout_urls(response.text)
        
        for logout_url in logout_urls:
            # Test logout functionality
            logout_response = await scanner._make_request('GET', logout_url, target)
            self.stats['requests_made'] += 1
            
            if logout_response:
                # Check if session cookies are invalidated
                session_cookies_cleared = self._check_session_cookies_cleared(logout_response)
                
                if not session_cookies_cleared:
                    vulnerability = self.create_vulnerability(
                        title="Session Not Invalidated on Logout",
                        severity="MEDIUM",
                        description=f"Session cookies not properly cleared on logout at {logout_url}",
                        evidence={
                            'logout_url': logout_url,
                            'response_status': logout_response.status_code,
                            'cookies_after_logout': [
                                {'name': c.name, 'value': c.value[:10] + "..."}
                                for c in logout_response.cookies
                                if self._is_session_cookie(c.name)
                            ]
                        },
                        recommendation="Properly invalidate session cookies on logout",
                        cwe_id="CWE-613",
                        owasp_category="A07:2021 – Identification and Authentication Failures"
                    )
                    
                    self.add_vulnerability(vulnerability)
    
    async def _test_concurrent_sessions(self, target: Target, scanner: SecurityScanner):
        """Test for concurrent session vulnerabilities"""
        
        # This is a simplified test - would need actual authentication in practice
        
        # Get initial session
        response1 = await scanner._make_request('GET', target.url, target)
        self.stats['requests_made'] += 1
        
        if not response1:
            return
        
        session1_cookies = {c.name: c.value for c in response1.cookies if self._is_session_cookie(c.name)}
        
        # Get second session
        response2 = await scanner._make_request('GET', target.url, target)
        self.stats['requests_made'] += 1
        
        if not response2:
            return
        
        session2_cookies = {c.name: c.value for c in response2.cookies if self._is_session_cookie(c.name)}
        
        # Check if both sessions are valid simultaneously
        if session1_cookies and session2_cookies:
            # Test if first session is still valid after second session creation
            response_test = await scanner._make_request(
                'GET', target.url, target, cookies=session1_cookies
            )
            self.stats['requests_made'] += 1
            
            if response_test and response_test.status_code == 200:
                # Both sessions appear to be valid - this might indicate concurrent session issue
                # Note: This is a basic check and would need more sophisticated testing in practice
                
                vulnerability = self.create_vulnerability(
                    title="Potential Concurrent Session Issue",
                    severity="INFO",
                    description="Multiple sessions may be allowed concurrently",
                    evidence={
                        'session1_cookies': list(session1_cookies.keys()),
                        'session2_cookies': list(session2_cookies.keys()),
                        'both_sessions_valid': True
                    },
                    recommendation="Consider implementing session management controls",
                    cwe_id="CWE-384",
                    owasp_category="A07:2021 – Identification and Authentication Failures"
                )
                
                self.add_vulnerability(vulnerability)
    
    def _is_session_cookie(self, cookie_name: str) -> bool:
        """Check if cookie is likely a session cookie"""
        
        session_patterns = [
            r'session',
            r'jsessionid',
            r'phpsessid',
            r'aspsessionid',
            r'sid',
            r'auth',
            r'token'
        ]
        
        cookie_lower = cookie_name.lower()
        
        for pattern in session_patterns:
            if re.search(pattern, cookie_lower):
                return True
        
        return False
    
    def _find_logout_urls(self, html_content: str) -> List[str]:
        """Find logout URLs in HTML content"""
        
        logout_patterns = [
            r'href=["\']([^"\']*logout[^"\']*)["\']',
            r'href=["\']([^"\']*signout[^"\']*)["\']',
            r'href=["\']([^"\']*sign-out[^"\']*)["\']',
            r'action=["\']([^"\']*logout[^"\']*)["\']'
        ]
        
        logout_urls = []
        
        for pattern in logout_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            logout_urls.extend(matches)
        
        # Remove duplicates and return first few
        return list(set(logout_urls))[:3]
    
    def _check_session_cookies_cleared(self, response) -> bool:
        """Check if session cookies are cleared in response"""
        
        for cookie in response.cookies:
            if self._is_session_cookie(cookie.name):
                # Check if cookie is expired or has empty value
                if cookie.value == '' or cookie.value == 'deleted':
                    return True
                
                # Check if cookie has past expiration date
                if hasattr(cookie, 'expires') and cookie.expires:
                    # This would need proper date parsing in practice
                    return True
        
        return False