"""
Core HTTP scanner with async capabilities
"""

import asyncio
import httpx
import random
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse
import logging

from .config import Config, Target


class SecurityScanner:
    """Async HTTP security scanner"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # HTTP client configuration
        self.client_config = {
            'timeout': httpx.Timeout(self.config.scan.timeout),
            'limits': httpx.Limits(max_connections=self.config.scan.max_threads),
            'follow_redirects': True
        }
        
        # Request statistics
        self.stats = {
            'requests_made': 0,
            'responses_received': 0,
            'errors': 0
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.client = httpx.AsyncClient(**self.client_config)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.client.aclose()
    
    async def analyze_target(self, target: Target) -> Dict[str, Any]:
        """Analyze target for basic information"""
        async with self:
            results = {
                'url': target.url,
                'status': 'unknown',
                'server': None,
                'technologies': [],
                'forms': [],
                'links': [],
                'cookies': [],
                'headers': {},
                'requests_made': 0
            }
            
            try:
                # Initial request
                response = await self._make_request('GET', target.url, target)
                if response:
                    results['status'] = 'accessible'
                    results['headers'] = dict(response.headers)
                    results['server'] = response.headers.get('server')
                    results['cookies'] = [
                        {'name': cookie.name, 'value': cookie.value, 'secure': cookie.secure}
                        for cookie in response.cookies
                    ]
                    
                    # Analyze response content
                    if response.headers.get('content-type', '').startswith('text/html'):
                        content_analysis = await self._analyze_html_content(response.text)
                        results.update(content_analysis)
                
                results['requests_made'] = self.stats['requests_made']
                
            except Exception as e:
                self.logger.error(f"Target analysis failed: {e}")
                results['error'] = str(e)
            
            return results
    
    async def _analyze_html_content(self, html: str) -> Dict[str, Any]:
        """Analyze HTML content for forms, links, etc."""
        from bs4 import BeautifulSoup
        
        soup = BeautifulSoup(html, 'html.parser')
        
        # Find forms
        forms = []
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                form_data['inputs'].append({
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                })
            
            forms.append(form_data)
        
        # Find links
        links = [a.get('href') for a in soup.find_all('a', href=True)]
        
        # Detect technologies
        technologies = []
        
        # Check for common frameworks/libraries
        if soup.find(attrs={'name': 'generator'}):
            generator = soup.find(attrs={'name': 'generator'})['content']
            technologies.append(generator)
        
        # Check for JavaScript frameworks
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script['src']
            if 'jquery' in src.lower():
                technologies.append('jQuery')
            elif 'angular' in src.lower():
                technologies.append('AngularJS')
            elif 'react' in src.lower():
                technologies.append('React')
            elif 'vue' in src.lower():
                technologies.append('Vue.js')
        
        return {
            'forms': forms,
            'links': links[:50],  # Limit to first 50 links
            'technologies': list(set(technologies))
        }
    
    async def _make_request(
        self, 
        method: str, 
        url: str, 
        target: Target,
        **kwargs
    ) -> Optional[httpx.Response]:
        """Make HTTP request with error handling and retries"""
        
        # Prepare headers
        headers = {
            'User-Agent': random.choice(self.config.scan.user_agents),
            **target.headers
        }
        headers.update(kwargs.get('headers', {}))
        
        # Add cookies
        cookies = {**target.cookies, **kwargs.get('cookies', {})}
        
        for attempt in range(self.config.scan.max_retries):
            try:
                # Add delay between requests
                if self.stats['requests_made'] > 0:
                    await asyncio.sleep(self.config.scan.delay_between_requests)
                
                response = await self.client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    cookies=cookies,
                    **{k: v for k, v in kwargs.items() if k not in ['headers', 'cookies']}
                )
                
                self.stats['requests_made'] += 1
                self.stats['responses_received'] += 1
                
                return response
                
            except httpx.TimeoutException:
                self.logger.warning(f"Request timeout for {url} (attempt {attempt + 1})")
                if attempt == self.config.scan.max_retries - 1:
                    self.stats['errors'] += 1
                    return None
                    
            except Exception as e:
                self.logger.error(f"Request failed for {url}: {e}")
                self.stats['errors'] += 1
                if attempt == self.config.scan.max_retries - 1:
                    return None
        
        return None
    
    async def test_payload(
        self, 
        target: Target, 
        payload: str, 
        parameter: str,
        method: str = 'GET'
    ) -> Optional[httpx.Response]:
        """Test a specific payload against a parameter"""
        
        if method.upper() == 'GET':
            # URL parameter injection
            separator = '&' if '?' in target.url else '?'
            test_url = f"{target.url}{separator}{parameter}={payload}"
            return await self._make_request('GET', test_url, target)
        
        elif method.upper() == 'POST':
            # POST data injection
            data = {parameter: payload}
            return await self._make_request('POST', target.url, target, data=data)
        
        return None
    
    async def test_multiple_payloads(
        self,
        target: Target,
        payloads: List[str],
        parameter: str,
        method: str = 'GET'
    ) -> List[Dict[str, Any]]:
        """Test multiple payloads concurrently"""
        
        tasks = []
        for payload in payloads:
            task = asyncio.create_task(
                self._test_payload_with_metadata(target, payload, parameter, method)
            )
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and None results
        valid_results = []
        for result in results:
            if not isinstance(result, Exception) and result is not None:
                valid_results.append(result)
        
        return valid_results
    
    async def _test_payload_with_metadata(
        self,
        target: Target,
        payload: str,
        parameter: str,
        method: str
    ) -> Optional[Dict[str, Any]]:
        """Test payload and return result with metadata"""
        
        response = await self.test_payload(target, payload, parameter, method)
        
        if response:
            return {
                'payload': payload,
                'parameter': parameter,
                'method': method,
                'status_code': response.status_code,
                'response_length': len(response.text),
                'response_time': response.elapsed.total_seconds(),
                'headers': dict(response.headers),
                'content': response.text[:1000]  # First 1000 chars
            }
        
        return None
    
    def get_statistics(self) -> Dict[str, int]:
        """Get scanner statistics"""
        return self.stats.copy()