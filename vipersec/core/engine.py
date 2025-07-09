"""
Core ViperSec scanning engine with async capabilities
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid

from .config import Config, Target
from .scanner import SecurityScanner
from ..modules import ModuleRegistry
from ..ai.response_classifier import ResponseClassifier
from ..reports.generator import ReportGenerator


class ViperSecEngine:
    """Main ViperSec scanning engine"""
    
    def __init__(self, config: Config):
        self.config = config
        self.session_id = str(uuid.uuid4())
        self.start_time = None
        self.end_time = None
        
        # Initialize components
        self.scanner = SecurityScanner(config)
        self.module_registry = ModuleRegistry()
        self.response_classifier = ResponseClassifier(config.ai) if config.ai.enabled else None
        self.report_generator = ReportGenerator(config.reports)
        
        # Results storage
        self.results = {
            'session_id': self.session_id,
            'vulnerabilities': [],
            'statistics': {},
            'metadata': {}
        }
        
        # Setup logging
        self._setup_logging()
    
    def _setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=getattr(logging, self.config.log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    async def scan_target(self, target: Target, modules: List[str] = None) -> Dict[str, Any]:
        """
        Perform comprehensive security scan on target
        
        Args:
            target: Target configuration
            modules: List of modules to run (default: all enabled)
            
        Returns:
            Scan results dictionary
        """
        self.start_time = datetime.now()
        self.logger.info(f"Starting scan for {target.url}")
        
        # Use specified modules or default enabled ones
        if modules is None:
            modules = self.config.modules.enabled_modules
        
        # Initialize results
        self.results.update({
            'target': target.url,
            'start_time': self.start_time.isoformat(),
            'modules_run': modules,
            'vulnerabilities': [],
            'statistics': {
                'total_requests': 0,
                'vulnerabilities_found': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        })
        
        try:
            # Run reconnaissance
            await self._run_reconnaissance(target)
            
            # Run security modules
            tasks = []
            for module_name in modules:
                if self.module_registry.is_available(module_name):
                    module = self.module_registry.get_module(module_name)
                    task = asyncio.create_task(
                        self._run_module(module, target),
                        name=f"module_{module_name}"
                    )
                    tasks.append(task)
            
            # Wait for all modules to complete
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Process results
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        self.logger.error(f"Module {modules[i]} failed: {result}")
                    else:
                        self._process_module_results(result)
            
            # Finalize results
            self.end_time = datetime.now()
            self.results['end_time'] = self.end_time.isoformat()
            self.results['duration'] = (self.end_time - self.start_time).total_seconds()
            
            # AI-powered result analysis
            if self.response_classifier:
                await self._analyze_results_with_ai()
            
            self.logger.info(f"Scan completed. Found {len(self.results['vulnerabilities'])} vulnerabilities")
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            self.results['error'] = str(e)
        
        return self.results
    
    async def _run_reconnaissance(self, target: Target):
        """Run reconnaissance phase"""
        self.logger.info("Running reconnaissance...")
        
        # Basic target analysis
        recon_results = await self.scanner.analyze_target(target)
        self.results['reconnaissance'] = recon_results
        
        # Update statistics
        self.results['statistics']['total_requests'] += recon_results.get('requests_made', 0)
    
    async def _run_module(self, module, target: Target) -> Dict[str, Any]:
        """Run individual security module"""
        self.logger.info(f"Running module: {module.name}")
        
        try:
            # Execute module
            module_results = await module.scan(target, self.scanner)
            
            # Add metadata
            module_results['module'] = module.name
            module_results['timestamp'] = datetime.now().isoformat()
            
            return module_results
            
        except Exception as e:
            self.logger.error(f"Module {module.name} failed: {e}")
            return {
                'module': module.name,
                'error': str(e),
                'vulnerabilities': []
            }
    
    def _process_module_results(self, module_results: Dict[str, Any]):
        """Process results from a security module"""
        if 'vulnerabilities' in module_results:
            for vuln in module_results['vulnerabilities']:
                # Add to main results
                self.results['vulnerabilities'].append(vuln)
                
                # Update statistics
                severity = vuln.get('severity', 'info').lower()
                if severity in self.results['statistics']:
                    self.results['statistics'][severity] += 1
                
                self.results['statistics']['vulnerabilities_found'] += 1
        
        # Update request count
        if 'requests_made' in module_results:
            self.results['statistics']['total_requests'] += module_results['requests_made']
    
    async def _analyze_results_with_ai(self):
        """Use AI to analyze and enhance results"""
        self.logger.info("Analyzing results with AI...")
        
        try:
            # Classify and prioritize vulnerabilities
            for vuln in self.results['vulnerabilities']:
                if 'response' in vuln:
                    classification = await self.response_classifier.classify_response(
                        vuln['response']
                    )
                    vuln['ai_classification'] = classification
            
            # Generate AI insights
            insights = await self.response_classifier.generate_insights(
                self.results['vulnerabilities']
            )
            self.results['ai_insights'] = insights
            
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
    
    async def generate_report(self, output_path: str, format: str = "html") -> str:
        """Generate security report"""
        self.logger.info(f"Generating {format} report...")
        
        report_path = await self.report_generator.generate(
            self.results, 
            output_path, 
            format
        )
        
        self.logger.info(f"Report saved to: {report_path}")
        return report_path
    
    def get_summary(self) -> Dict[str, Any]:
        """Get scan summary"""
        return {
            'session_id': self.session_id,
            'target': self.results.get('target'),
            'duration': self.results.get('duration'),
            'vulnerabilities_found': self.results['statistics']['vulnerabilities_found'],
            'severity_breakdown': {
                'critical': self.results['statistics']['critical'],
                'high': self.results['statistics']['high'],
                'medium': self.results['statistics']['medium'],
                'low': self.results['statistics']['low'],
                'info': self.results['statistics']['info']
            },
            'modules_run': self.results.get('modules_run', []),
            'total_requests': self.results['statistics']['total_requests']
        }