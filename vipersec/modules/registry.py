"""
Module registry for managing security testing modules
"""

from typing import Dict, List, Optional
import importlib
import logging

from .base import BaseModule


class ModuleRegistry:
    """Registry for security testing modules"""
    
    def __init__(self):
        self.modules: Dict[str, BaseModule] = {}
        self.logger = logging.getLogger(__name__)
        
        # Auto-register built-in modules
        self._register_builtin_modules()
    
    def _register_builtin_modules(self):
        """Register built-in security modules"""
        builtin_modules = [
            ('xss', 'XSSModule'),
            ('sqli', 'SQLInjectionModule'),
            ('csrf', 'CSRFModule'),
            ('auth', 'AuthModule'),
            ('session', 'SessionModule'),
            ('pain_testing', 'PainTestingModule')
        ]
        
        for module_name, class_name in builtin_modules:
            try:
                module = importlib.import_module(f'vipersec.modules.{module_name}')
                module_class = getattr(module, class_name)
                instance = module_class()
                self.register_module(instance)
                
            except (ImportError, AttributeError) as e:
                self.logger.warning(f"Failed to load module {module_name}: {e}")
    
    def register_module(self, module: BaseModule):
        """Register a security module"""
        self.modules[module.name] = module
        self.logger.info(f"Registered module: {module.name}")
    
    def get_module(self, name: str) -> Optional[BaseModule]:
        """Get module by name"""
        return self.modules.get(name)
    
    def is_available(self, name: str) -> bool:
        """Check if module is available"""
        return name in self.modules
    
    def list_modules(self) -> List[str]:
        """List all available modules"""
        return list(self.modules.keys())
    
    def get_module_info(self, name: str) -> Optional[Dict[str, str]]:
        """Get module information"""
        module = self.get_module(name)
        if module:
            return {
                'name': module.name,
                'description': module.description
            }
        return None