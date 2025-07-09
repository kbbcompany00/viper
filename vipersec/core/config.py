"""
Configuration management for ViperSec 2025
"""

import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
from dataclasses import dataclass


class ProxyConfig(BaseModel):
    """Proxy configuration"""
    enabled: bool = False
    http_proxy: Optional[str] = None
    https_proxy: Optional[str] = None
    rotation_enabled: bool = False
    proxy_list: List[str] = Field(default_factory=list)


class AIConfig(BaseModel):
    """AI/ML configuration"""
    enabled: bool = True
    model_path: str = "models/"
    response_classifier_model: str = "bert-base-uncased"
    captcha_solver_enabled: bool = True
    reinforcement_learning: bool = True
    anomaly_detection: bool = True


class ScanConfig(BaseModel):
    """Scanning configuration"""
    max_threads: int = 50
    timeout: int = 30
    max_retries: int = 3
    delay_between_requests: float = 0.1
    user_agents: List[str] = Field(default_factory=lambda: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    ])


class ModuleConfig(BaseModel):
    """Module-specific configuration"""
    enabled_modules: List[str] = Field(default_factory=lambda: [
        "auth", "xss", "sqli", "csrf", "session", "pain_testing"
    ])
    auth_config: Dict[str, Any] = Field(default_factory=dict)
    xss_config: Dict[str, Any] = Field(default_factory=dict)
    sqli_config: Dict[str, Any] = Field(default_factory=dict)


class ReportConfig(BaseModel):
    """Reporting configuration"""
    output_formats: List[str] = Field(default_factory=lambda: ["json", "html"])
    template_dir: str = "templates/"
    include_screenshots: bool = True
    include_payloads: bool = True


class Config(BaseModel):
    """Main ViperSec configuration"""
    version: str = "2025.1.0"
    debug: bool = False
    log_level: str = "INFO"
    
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    modules: ModuleConfig = Field(default_factory=ModuleConfig)
    reports: ReportConfig = Field(default_factory=ReportConfig)
    
    @classmethod
    def load_from_file(cls, config_path: str = "config.yaml") -> "Config":
        """Load configuration from YAML file"""
        config_file = Path(config_path)
        if config_file.exists():
            with open(config_file, 'r') as f:
                data = yaml.safe_load(f)
                return cls(**data)
        return cls()
    
    def save_to_file(self, config_path: str = "config.yaml") -> None:
        """Save configuration to YAML file"""
        with open(config_path, 'w') as f:
            yaml.dump(self.dict(), f, default_flow_style=False)


@dataclass
class Target:
    """Target configuration"""
    url: str
    headers: Dict[str, str] = None
    cookies: Dict[str, str] = None
    auth_type: Optional[str] = None
    credentials: Optional[Dict[str, str]] = None
    scope: List[str] = None
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {}
        if self.cookies is None:
            self.cookies = {}
        if self.scope is None:
            self.scope = []