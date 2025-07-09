"""
Command-line interface for ViperSec 2025
"""

import asyncio
import click
from pathlib import Path
from typing import List, Optional
import sys

from .core.config import Config, Target
from .core.engine import ViperSecEngine
from .modules.registry import ModuleRegistry


@click.group()
@click.version_option(version="2025.1.0")
@click.option('--config', '-c', default='config.yaml', help='Configuration file path')
@click.option('--debug', is_flag=True, help='Enable debug mode')
@click.pass_context
def cli(ctx, config: str, debug: bool):
    """ViperSec 2025 - Next-Generation AI-Driven Cybersecurity Testing Platform"""
    
    # Load configuration
    try:
        ctx.ensure_object(dict)
        ctx.obj['config'] = Config.load_from_file(config)
        
        if debug:
            ctx.obj['config'].debug = True
            ctx.obj['config'].log_level = 'DEBUG'
            
    except Exception as e:
        click.echo(f"Error loading configuration: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--target', '-t', required=True, help='Target URL to scan')
@click.option('--modules', '-m', help='Comma-separated list of modules to run')
@click.option('--output', '-o', help='Output file path')
@click.option('--format', '-f', default='html', type=click.Choice(['html', 'json', 'markdown', 'pdf']), help='Output format')
@click.option('--threads', type=int, help='Number of threads to use')
@click.option('--timeout', type=int, help='Request timeout in seconds')
@click.pass_context
def scan(ctx, target: str, modules: Optional[str], output: Optional[str], format: str, threads: Optional[int], timeout: Optional[int]):
    """Perform comprehensive security scan on target"""
    
    config = ctx.obj['config']
    
    # Override config with CLI options
    if threads:
        config.scan.max_threads = threads
    if timeout:
        config.scan.timeout = timeout
    
    # Parse modules
    module_list = None
    if modules:
        module_list = [m.strip() for m in modules.split(',')]
    
    # Create target
    target_obj = Target(url=target)
    
    # Generate output filename if not provided
    if not output:
        from urllib.parse import urlparse
        domain = urlparse(target).netloc.replace(':', '_')
        timestamp = asyncio.get_event_loop().time()
        output = f"vipersec_scan_{domain}_{int(timestamp)}.{format}"
    
    click.echo(f"🛡️  ViperSec 2025 - Starting scan of {target}")
    click.echo(f"📊 Modules: {module_list or 'all enabled'}")
    click.echo(f"📁 Output: {output} ({format})")
    click.echo()
    
    # Run scan
    asyncio.run(_run_scan(config, target_obj, module_list, output, format))


@cli.command()
@click.option('--target', '-t', required=True, help='Target URL for brute force')
@click.option('--userlist', '-u', help='Username list file')
@click.option('--passwordlist', '-p', help='Password list file')
@click.option('--detect-2fa', is_flag=True, help='Detect 2FA mechanisms')
@click.option('--proxy-list', help='Proxy list file for rotation')
@click.pass_context
def brute(ctx, target: str, userlist: Optional[str], passwordlist: Optional[str], detect_2fa: bool, proxy_list: Optional[str]):
    """Perform brute force authentication testing"""
    
    click.echo(f"🔓 ViperSec 2025 - Brute force testing {target}")
    
    if detect_2fa:
        click.echo("🔐 2FA detection enabled")
    
    if proxy_list:
        click.echo(f"🌐 Using proxy rotation from {proxy_list}")
    
    # This would implement actual brute force functionality
    click.echo("⚠️  Brute force module not fully implemented in this demo")


@cli.command()
@click.option('--domain', '-d', required=True, help='Domain for reconnaissance')
@click.option('--amass', is_flag=True, help='Use Amass for subdomain enumeration')
@click.option('--shodan', is_flag=True, help='Use Shodan for asset discovery')
@click.option('--output', '-o', help='Output file for results')
@click.pass_context
def recon(ctx, domain: str, amass: bool, shodan: bool, output: Optional[str]):
    """Perform reconnaissance and asset discovery"""
    
    click.echo(f"🔍 ViperSec 2025 - Reconnaissance of {domain}")
    
    if amass:
        click.echo("📡 Amass subdomain enumeration enabled")
    
    if shodan:
        click.echo("🌍 Shodan asset discovery enabled")
    
    # This would implement actual reconnaissance functionality
    click.echo("⚠️  Reconnaissance module not fully implemented in this demo")


@cli.command()
@click.option('--target', '-t', required=True, help='Target URL for pain testing')
@click.option('--mode', default='normal', type=click.Choice(['safe', 'normal', 'aggressive']), help='Testing mode')
@click.option('--threads', type=int, default=10, help='Number of concurrent threads')
@click.option('--ai-fuzzing', is_flag=True, help='Enable AI-powered fuzzing')
@click.pass_context
def pain(ctx, target: str, mode: str, threads: int, ai_fuzzing: bool):
    """Perform aggressive pain testing and stress simulation"""
    
    click.echo(f"💥 ViperSec 2025 - Pain testing {target}")
    click.echo(f"⚡ Mode: {mode.upper()}")
    click.echo(f"🧵 Threads: {threads}")
    
    if ai_fuzzing:
        click.echo("🤖 AI-powered fuzzing enabled")
    
    config = ctx.obj['config']
    config.scan.max_threads = threads
    
    # Create target and run pain testing
    target_obj = Target(url=target)
    
    asyncio.run(_run_pain_testing(config, target_obj, mode, ai_fuzzing))


@cli.command()
@click.option('--input', '-i', required=True, help='Input scan results file')
@click.option('--format', '-f', default='html', type=click.Choice(['html', 'json', 'markdown', 'pdf']), help='Output format')
@click.option('--include', help='Include specific sections (comma-separated)')
@click.pass_context
def report(ctx, input: str, format: str, include: Optional[str]):
    """Generate reports from scan results"""
    
    click.echo(f"📊 ViperSec 2025 - Generating {format} report from {input}")
    
    # This would implement report generation from existing results
    click.echo("⚠️  Report generation from file not fully implemented in this demo")


@cli.command()
@click.pass_context
def modules(ctx):
    """List available security testing modules"""
    
    click.echo("🔧 ViperSec 2025 - Available Modules\n")
    
    registry = ModuleRegistry()
    
    for module_name in registry.list_modules():
        module_info = registry.get_module_info(module_name)
        if module_info:
            click.echo(f"• {module_name}: {module_info['description']}")
    
    click.echo(f"\nTotal modules: {len(registry.list_modules())}")


async def _run_scan(config: Config, target: Target, modules: Optional[List[str]], output: str, format: str):
    """Run security scan"""
    
    try:
        # Initialize engine
        engine = ViperSecEngine(config)
        
        # Run scan
        results = await engine.scan_target(target, modules)
        
        # Generate report
        report_path = await engine.generate_report(output, format)
        
        # Display summary
        summary = engine.get_summary()
        
        click.echo("✅ Scan completed successfully!")
        click.echo(f"📊 Found {summary['vulnerabilities_found']} vulnerabilities")
        click.echo(f"🔴 Critical: {summary['severity_breakdown']['critical']}")
        click.echo(f"🟠 High: {summary['severity_breakdown']['high']}")
        click.echo(f"🟡 Medium: {summary['severity_breakdown']['medium']}")
        click.echo(f"🟢 Low: {summary['severity_breakdown']['low']}")
        click.echo(f"ℹ️  Info: {summary['severity_breakdown']['info']}")
        click.echo(f"📁 Report saved to: {report_path}")
        
    except Exception as e:
        click.echo(f"❌ Scan failed: {e}", err=True)
        sys.exit(1)


async def _run_pain_testing(config: Config, target: Target, mode: str, ai_fuzzing: bool):
    """Run pain testing"""
    
    try:
        # Initialize engine
        engine = ViperSecEngine(config)
        
        # Run only pain testing module
        results = await engine.scan_target(target, ['pain_testing'])
        
        # Display results
        vulnerabilities = results.get('vulnerabilities', [])
        
        click.echo("💥 Pain testing completed!")
        click.echo(f"📊 Found {len(vulnerabilities)} issues")
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'INFO')
            title = vuln.get('title', 'Unknown')
            
            severity_icon = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🟢',
                'INFO': 'ℹ️'
            }.get(severity, 'ℹ️')
            
            click.echo(f"{severity_icon} {severity}: {title}")
        
    except Exception as e:
        click.echo(f"❌ Pain testing failed: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    cli()