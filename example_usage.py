#!/usr/bin/env python3
"""
ViperSec 2025 - Example Usage Script
Demonstrates how to use ViperSec programmatically
"""

import asyncio
from vipersec.core.config import Config, Target
from vipersec.core.engine import ViperSecEngine


async def basic_scan_example():
    """Basic security scan example"""
    
    print("🛡️  ViperSec 2025 - Basic Scan Example")
    print("=" * 50)
    
    # Load configuration
    config = Config.load_from_file('config.yaml')
    
    # Create target
    target = Target(
        url="https://httpbin.org",
        headers={"User-Agent": "ViperSec-2025-Scanner"}
    )
    
    # Initialize engine
    engine = ViperSecEngine(config)
    
    try:
        # Run scan with specific modules
        print(f"🎯 Scanning target: {target.url}")
        results = await engine.scan_target(target, modules=['xss', 'sqli'])
        
        # Display summary
        summary = engine.get_summary()
        print(f"\n📊 Scan Results:")
        print(f"   • Vulnerabilities found: {summary['vulnerabilities_found']}")
        print(f"   • Critical: {summary['severity_breakdown']['critical']}")
        print(f"   • High: {summary['severity_breakdown']['high']}")
        print(f"   • Medium: {summary['severity_breakdown']['medium']}")
        print(f"   • Low: {summary['severity_breakdown']['low']}")
        print(f"   • Info: {summary['severity_breakdown']['info']}")
        print(f"   • Total requests: {summary['total_requests']}")
        print(f"   • Duration: {summary['duration']:.2f} seconds")
        
        # Generate report
        report_path = await engine.generate_report("example_report.html", "html")
        print(f"\n📁 Report saved to: {report_path}")
        
        # Display vulnerabilities
        if results['vulnerabilities']:
            print(f"\n🔍 Vulnerability Details:")
            for i, vuln in enumerate(results['vulnerabilities'], 1):
                print(f"   {i}. {vuln['title']} ({vuln['severity']})")
                print(f"      Module: {vuln['module']}")
                print(f"      CWE: {vuln.get('cwe_id', 'N/A')}")
                print()
        else:
            print("\n✅ No vulnerabilities detected!")
        
    except Exception as e:
        print(f"❌ Scan failed: {e}")


async def advanced_scan_example():
    """Advanced scan with custom configuration"""
    
    print("\n🚀 ViperSec 2025 - Advanced Scan Example")
    print("=" * 50)
    
    # Create custom configuration
    config = Config()
    config.scan.max_threads = 20
    config.scan.timeout = 15
    config.ai.enabled = True
    
    # Create target with authentication
    target = Target(
        url="https://httpbin.org/forms/post",
        headers={
            "User-Agent": "ViperSec-2025-Advanced",
            "Accept": "text/html,application/xhtml+xml"
        }
    )
    
    # Initialize engine
    engine = ViperSecEngine(config)
    
    try:
        print(f"🎯 Advanced scanning: {target.url}")
        print(f"🧵 Using {config.scan.max_threads} threads")
        print(f"🤖 AI analysis: {'enabled' if config.ai.enabled else 'disabled'}")
        
        # Run comprehensive scan
        results = await engine.scan_target(target)
        
        # Show AI insights if available
        if 'ai_insights' in results:
            insights = results['ai_insights']
            print(f"\n🤖 AI Insights:")
            print(f"   • Risk Score: {insights.get('risk_score', 0):.1f}/10")
            print(f"   • Summary: {insights.get('summary', 'No summary available')}")
            
            if insights.get('recommendations'):
                print(f"   • Recommendations:")
                for rec in insights['recommendations'][:3]:
                    print(f"     - {rec}")
        
        # Generate multiple report formats
        await engine.generate_report("advanced_report.html", "html")
        await engine.generate_report("advanced_report.json", "json")
        await engine.generate_report("advanced_report.md", "markdown")
        
        print(f"\n📁 Reports generated in multiple formats")
        
    except Exception as e:
        print(f"❌ Advanced scan failed: {e}")


async def pain_testing_example():
    """Pain testing example"""
    
    print("\n💥 ViperSec 2025 - Pain Testing Example")
    print("=" * 50)
    
    config = Config()
    config.scan.max_threads = 30
    
    target = Target(url="https://httpbin.org/anything")
    
    engine = ViperSecEngine(config)
    
    try:
        print(f"💥 Pain testing: {target.url}")
        print("⚠️  Running aggressive stress tests...")
        
        # Run only pain testing module
        results = await engine.scan_target(target, modules=['pain_testing'])
        
        pain_vulns = [v for v in results['vulnerabilities'] if v['module'] == 'pain_testing']
        
        print(f"\n📊 Pain Testing Results:")
        print(f"   • Issues found: {len(pain_vulns)}")
        
        for vuln in pain_vulns:
            print(f"   • {vuln['title']} ({vuln['severity']})")
        
    except Exception as e:
        print(f"❌ Pain testing failed: {e}")


async def module_demonstration():
    """Demonstrate individual modules"""
    
    print("\n🔧 ViperSec 2025 - Module Demonstration")
    print("=" * 50)
    
    from vipersec.modules.registry import ModuleRegistry
    
    registry = ModuleRegistry()
    
    print("Available modules:")
    for module_name in registry.list_modules():
        module_info = registry.get_module_info(module_name)
        print(f"   • {module_name}: {module_info['description']}")
    
    # Test individual module
    config = Config()
    target = Target(url="https://httpbin.org/forms/post")
    engine = ViperSecEngine(config)
    
    print(f"\n🧪 Testing XSS module on {target.url}")
    
    try:
        results = await engine.scan_target(target, modules=['xss'])
        xss_vulns = [v for v in results['vulnerabilities'] if v['module'] == 'xss']
        
        print(f"   • XSS vulnerabilities found: {len(xss_vulns)}")
        
    except Exception as e:
        print(f"❌ Module test failed: {e}")


async def main():
    """Main example runner"""
    
    print("🛡️  ViperSec 2025 - Cybersecurity Testing Platform")
    print("🤖 AI-Powered Vulnerability Detection & Analysis")
    print("=" * 60)
    
    try:
        # Run examples
        await basic_scan_example()
        await advanced_scan_example()
        await pain_testing_example()
        await module_demonstration()
        
        print("\n✅ All examples completed successfully!")
        print("\n📚 Next steps:")
        print("   • Review generated reports")
        print("   • Customize config.yaml for your needs")
        print("   • Explore CLI commands: python -m vipersec.cli --help")
        print("   • Read documentation for advanced features")
        
    except KeyboardInterrupt:
        print("\n⏹️  Examples interrupted by user")
    except Exception as e:
        print(f"\n❌ Example execution failed: {e}")


if __name__ == "__main__":
    # Run examples
    asyncio.run(main())