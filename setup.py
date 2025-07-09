"""
Setup script for ViperSec 2025
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="vipersec",
    version="2025.1.0",
    author="ViperSec Security Team",
    author_email="team@vipersec.com",
    description="Next-Generation AI-Driven Cybersecurity Testing Platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/vipersec/vipersec-2025",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.11",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "vipersec=vipersec.cli:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "vipersec": ["templates/*", "config.yaml"],
    },
    keywords="cybersecurity, penetration testing, vulnerability scanning, AI security, web application security",
    project_urls={
        "Bug Reports": "https://github.com/vipersec/vipersec-2025/issues",
        "Source": "https://github.com/vipersec/vipersec-2025",
        "Documentation": "https://docs.vipersec.com",
    },
)