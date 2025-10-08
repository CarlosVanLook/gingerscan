"""
Setup script for Ginger Scan
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="gingerscan",
    version="1.0.0",
    author="Mr Cherif",
    author_email="mrxcherif@hotmail.com",
    description="A comprehensive Python toolkit for network scanning and security assessment",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/mrxcherif/gingerscan",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Networking",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.11",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.4.3",
            "pytest-asyncio>=0.21.1",
            "pytest-cov>=4.1.0",
            "black>=23.11.0",
            "flake8>=6.1.0",
            "mypy>=1.7.1",
            "pre-commit>=3.6.0",
        ],
        "web": [
            "fastapi>=0.104.1",
            "uvicorn>=0.24.0",
            "jinja2>=3.1.2",
        ],
        "reports": [
            "reportlab>=4.0.7",
            "weasyprint>=60.2",
            "plotly>=5.17.0",
            "matplotlib>=3.8.2",
        ],
        "security": [
            "shodan>=1.31.0",
            "cryptography>=41.0.8",
        ],
    },
    entry_points={
        "console_scripts": [
            "gingerscan=tools.cli:main",
            "gs-scan=tools.scanner:main",
            "gs-parse=tools.parser:main",
            "gs-report=tools.reporter:main",
            "gs-vuln=tools.vuln_checks:main",
            "gs-web=tools.web_dashboard:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.yaml", "*.yml", "*.json", "*.html", "*.css", "*.js"],
    },
    keywords="network, scanning, security, penetration-testing, vulnerability-assessment, port-scanning",
    project_urls={
        "Bug Reports": "https://github.com/mrxcherif/gingerscan/issues",
        "Source": "https://github.com/mrxcherif/gingerscan",
        "Documentation": "https://github.com/mrxcherif/gingerscan/docs",
    },
)
