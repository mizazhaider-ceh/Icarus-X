"""
ICARUS-X Technology Detection Module
====================================
Detect web technologies, frameworks, CMS, etc.
"""

import asyncio
import re
from dataclasses import dataclass
from typing import Optional

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


@dataclass
class Technology:
    """Detected technology."""
    name: str
    category: str
    version: Optional[str] = None
    confidence: int = 100
    website: Optional[str] = None


# Technology signatures (header, meta, body patterns)
TECH_SIGNATURES = {
    # Web Servers
    "nginx": {
        "category": "Web Server",
        "headers": {"server": r"nginx/?(.*)"},
        "website": "https://nginx.org",
    },
    "Apache": {
        "category": "Web Server",
        "headers": {"server": r"Apache/?(.*)"},
        "website": "https://httpd.apache.org",
    },
    "IIS": {
        "category": "Web Server",
        "headers": {"server": r"Microsoft-IIS/(.*)"},
        "website": "https://www.iis.net",
    },
    "LiteSpeed": {
        "category": "Web Server",
        "headers": {"server": r"LiteSpeed"},
    },
    
    # Programming Languages
    "PHP": {
        "category": "Language",
        "headers": {"x-powered-by": r"PHP/(.*)"},
        "cookies": ["PHPSESSID"],
    },
    "ASP.NET": {
        "category": "Language",
        "headers": {"x-powered-by": r"ASP\.NET"},
        "cookies": ["ASP.NET_SessionId", "ASPSESSIONID"],
    },
    "Python": {
        "category": "Language",
        "headers": {"server": r"Python|Werkzeug|gunicorn"},
    },
    "Node.js": {
        "category": "Language",
        "headers": {"x-powered-by": r"Express"},
    },
    "Java": {
        "category": "Language",
        "headers": {"x-powered-by": r"Servlet|JSP"},
        "cookies": ["JSESSIONID"],
    },
    
    # CMS
    "WordPress": {
        "category": "CMS",
        "body": [r"wp-content", r"wp-includes", r"/wp-json/"],
        "meta": {"generator": r"WordPress (.*)"},
        "website": "https://wordpress.org",
    },
    "Drupal": {
        "category": "CMS",
        "body": [r"Drupal", r"/sites/default/files/"],
        "headers": {"x-generator": r"Drupal (.*)"},
        "website": "https://drupal.org",
    },
    "Joomla": {
        "category": "CMS",
        "body": [r"/media/jui/", r"Joomla!"],
        "meta": {"generator": r"Joomla"},
        "website": "https://joomla.org",
    },
    "Magento": {
        "category": "CMS",
        "body": [r"Magento", r"/static/version"],
        "cookies": ["frontend"],
    },
    "Shopify": {
        "category": "E-commerce",
        "body": [r"cdn\.shopify\.com", r"Shopify\.theme"],
        "headers": {"x-shopid": r".*"},
    },
    
    # Frameworks
    "React": {
        "category": "JavaScript Framework",
        "body": [r"react\.production\.min\.js", r"__REACT_DEVTOOLS_GLOBAL_HOOK__", r"_reactRootContainer"],
    },
    "Vue.js": {
        "category": "JavaScript Framework",
        "body": [r"vue\.min\.js", r"Vue\.js", r"__VUE__"],
    },
    "Angular": {
        "category": "JavaScript Framework",
        "body": [r"ng-version", r"angular\.min\.js", r"ng-app"],
    },
    "jQuery": {
        "category": "JavaScript Library",
        "body": [r"jquery[.-](\d+\.\d+\.\d+)?\.min\.js", r"jQuery v(\d+\.\d+\.\d+)"],
    },
    "Bootstrap": {
        "category": "CSS Framework",
        "body": [r"bootstrap[.-](\d+\.\d+\.\d+)?\.min\.(css|js)"],
    },
    "Tailwind CSS": {
        "category": "CSS Framework",
        "body": [r"tailwindcss", r"tailwind\.min\.css"],
    },
    "Laravel": {
        "category": "PHP Framework",
        "cookies": ["laravel_session"],
        "body": [r"Laravel"],
    },
    "Django": {
        "category": "Python Framework",
        "cookies": ["csrftoken", "sessionid"],
        "body": [r"csrfmiddlewaretoken"],
    },
    "Flask": {
        "category": "Python Framework",
        "headers": {"server": r"Werkzeug"},
    },
    "Ruby on Rails": {
        "category": "Ruby Framework",
        "headers": {"x-powered-by": r"Phusion Passenger"},
        "cookies": ["_session_id"],
    },
    "Spring": {
        "category": "Java Framework",
        "cookies": ["JSESSIONID"],
        "headers": {"x-application-context": r".*"},
    },
    
    # CDN & Hosting
    "Cloudflare": {
        "category": "CDN",
        "headers": {"server": r"cloudflare", "cf-ray": r".*"},
    },
    "AWS": {
        "category": "Hosting",
        "headers": {"server": r"AmazonS3|awselb"},
    },
    "Google Cloud": {
        "category": "Hosting",
        "headers": {"server": r"Google Frontend|gws"},
    },
    "Vercel": {
        "category": "Hosting",
        "headers": {"server": r"Vercel", "x-vercel-id": r".*"},
    },
    "Netlify": {
        "category": "Hosting",
        "headers": {"server": r"Netlify"},
    },
    
    # Security
    "CloudFlare WAF": {
        "category": "Security",
        "headers": {"cf-ray": r".*"},
    },
    "ModSecurity": {
        "category": "Security",
        "headers": {"server": r"mod_security"},
    },
    
    # Analytics
    "Google Analytics": {
        "category": "Analytics",
        "body": [r"google-analytics\.com", r"gtag\(", r"GoogleAnalyticsObject"],
    },
    "Google Tag Manager": {
        "category": "Analytics",
        "body": [r"googletagmanager\.com", r"gtm\.js"],
    },
}


async def detect_technologies(
    url: str,
    timeout: float = 10.0,
) -> list[Technology]:
    """
    Detect technologies used by a website.
    
    Args:
        url: Target URL
        timeout: Request timeout
    
    Returns:
        List of detected technologies
    """
    detected = []
    
    try:
        async with httpx.AsyncClient(
            verify=False,
            timeout=timeout,
            follow_redirects=True,
        ) as client:
            response = await client.get(url)
            
            headers = {k.lower(): v for k, v in response.headers.items()}
            body = response.text
            cookies = {c.name: c.value for c in response.cookies}
            
            # Check each technology
            for tech_name, signatures in TECH_SIGNATURES.items():
                version = None
                confidence = 0
                
                # Check headers
                if "headers" in signatures:
                    for header_name, pattern in signatures["headers"].items():
                        if header_name in headers:
                            match = re.search(pattern, headers[header_name], re.I)
                            if match:
                                confidence += 50
                                if match.groups():
                                    version = match.group(1)
                
                # Check cookies
                if "cookies" in signatures:
                    for cookie in signatures["cookies"]:
                        if cookie in cookies:
                            confidence += 30
                
                # Check body patterns
                if "body" in signatures:
                    for pattern in signatures["body"]:
                        match = re.search(pattern, body, re.I)
                        if match:
                            confidence += 40
                            if match.groups() and not version:
                                version = match.group(1)
                
                # Check meta tags
                if "meta" in signatures:
                    for meta_name, pattern in signatures["meta"].items():
                        meta_pattern = f'<meta[^>]*name=["\']?{meta_name}["\']?[^>]*content=["\']([^"\']+)["\']'
                        match = re.search(meta_pattern, body, re.I)
                        if match:
                            version_match = re.search(pattern, match.group(1))
                            if version_match:
                                confidence += 50
                                if version_match.groups():
                                    version = version_match.group(1)
                
                # Add if confident
                if confidence >= 30:
                    detected.append(Technology(
                        name=tech_name,
                        category=signatures["category"],
                        version=version.strip() if version else None,
                        confidence=min(confidence, 100),
                        website=signatures.get("website"),
                    ))
    
    except Exception as e:
        console.print(f"[red]Tech detection error: {e}[/red]")
    
    return detected


def display_technologies(technologies: list[Technology]):
    """Display detected technologies."""
    if not technologies:
        console.print("[dim]No technologies detected[/dim]")
        return
    
    # Group by category
    by_category = {}
    for tech in technologies:
        if tech.category not in by_category:
            by_category[tech.category] = []
        by_category[tech.category].append(tech)
    
    table = Table(title="Detected Technologies", show_header=True, header_style="bold cyan")
    table.add_column("Category", style="cyan")
    table.add_column("Technology", style="green")
    table.add_column("Version", style="yellow")
    table.add_column("Confidence", justify="right")
    
    for category, techs in sorted(by_category.items()):
        for i, tech in enumerate(techs):
            cat = category if i == 0 else ""
            version = tech.version or "-"
            conf = f"{tech.confidence}%"
            
            # Color confidence
            if tech.confidence >= 80:
                conf = f"[green]{conf}[/green]"
            elif tech.confidence >= 50:
                conf = f"[yellow]{conf}[/yellow]"
            else:
                conf = f"[dim]{conf}[/dim]"
            
            table.add_row(cat, tech.name, version, conf)
    
    console.print(table)


async def fingerprint_target(url: str) -> dict:
    """
    Full fingerprint of a target.
    
    Returns dict with technologies, headers, and analysis.
    """
    result = {
        "url": url,
        "technologies": [],
        "headers": {},
        "security_headers": {},
        "interesting_headers": [],
    }
    
    # Detect technologies
    technologies = await detect_technologies(url)
    result["technologies"] = [
        {"name": t.name, "category": t.category, "version": t.version}
        for t in technologies
    ]
    
    # Get headers
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            response = await client.get(url)
            result["headers"] = dict(response.headers)
            
            # Check security headers
            security_headers = [
                "strict-transport-security",
                "x-frame-options",
                "x-content-type-options",
                "content-security-policy",
                "x-xss-protection",
                "referrer-policy",
            ]
            
            for header in security_headers:
                if header in response.headers:
                    result["security_headers"][header] = response.headers[header]
                else:
                    result["interesting_headers"].append(f"Missing: {header}")
    
    except Exception:
        pass
    
    return result
