"""
ICARUS-X Web Spider/Crawler Module
===================================
Crawl web applications to discover endpoints, forms, and parameters.
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs
import httpx

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table
from rich.tree import Tree

console = Console()


@dataclass
class Endpoint:
    """Discovered endpoint."""
    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    status_code: int = 0
    content_type: str = ""
    depth: int = 0


@dataclass
class SpiderResult:
    """Spider crawl results."""
    base_url: str
    endpoints: list[Endpoint] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    parameters: set = field(default_factory=set)
    emails: set = field(default_factory=set)
    js_files: list[str] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    subdomains: set = field(default_factory=set)


class WebSpider:
    """Web application spider/crawler."""
    
    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        max_pages: int = 100,
        timeout: int = 10,
        user_agent: str = "ICARUS-X Spider/2.0",
        respect_robots: bool = True,
    ):
        self.base_url = base_url.rstrip('/')
        self.base_domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.user_agent = user_agent
        self.respect_robots = respect_robots
        
        self.visited: set[str] = set()
        self.to_visit: list[tuple[str, int]] = [(base_url, 0)]
        self.result = SpiderResult(base_url=base_url)
        
        # Patterns
        self.link_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.I)
        self.src_pattern = re.compile(r'src=["\']([^"\']+)["\']', re.I)
        self.form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.I)
        self.input_pattern = re.compile(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', re.I)
        self.email_pattern = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
        self.api_pattern = re.compile(r'["\']/(api|v\d+)/[^"\']*["\']', re.I)
        self.js_variable_pattern = re.compile(r'var\s+(\w+)\s*=\s*["\']([^"\']+)["\']')
    
    def is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to same domain."""
        parsed = urlparse(url)
        return parsed.netloc == self.base_domain or parsed.netloc == ""
    
    def normalize_url(self, url: str, current_url: str) -> Optional[str]:
        """Normalize and validate URL."""
        if not url or url.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
            return None
        
        # Make absolute URL
        full_url = urljoin(current_url, url)
        parsed = urlparse(full_url)
        
        # Remove fragment
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        
        return normalized if self.is_same_domain(normalized) else None
    
    def extract_links(self, html: str, current_url: str) -> list[str]:
        """Extract all links from HTML."""
        links = []
        
        # href links
        for match in self.link_pattern.finditer(html):
            url = self.normalize_url(match.group(1), current_url)
            if url:
                links.append(url)
        
        # src links (scripts, images)
        for match in self.src_pattern.finditer(html):
            url = self.normalize_url(match.group(1), current_url)
            if url:
                links.append(url)
        
        return list(set(links))
    
    def extract_forms(self, html: str, current_url: str) -> list[dict]:
        """Extract forms from HTML."""
        forms = []
        
        for form_match in self.form_pattern.finditer(html):
            form_html = form_match.group(0)
            
            # Get form action
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
            action = action_match.group(1) if action_match else current_url
            action = self.normalize_url(action, current_url) or current_url
            
            # Get method
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.I)
            method = (method_match.group(1) if method_match else 'GET').upper()
            
            # Get inputs
            inputs = self.input_pattern.findall(form_html)
            
            # Get textareas
            textarea_pattern = re.compile(r'<textarea[^>]*name=["\']([^"\']+)["\']', re.I)
            inputs.extend(textarea_pattern.findall(form_html))
            
            # Get selects
            select_pattern = re.compile(r'<select[^>]*name=["\']([^"\']+)["\']', re.I)
            inputs.extend(select_pattern.findall(form_html))
            
            if inputs:
                forms.append({
                    'action': action,
                    'method': method,
                    'inputs': inputs,
                })
                
                # Add to parameters
                for inp in inputs:
                    self.result.parameters.add(inp)
        
        return forms
    
    def extract_js_files(self, html: str, current_url: str) -> list[str]:
        """Extract JavaScript file URLs."""
        js_files = []
        pattern = re.compile(r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
        
        for match in pattern.finditer(html):
            url = self.normalize_url(match.group(1), current_url)
            if url:
                js_files.append(url)
        
        return js_files
    
    def extract_api_endpoints(self, html: str) -> list[str]:
        """Extract potential API endpoints from HTML/JS."""
        endpoints = []
        
        for match in self.api_pattern.finditer(html):
            endpoints.append(match.group(0).strip('"\''))
        
        return endpoints
    
    def extract_emails(self, html: str) -> list[str]:
        """Extract email addresses."""
        return list(set(self.email_pattern.findall(html)))
    
    def extract_url_params(self, url: str) -> list[str]:
        """Extract parameters from URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())
    
    async def crawl_page(self, url: str, depth: int, client: httpx.AsyncClient) -> Optional[str]:
        """Crawl a single page."""
        try:
            response = await client.get(url, follow_redirects=True, timeout=self.timeout)
            
            content_type = response.headers.get('content-type', '')
            
            # Create endpoint
            endpoint = Endpoint(
                url=url,
                method="GET",
                params=self.extract_url_params(url),
                status_code=response.status_code,
                content_type=content_type,
                depth=depth,
            )
            self.result.endpoints.append(endpoint)
            
            # Add URL params to result
            for param in endpoint.params:
                self.result.parameters.add(param)
            
            if 'text/html' in content_type:
                return response.text
            
            return None
            
        except Exception as e:
            return None
    
    async def crawl(self) -> SpiderResult:
        """Run the spider."""
        headers = {"User-Agent": self.user_agent}
        
        async with httpx.AsyncClient(headers=headers, verify=False) as client:
            with Progress(
                SpinnerColumn(),
                TextColumn("[cyan]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console,
            ) as progress:
                task = progress.add_task("Crawling...", total=self.max_pages)
                
                while self.to_visit and len(self.visited) < self.max_pages:
                    url, depth = self.to_visit.pop(0)
                    
                    if url in self.visited or depth > self.max_depth:
                        continue
                    
                    self.visited.add(url)
                    progress.update(task, advance=1, description=f"Crawling: {url[:50]}...")
                    
                    html = await self.crawl_page(url, depth, client)
                    
                    if html:
                        # Extract data
                        links = self.extract_links(html, url)
                        forms = self.extract_forms(html, url)
                        js_files = self.extract_js_files(html, url)
                        api_endpoints = self.extract_api_endpoints(html)
                        emails = self.extract_emails(html)
                        
                        # Update results
                        self.result.forms.extend(forms)
                        self.result.js_files.extend(js_files)
                        self.result.api_endpoints.extend(api_endpoints)
                        self.result.emails.update(emails)
                        
                        # Add new links to crawl
                        for link in links:
                            if link not in self.visited:
                                self.to_visit.append((link, depth + 1))
                    
                    # Small delay to be nice
                    await asyncio.sleep(0.1)
        
        # Dedupe
        self.result.js_files = list(set(self.result.js_files))
        self.result.api_endpoints = list(set(self.result.api_endpoints))
        
        return self.result


def display_spider_results(result: SpiderResult):
    """Display spider crawl results."""
    console.print(f"\n[bold cyan]Spider Results for {result.base_url}[/bold cyan]\n")
    
    # Summary
    summary = Table(title="Summary", show_header=False)
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", style="green")
    
    summary.add_row("Endpoints Discovered", str(len(result.endpoints)))
    summary.add_row("Forms Found", str(len(result.forms)))
    summary.add_row("Parameters Found", str(len(result.parameters)))
    summary.add_row("JavaScript Files", str(len(result.js_files)))
    summary.add_row("API Endpoints", str(len(result.api_endpoints)))
    summary.add_row("Emails Found", str(len(result.emails)))
    
    console.print(summary)
    console.print()
    
    # Endpoints
    if result.endpoints:
        table = Table(title="Discovered Endpoints", show_header=True, header_style="bold cyan")
        table.add_column("URL", style="white", max_width=60)
        table.add_column("Status", justify="center")
        table.add_column("Params", style="yellow")
        
        for ep in result.endpoints[:30]:
            status_color = "green" if 200 <= ep.status_code < 300 else "yellow"
            table.add_row(
                ep.url,
                f"[{status_color}]{ep.status_code}[/{status_color}]",
                ", ".join(ep.params) if ep.params else "-"
            )
        
        if len(result.endpoints) > 30:
            table.add_row(f"... and {len(result.endpoints) - 30} more", "", "")
        
        console.print(table)
        console.print()
    
    # Forms
    if result.forms:
        console.print("[bold yellow]Forms Found:[/bold yellow]")
        for i, form in enumerate(result.forms[:10], 1):
            console.print(f"  {i}. [{form['method']}] {form['action']}")
            console.print(f"     [dim]Inputs: {', '.join(form['inputs'])}[/dim]")
        console.print()
    
    # Parameters
    if result.parameters:
        console.print(f"[bold magenta]Parameters Found ({len(result.parameters)}):[/bold magenta]")
        console.print(f"  [dim]{', '.join(sorted(result.parameters)[:30])}[/dim]")
        console.print()
    
    # JS Files
    if result.js_files:
        console.print(f"[bold green]JavaScript Files ({len(result.js_files)}):[/bold green]")
        for js in result.js_files[:10]:
            console.print(f"  [dim]{js}[/dim]")
        console.print()
    
    # API Endpoints
    if result.api_endpoints:
        console.print(f"[bold red]Potential API Endpoints ({len(result.api_endpoints)}):[/bold red]")
        for api in result.api_endpoints[:10]:
            console.print(f"  [cyan]{api}[/cyan]")
        console.print()
    
    # Emails
    if result.emails:
        console.print(f"[bold blue]Emails Found ({len(result.emails)}):[/bold blue]")
        for email in result.emails:
            console.print(f"  [dim]{email}[/dim]")


async def run_spider(
    target: str,
    depth: int = 3,
    max_pages: int = 100,
    timeout: int = 10,
) -> SpiderResult:
    """Run the web spider."""
    spider = WebSpider(
        base_url=target,
        max_depth=depth,
        max_pages=max_pages,
        timeout=timeout,
    )
    return await spider.crawl()
