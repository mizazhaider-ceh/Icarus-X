"""
ICARUS-X Wordlist Manager
=========================
Manage and discover wordlists for pentesting tasks.
"""

import os
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.tree import Tree
from rich.panel import Panel

console = Console()


@dataclass
class Wordlist:
    """Wordlist definition."""
    name: str
    category: str
    subcategory: str
    path: str
    description: str
    size: Optional[int] = None  # Number of lines


# Common wordlist locations
WORDLIST_LOCATIONS = [
    "/usr/share/wordlists",
    "/usr/share/seclists",
    "/usr/share/dirb/wordlists",
    "/usr/share/dirbuster/wordlists",
    "/usr/share/wfuzz/wordlist",
    "/opt/SecLists",
    Path.home() / "wordlists",
    Path.home() / "SecLists",
]


# Wordlist catalog organized by category
WORDLIST_CATALOG = {
    "Directory Bruteforce": {
        "description": "Web directory and file discovery",
        "icon": "📁",
        "wordlists": [
            # SecLists Discovery
            Wordlist("common.txt", "Directory Bruteforce", "General", 
                     "/usr/share/seclists/Discovery/Web-Content/common.txt",
                     "Most common web paths (4,600+ entries)"),
            Wordlist("directory-list-2.3-small.txt", "Directory Bruteforce", "General",
                     "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
                     "Small directory list (87k entries)"),
            Wordlist("directory-list-2.3-medium.txt", "Directory Bruteforce", "General",
                     "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
                     "Medium directory list (220k entries)"),
            Wordlist("directory-list-2.3-big.txt", "Directory Bruteforce", "General",
                     "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt",
                     "Large directory list (1.2M entries)"),
            Wordlist("raft-large-directories.txt", "Directory Bruteforce", "RAFT",
                     "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
                     "RAFT large directories"),
            Wordlist("raft-large-files.txt", "Directory Bruteforce", "RAFT",
                     "/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt",
                     "RAFT large files"),
            # Dirb
            Wordlist("common.txt (dirb)", "Directory Bruteforce", "Dirb",
                     "/usr/share/dirb/wordlists/common.txt",
                     "Dirb common wordlist"),
            Wordlist("big.txt", "Directory Bruteforce", "Dirb",
                     "/usr/share/dirb/wordlists/big.txt",
                     "Dirb big wordlist"),
        ],
    },
    "Subdomain Enumeration": {
        "description": "Subdomain and DNS discovery",
        "icon": "🌐",
        "wordlists": [
            Wordlist("subdomains-top1million-5000.txt", "Subdomain Enumeration", "Top",
                     "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                     "Top 5,000 subdomains"),
            Wordlist("subdomains-top1million-20000.txt", "Subdomain Enumeration", "Top",
                     "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
                     "Top 20,000 subdomains"),
            Wordlist("subdomains-top1million-110000.txt", "Subdomain Enumeration", "Top",
                     "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
                     "Top 110,000 subdomains"),
            Wordlist("bitquark-subdomains-top100000.txt", "Subdomain Enumeration", "Bitquark",
                     "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
                     "Bitquark top 100k subdomains"),
            Wordlist("fierce-hostlist.txt", "Subdomain Enumeration", "Fierce",
                     "/usr/share/seclists/Discovery/DNS/fierce-hostlist.txt",
                     "Fierce subdomain list"),
        ],
    },
    "Password Attacks": {
        "description": "Password cracking and brute-force",
        "icon": "🔐",
        "wordlists": [
            Wordlist("rockyou.txt", "Password Attacks", "Common",
                     "/usr/share/wordlists/rockyou.txt",
                     "RockYou breach passwords (14M+ entries)"),
            Wordlist("darkweb2017-top10000.txt", "Password Attacks", "Common",
                     "/usr/share/seclists/Passwords/darkweb2017-top10000.txt",
                     "Dark web top 10,000 passwords"),
            Wordlist("xato-net-10-million-passwords.txt", "Password Attacks", "Large",
                     "/usr/share/seclists/Passwords/xato-net-10-million-passwords.txt",
                     "10 million passwords"),
            Wordlist("common-credentials/10-million-password-list-top-1000000.txt", "Password Attacks", "Large",
                     "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
                     "Top 1 million passwords"),
            Wordlist("Default-Credentials/default-passwords.txt", "Password Attacks", "Default",
                     "/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt",
                     "Default device/service passwords"),
        ],
    },
    "Username Enumeration": {
        "description": "Username and user discovery",
        "icon": "👤",
        "wordlists": [
            Wordlist("top-usernames-shortlist.txt", "Username Enumeration", "Common",
                     "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
                     "Short username list (17 entries)"),
            Wordlist("Names/names.txt", "Username Enumeration", "Names",
                     "/usr/share/seclists/Usernames/Names/names.txt",
                     "Common names wordlist"),
            Wordlist("xato-net-10-million-usernames.txt", "Username Enumeration", "Large",
                     "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",
                     "10 million usernames"),
        ],
    },
    "Fuzzing": {
        "description": "Parameter and input fuzzing",
        "icon": "🔧",
        "wordlists": [
            Wordlist("burp-parameter-names.txt", "Fuzzing", "Parameters",
                     "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
                     "Common parameter names"),
            Wordlist("special-chars.txt", "Fuzzing", "Special",
                     "/usr/share/seclists/Fuzzing/special-chars.txt",
                     "Special characters for fuzzing"),
            Wordlist("LFI/LFI-Jhaddix.txt", "Fuzzing", "LFI",
                     "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt",
                     "LFI payloads by Jhaddix"),
            Wordlist("SQLi/Generic-SQLi.txt", "Fuzzing", "SQLi",
                     "/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt",
                     "Generic SQL injection payloads"),
            Wordlist("XSS/XSS-Jhaddix.txt", "Fuzzing", "XSS",
                     "/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt",
                     "XSS payloads by Jhaddix"),
            Wordlist("command-injection-commix.txt", "Fuzzing", "Command Injection",
                     "/usr/share/seclists/Fuzzing/command-injection-commix.txt",
                     "Command injection payloads"),
        ],
    },
    "API Testing": {
        "description": "API endpoint and parameter discovery",
        "icon": "🔌",
        "wordlists": [
            Wordlist("api-endpoints.txt", "API Testing", "Endpoints",
                     "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
                     "Common API endpoints"),
            Wordlist("api-seen-in-wild.txt", "API Testing", "Endpoints",
                     "/usr/share/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt",
                     "API endpoints seen in the wild"),
            Wordlist("graphql.txt", "API Testing", "GraphQL",
                     "/usr/share/seclists/Discovery/Web-Content/graphql.txt",
                     "GraphQL endpoints and introspection"),
        ],
    },
    "Technology Specific": {
        "description": "CMS and technology-specific paths",
        "icon": "🛠️",
        "wordlists": [
            Wordlist("wp-plugins.fuzz.txt", "Technology Specific", "WordPress",
                     "/usr/share/seclists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt",
                     "WordPress plugin paths"),
            Wordlist("wp-themes.fuzz.txt", "Technology Specific", "WordPress",
                     "/usr/share/seclists/Discovery/Web-Content/CMS/wp-themes.fuzz.txt",
                     "WordPress theme paths"),
            Wordlist("joomla-plugins.fuzz.txt", "Technology Specific", "Joomla",
                     "/usr/share/seclists/Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt",
                     "Joomla plugin paths"),
            Wordlist("drupal-plugins.fuzz.txt", "Technology Specific", "Drupal",
                     "/usr/share/seclists/Discovery/Web-Content/CMS/drupal.fuzz.txt",
                     "Drupal paths"),
            Wordlist("tomcat.txt", "Technology Specific", "Tomcat",
                     "/usr/share/seclists/Discovery/Web-Content/tomcat.txt",
                     "Apache Tomcat paths"),
            Wordlist("IIS.fuzz.txt", "Technology Specific", "IIS",
                     "/usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt",
                     "Microsoft IIS paths"),
        ],
    },
}


def check_wordlist_exists(path: str) -> bool:
    """Check if a wordlist file exists."""
    return Path(path).exists()


def get_wordlist_size(path: str) -> Optional[int]:
    """Get the number of lines in a wordlist."""
    try:
        with open(path, 'r', errors='ignore') as f:
            return sum(1 for _ in f)
    except Exception:
        return None


def find_seclists_path() -> Optional[str]:
    """Find SecLists installation path."""
    locations = [
        "/usr/share/seclists",
        "/opt/SecLists",
        Path.home() / "SecLists",
        "/usr/share/wordlists/seclists",
    ]
    for loc in locations:
        if Path(loc).exists():
            return str(loc)
    return None


def display_wordlists(category: str = None, show_missing: bool = False):
    """Display available wordlists organized by category."""
    console.print("\n[bold cyan]ICARUS-X Wordlist Manager[/bold cyan]\n")
    
    # Check SecLists
    seclists_path = find_seclists_path()
    if seclists_path:
        console.print(f"[green]SecLists found:[/green] {seclists_path}")
    else:
        console.print("[yellow]SecLists not found. Install with:[/yellow]")
        console.print("  sudo apt install seclists")
        console.print("  [dim]or: git clone https://github.com/danielmiessler/SecLists.git[/dim]\n")
    
    # Filter by category if specified
    categories = WORDLIST_CATALOG.keys()
    if category:
        category_lower = category.lower()
        categories = [c for c in categories if category_lower in c.lower()]
    
    for cat_name in categories:
        cat_data = WORDLIST_CATALOG[cat_name]
        icon = cat_data.get("icon", "📄")
        
        # Create tree structure
        tree = Tree(f"[bold cyan]{icon} {cat_name}[/bold cyan] - [dim]{cat_data['description']}[/dim]")
        
        # Group by subcategory
        by_subcat = {}
        for wl in cat_data["wordlists"]:
            if wl.subcategory not in by_subcat:
                by_subcat[wl.subcategory] = []
            by_subcat[wl.subcategory].append(wl)
        
        wordlist_count = 0
        available_count = 0
        
        for subcat, wordlists in by_subcat.items():
            branch = tree.add(f"[yellow]{subcat}[/yellow]")
            
            for wl in wordlists:
                exists = check_wordlist_exists(wl.path)
                wordlist_count += 1
                
                if exists:
                    available_count += 1
                    status = "[green]✓[/green]"
                    path_style = "dim"
                else:
                    if not show_missing:
                        continue
                    status = "[red]✗[/red]"
                    path_style = "dim red"
                
                branch.add(
                    f"{status} [white]{wl.name}[/white]\n"
                    f"   [{path_style}]{wl.path}[/{path_style}]\n"
                    f"   [dim italic]{wl.description}[/dim italic]"
                )
        
        if available_count > 0 or show_missing:
            console.print(tree)
            console.print(f"[dim]Available: {available_count}/{wordlist_count}[/dim]\n")


def display_wordlists_table(category: str = None):
    """Display wordlists in a compact table format."""
    console.print("\n[bold cyan]ICARUS-X Wordlist Manager[/bold cyan]\n")
    
    for cat_name, cat_data in WORDLIST_CATALOG.items():
        if category and category.lower() not in cat_name.lower():
            continue
        
        icon = cat_data.get("icon", "📄")
        
        table = Table(
            title=f"{icon} {cat_name}",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Name", style="white")
        table.add_column("Status", justify="center", width=6)
        table.add_column("Path", style="dim")
        table.add_column("Description", style="dim")
        
        for wl in cat_data["wordlists"]:
            exists = check_wordlist_exists(wl.path)
            status = "[green]OK[/green]" if exists else "[red]--[/red]"
            
            # Only show if exists
            if exists:
                table.add_row(wl.name, status, wl.path, wl.description)
        
        if table.row_count > 0:
            console.print(table)
            console.print()


def get_wordlist_path(name: str) -> Optional[str]:
    """Get the path for a wordlist by name or alias."""
    name_lower = name.lower()
    
    # Common aliases
    aliases = {
        "rockyou": "/usr/share/wordlists/rockyou.txt",
        "common": "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "small": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
        "medium": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "big": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt",
        "large": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt",
        "subdomains": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "api": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
        "lfi": "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt",
        "sqli": "/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt",
        "xss": "/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt",
    }
    
    if name_lower in aliases:
        path = aliases[name_lower]
        if Path(path).exists():
            return path
    
    # Search in catalog
    for cat_data in WORDLIST_CATALOG.values():
        for wl in cat_data["wordlists"]:
            if name_lower in wl.name.lower():
                if Path(wl.path).exists():
                    return wl.path
    
    # Check if it's a direct path
    if Path(name).exists():
        return name
    
    return None


def search_wordlists(query: str) -> list[Wordlist]:
    """Search for wordlists by name or description."""
    results = []
    query_lower = query.lower()
    
    for cat_data in WORDLIST_CATALOG.values():
        for wl in cat_data["wordlists"]:
            if (query_lower in wl.name.lower() or 
                query_lower in wl.description.lower() or
                query_lower in wl.category.lower()):
                if check_wordlist_exists(wl.path):
                    results.append(wl)
    
    return results


def display_search_results(query: str):
    """Display search results."""
    results = search_wordlists(query)
    
    if not results:
        console.print(f"[yellow]No wordlists found matching: {query}[/yellow]")
        return
    
    table = Table(title=f"Search Results: '{query}'", show_header=True, header_style="bold cyan")
    table.add_column("Name")
    table.add_column("Category", style="cyan")
    table.add_column("Path", style="dim")
    
    for wl in results:
        table.add_row(wl.name, wl.category, wl.path)
    
    console.print(table)


def install_seclists_instructions():
    """Show SecLists installation instructions."""
    console.print(Panel(
        "[bold]Install SecLists:[/bold]\n\n"
        "[cyan]APT (Kali/Debian):[/cyan]\n"
        "  sudo apt install seclists\n\n"
        "[cyan]Manual Install:[/cyan]\n"
        "  git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists\n\n"
        "[cyan]Or Download:[/cyan]\n"
        "  https://github.com/danielmiessler/SecLists/archive/master.zip",
        title="SecLists Installation",
        border_style="cyan",
    ))


def get_file_size_human(size_bytes: int) -> str:
    """Convert bytes to human readable size."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f}TB"


def scan_wordlist_folder(folder: str, max_depth: int = 3) -> dict:
    """
    Scan a folder recursively and find all wordlist files.
    
    Returns dict organized by subfolder.
    """
    results = {}
    folder_path = Path(folder)
    
    if not folder_path.exists():
        return results
    
    # Common wordlist extensions
    wordlist_extensions = {'.txt', '.lst', '.dic', '.dict', '.wordlist', '.words'}
    
    def scan_dir(current_path: Path, depth: int = 0):
        if depth > max_depth:
            return
        
        try:
            for item in sorted(current_path.iterdir()):
                if item.is_file():
                    # Check if it looks like a wordlist
                    if item.suffix.lower() in wordlist_extensions or item.suffix == '':
                        # Get relative path from root folder
                        rel_path = item.relative_to(folder_path)
                        parent = str(rel_path.parent) if str(rel_path.parent) != '.' else 'Root'
                        
                        if parent not in results:
                            results[parent] = []
                        
                        # Get file size
                        try:
                            size = item.stat().st_size
                            size_str = get_file_size_human(size)
                        except Exception:
                            size_str = "?"
                        
                        results[parent].append({
                            'name': item.name,
                            'path': str(item),
                            'size': size_str,
                        })
                
                elif item.is_dir() and not item.name.startswith('.'):
                    scan_dir(item, depth + 1)
        
        except PermissionError:
            pass
    
    scan_dir(folder_path)
    return results


def display_all_wordlists():
    """Scan and display ALL wordlists from common locations."""
    console.print("\n[bold cyan]ICARUS-X Wordlist Scanner[/bold cyan]\n")
    console.print("[dim]Scanning all wordlist folders...[/dim]\n")
    
    # Scan all wordlist locations (directories only!)
    locations = [
        ("/usr/share/wordlists", "System Wordlists"),
        ("/usr/share/seclists", "SecLists"),
        ("/usr/share/dirb/wordlists", "Dirb Wordlists"),
        ("/usr/share/dirbuster/wordlists", "DirBuster Wordlists"),
        ("/usr/share/wfuzz/wordlist", "wFuzz Wordlists"),
        ("/usr/share/metasploit-framework/data/wordlists", "Metasploit Wordlists"),
        ("/usr/share/john", "John Wordlists"),
    ]
    
    total_files = 0
    
    for folder, name in locations:
        folder_path = Path(folder)
        if not folder_path.exists() or not folder_path.is_dir():
            continue
        
        results = scan_wordlist_folder(folder, max_depth=4)

        
        if not results:
            continue
        
        # Count files
        file_count = sum(len(files) for files in results.values())
        total_files += file_count
        
        # Create tree
        tree = Tree(f"[bold cyan]{name}[/bold cyan] [dim]({folder})[/dim] - [yellow]{file_count} files[/yellow]")
        
        for subdir, files in sorted(results.items()):
            if subdir == 'Root':
                branch = tree
            else:
                branch = tree.add(f"[yellow]{subdir}/[/yellow]")
            
            # Limit files shown per directory
            shown = 0
            for f in files[:15]:
                branch.add(f"[white]{f['name']}[/white] [dim]({f['size']})[/dim]")
                shown += 1
            
            if len(files) > 15:
                branch.add(f"[dim]... and {len(files) - 15} more files[/dim]")
        
        console.print(tree)
        console.print()
    
    console.print(f"[bold green]Total: {total_files} wordlist files found[/bold green]\n")


def display_folder_contents(folder: str):
    """Display contents of a specific wordlist folder."""
    console.print(f"\n[bold cyan]Wordlists in: {folder}[/bold cyan]\n")
    
    results = scan_wordlist_folder(folder, max_depth=5)
    
    if not results:
        console.print(f"[yellow]Folder not found or empty: {folder}[/yellow]")
        return
    
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Folder", style="yellow")
    table.add_column("Name", style="white")
    table.add_column("Size", justify="right", style="dim")
    table.add_column("Path", style="dim")
    
    for subdir, files in sorted(results.items()):
        for i, f in enumerate(files):
            folder_display = subdir if i == 0 else ""
            table.add_row(folder_display, f['name'], f['size'], f['path'])
    
    console.print(table)
    
    file_count = sum(len(files) for files in results.values())
    console.print(f"\n[dim]Total: {file_count} files[/dim]")


def list_wordlist_folders():
    """Show available wordlist folders and their status."""
    console.print("\n[bold cyan]Available Wordlist Locations[/bold cyan]\n")
    
    locations = [
        ("/usr/share/wordlists", "Main wordlists folder (rockyou, etc.)"),
        ("/usr/share/seclists", "SecLists collection"),
        ("/usr/share/dirb/wordlists", "Dirb wordlists"),
        ("/usr/share/dirbuster/wordlists", "DirBuster wordlists"),
        ("/usr/share/wfuzz/wordlist", "wFuzz wordlists"),
        ("/usr/share/metasploit-framework/data/wordlists", "Metasploit wordlists"),
        ("/usr/share/nmap/nselib/data", "Nmap NSE data"),
        ("/opt/SecLists", "Manual SecLists install"),
        (str(Path.home() / "wordlists"), "User wordlists"),
    ]
    
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Status", justify="center", width=8)
    table.add_column("Location", style="cyan")
    table.add_column("Description", style="dim")
    table.add_column("Files", justify="right")
    
    for path, desc in locations:
        exists = Path(path).exists()
        
        if exists:
            status = "[green]OK[/green]"
            # Count files (quick estimate)
            try:
                file_count = sum(1 for _ in Path(path).rglob('*.txt'))
            except Exception:
                file_count = 0
            count_str = str(file_count) if file_count > 0 else "-"
        else:
            status = "[red]--[/red]"
            count_str = "-"
        
        table.add_row(status, path, desc, count_str)
    
    console.print(table)
    console.print("\n[dim]Use 'wordlists --scan' to see all files[/dim]")
    console.print("[dim]Use 'wordlists --folder /path' to browse a folder[/dim]")

