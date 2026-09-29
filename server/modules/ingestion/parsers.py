import datetime
import re
from urllib.parse import unquote

_LOG_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[^"]+"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)
_LOG_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"

_ATTACK_SIGNATURES = [
    (re.compile(r"(union\s+select|select\s+.*from|insert\s+into|drop\s+table|'.*or\s+'1'='1|;--)", re.I), "SQL Injection", "HIGH"),
    (re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(|<iframe)", re.I), "XSS", "HIGH"),
    (re.compile(r"(\.\./|\.\.%2f|%2e%2e/|/etc/passwd|/etc/shadow|/proc/self)", re.I), "Path Traversal", "CRITICAL"),
    (re.compile(r"(;\s*(ls|cat|whoami|id|wget|curl|bash|sh)\b|&&|\|\s*(cat|ls|id))", re.I), "Command Injection", "CRITICAL"),
    (re.compile(r"(\bexec\b|\beval\b|base64_decode|system\s*\(|passthru\s*\()", re.I), "Code Injection", "CRITICAL"),
    (re.compile(r"(\bscanner\b|nikto|nmap|sqlmap|dirbuster|gobuster|nuclei)", re.I), "Scanning Tool", "MEDIUM"),
    (re.compile(r"(wp-admin|phpMyAdmin|\.env|\.git/config|web\.config|\.htaccess)", re.I), "Sensitive File Access", "HIGH"),
    (re.compile(r"(AND\s+\d+=\d+|OR\s+\d+=\d+|WAITFOR\s+DELAY|SLEEP\s*\()", re.I), "Blind SQLi", "CRITICAL"),
    (re.compile(r"(\bLDAP\b|ldap://|CN=|DC=)", re.I), "LDAP Injection", "HIGH"),
    (re.compile(r"(file://|gopher://|dict://|ftp://|sftp://)", re.I), "SSRF", "CRITICAL"),
]


def parse_log_line(line: str) -> dict | None:
    m = _LOG_RE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.datetime.strptime(m.group("time"), _LOG_TIME_FMT)
    except Exception:
        ts = datetime.datetime.now(datetime.timezone.utc)
    return {
        "ip":     m.group("ip"),
        "time":   ts,
        "method": m.group("method"),
        "path":   m.group("path"),
        "status": int(m.group("status")),
        "bytes":  m.group("bytes"),
        "referer": m.group("referer") or "",
        "ua":     m.group("ua") or "",
    }


def detect_attacks(path: str, ua: str) -> list[dict]:
    # Recursive unquote to catch double/triple encoding bypasses
    target = path + " " + (ua or "")
    prev = None
    curr = target
    for _ in range(3): # Limit depth
        prev = curr
        curr = unquote(curr)
        if curr == prev:
            break
    
    found = []
    for pattern, category, severity in _ATTACK_SIGNATURES:
        if pattern.search(curr):
            found.append({"category": category, "severity": severity})
    return found
