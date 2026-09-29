"""Source code static analysis scanner — endpoint discovery + secret detection + vuln patterns."""
import os
import re
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

SECRET_PATTERNS = [
    ("AWS_ACCESS_KEY",   r'AKIA[0-9A-Z]{16}',                                          "CRITICAL"),
    ("AWS_SECRET_KEY",   r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})',      "CRITICAL"),
    ("GITHUB_TOKEN",     r'ghp_[A-Za-z0-9]{36}',                                       "HIGH"),
    ("GITHUB_OAUTH",     r'gho_[A-Za-z0-9]{36}',                                       "HIGH"),
    ("PRIVATE_KEY",      r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',               "CRITICAL"),
    ("GENERIC_PASSWORD", r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{6,}["\']',      "HIGH"),
    ("GENERIC_API_KEY",  r'(?i)(api[_-]?key|apikey|api[_-]?secret)\s*=\s*["\'][^"\']{8,}["\']', "HIGH"),
    ("STRIPE_KEY",       r'sk_(live|test)_[A-Za-z0-9]{24,}',                          "CRITICAL"),
    ("JWT_SECRET",       r'(?i)(jwt[_-]?secret|jwt[_-]?key)\s*=\s*["\'][^"\']{8,}["\']', "HIGH"),
    ("HARDCODED_TOKEN",  r'(?i)(auth[_-]?token|bearer[_-]?token)\s*=\s*["\'][^"\']{16,}["\']', "HIGH"),
]

ENDPOINT_PATTERNS = {
    ".py": [
        (r'@(?:app|router|blueprint)\.(get|post|put|patch|delete|options)\(["\']([^"\']+)["\']', "FASTAPI/FLASK"),
        (r'path\(["\']([^"\']+)["\']', "DJANGO"),
    ],
    ".java": [
        (r'@(?:Get|Post|Put|Delete|Patch|Request)Mapping\(["\']?([^"\')\s]+)["\']?\)', "SPRING"),
        (r'@Path\(["\']([^"\']+)["\']', "JAX-RS"),
    ],
    ".go": [
        (r'(?:HandleFunc|Handle)\(["\']([^"\']+)["\']', "NET/HTTP"),
        (r'\.(?:GET|POST|PUT|DELETE|PATCH)\(["\']([^"\']+)["\']', "GIN/ECHO"),
    ],
    ".js": [
        (r'(?:app|router)\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']', "EXPRESS"),
    ],
    ".ts": [
        (r'(?:app|router)\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']', "EXPRESS-TS"),
        (r'@(?:Get|Post|Put|Delete|Patch)\(["\']([^"\']+)["\']', "NESTJS"),
    ],
}

VULN_PATTERNS = [
    ("SQL_INJECTION",  r'(?i)(execute|query|cursor\.execute)\s*\(\s*["\'].*%[s|d].*["\']', "HIGH"),
    ("SQL_INJECTION",  r'(?i)f["\'].*SELECT.*FROM.*\{', "HIGH"),
    ("PATH_TRAVERSAL", r'(?i)open\s*\([^)]*\+\s*(?:request|param|input|user)', "HIGH"),
    ("XXE",            r'(?i)(etree\.fromstring|parseString)\s*\(', "MEDIUM"),
    ("COMMAND_INJECT", r'(?i)(os\.system|subprocess\.call|eval)\s*\([^)]*(?:request|param|input|user)', "CRITICAL"),
    ("INSECURE_DESER", r'(?i)(pickle\.loads|yaml\.load\s*\(|marshal\.loads)', "HIGH"),
]

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build', 'target', '.idea'}
MAX_FILE_SIZE = 500 * 1024


def _snippet(lines: List[str], line_no: int, ctx: int = 2) -> str:
    start = max(0, line_no - ctx - 1)
    end = min(len(lines), line_no + ctx)
    return "\n".join(f"{i+1}: {l.rstrip()}" for i, l in enumerate(lines[start:end], start=start))


def _remediation(vuln: str) -> str:
    remap = {
        "SQL_INJECTION": "Use parameterized queries or ORM. Never concatenate user input into SQL.",
        "PATH_TRAVERSAL": "Validate paths with os.path.realpath; restrict to allowed directory.",
        "XXE": "Disable external entity processing; use defusedxml in Python.",
        "COMMAND_INJECT": "Avoid shell=True; use subprocess list args; never pass user input to shell.",
        "INSECURE_DESER": "Avoid pickle/marshal for untrusted data; use JSON with schema validation.",
    }
    return remap.get(vuln, "Review and fix the identified pattern.")


def scan_directory(root_path: str, account_id: int | None = None, repo_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Walk root_path and return findings compatible with SourceCodeFinding model."""
    if account_id is None:
        raise ValueError("account_id is required")
    findings: List[Dict[str, Any]] = []
    root = Path(root_path)
    if not root.exists():
        logger.warning(f"Path does not exist: {root_path}")
        return findings

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            filepath = Path(dirpath) / filename
            ext = filepath.suffix.lower()
            if ext not in {'.py', '.java', '.go', '.js', '.ts', '.env', '.yml', '.yaml', '.json', '.xml', '.properties', '.conf'}:
                continue
            try:
                if filepath.is_symlink():
                    continue
                if filepath.stat().st_size > MAX_FILE_SIZE:
                    continue
                content = filepath.read_text(encoding='utf-8', errors='ignore')
                lines = content.splitlines()
                rel = str(filepath.relative_to(root))

                # Secrets
                for name, pattern, severity in SECRET_PATTERNS:
                    for m in re.finditer(pattern, content):
                        ln = content[:m.start()].count('\n') + 1
                        findings.append({
                            "account_id": account_id, "repo_id": repo_id,
                            "file_path": rel, "line_number": ln,
                            "finding_type": "SECRET_LEAK", "severity": severity,
                            "title": f"Secret: {name}",
                            "description": f"{name} found. Match: {m.group()[:80]}",
                            "code_snippet": _snippet(lines, ln),
                            "remediation": "Remove secret. Use environment variables or a secrets manager.",
                            "status": "OPEN",
                        })

                # Endpoints
                for pat, framework in ENDPOINT_PATTERNS.get(ext, []):
                    for m in re.finditer(pat, content, re.IGNORECASE):
                        ln = content[:m.start()].count('\n') + 1
                        path = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(1)
                        findings.append({
                            "account_id": account_id, "repo_id": repo_id,
                            "file_path": rel, "line_number": ln,
                            "finding_type": "ENDPOINT_DISCOVERED", "severity": "INFO",
                            "title": f"Endpoint: {path}",
                            "description": f"API endpoint via {framework} in {rel}",
                            "code_snippet": _snippet(lines, ln),
                            "remediation": "Verify endpoint is in API inventory.",
                            "status": "OPEN",
                        })

                # Vuln patterns
                if ext in {'.py', '.java', '.go', '.js', '.ts'}:
                    for name, pattern, severity in VULN_PATTERNS:
                        for m in re.finditer(pattern, content, re.IGNORECASE):
                            ln = content[:m.start()].count('\n') + 1
                            findings.append({
                                "account_id": account_id, "repo_id": repo_id,
                                "file_path": rel, "line_number": ln,
                                "finding_type": "VULN_PATTERN", "severity": severity,
                                "title": f"Potential {name.replace('_', ' ').title()}",
                                "description": f"{name} pattern: {m.group()[:120]}",
                                "code_snippet": _snippet(lines, ln),
                                "remediation": _remediation(name),
                                "status": "OPEN",
                            })
            except Exception as e:
                logger.debug(f"Skipping {filepath}: {e}")

    return findings
