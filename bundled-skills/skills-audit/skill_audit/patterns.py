"""
Malicious Pattern Library for Static Analysis

Defines regex patterns and signatures for detecting malicious skill behavior.
"""

import re
from typing import Dict, List, Tuple
from .schemas import RiskLevel, RiskCategory

# Pattern format: (pattern, description, severity, category)
PatternMatch = Tuple[str, str, RiskLevel, RiskCategory]


class MaliciousPatterns:
    """Library of malicious code patterns"""

    # Remote Code Execution Patterns
    REMOTE_EXEC_PATTERNS: List[Tuple[str, str, RiskLevel]] = [
        (
            r"curl\s+.*\|\s*(?:bash|sh|zsh|python|perl|ruby)",
            "Download and execute remote script",
            RiskLevel.CRITICAL,
        ),
        (
            r"wget\s+.*\|\s*(?:bash|sh|zsh|python|perl|ruby)",
            "Download and execute remote script via wget",
            RiskLevel.CRITICAL,
        ),
        (
            r"base64\s+(?:-D|--decode)\s*\|\s*(?:bash|sh|zsh)",
            "Base64 decode and execute (obfuscated backdoor)",
            RiskLevel.CRITICAL,
        ),
        (
            r"\|\s*base64\s+(?:-D|--decode)\s*\|\s*(?:bash|sh|zsh)",
            "Piped base64 decode and execute (obfuscated backdoor)",
            RiskLevel.CRITICAL,
        ),
        (r"\beval\s*\(", "Dangerous eval() usage", RiskLevel.HIGH),
        (r"\bexec\s*\(", "Dangerous exec() usage", RiskLevel.HIGH),
        (r"__import__\s*\(['\"]os['\"]", "Dynamic os module import", RiskLevel.MEDIUM),
        (
            r"subprocess\.(?:call|run|Popen).*shell\s*=\s*True",
            "Shell injection risk via subprocess",
            RiskLevel.HIGH,
        ),
        (r"os\.system\s*\(", "Unsafe os.system() call", RiskLevel.HIGH),
        (
            r"pickle\.loads?\s*\(",
            "Unsafe pickle deserialization (RCE risk)",
            RiskLevel.CRITICAL,
        ),
    ]

    # Obfuscation Patterns
    OBFUSCATION_PATTERNS: List[Tuple[str, str, RiskLevel]] = [
        (
            r"base64\.(?:b64decode|decodebytes)\s*\(",
            "Base64 decoding (possible obfuscation)",
            RiskLevel.MEDIUM,
        ),
        (
            r"(?:codecs\.decode|decode)\s*\([^,]+,\s*['\"]rot[_-]?13['\"]",
            "ROT13 decoding (obfuscation)",
            RiskLevel.MEDIUM,
        ),
        (
            r"compile\s*\([^,]+,\s*['\"]<string>['\"]",
            "Dynamic code compilation",
            RiskLevel.HIGH,
        ),
        (r"chr\s*\(\s*\d+\s*\)", "Character encoding (possible obfuscation)", RiskLevel.LOW),
        (r"\\x[0-9a-fA-F]{2}", "Hex-encoded strings", RiskLevel.LOW),
        (r"zlib\.decompress\s*\(", "Compressed data (possible payload)", RiskLevel.MEDIUM),
    ]

    # Network / Data Exfiltration Patterns
    NETWORK_PATTERNS: List[Tuple[str, str, RiskLevel]] = [
        (
            r"requests\.(?:get|post|put|delete)\s*\([^)]*(?:data|json|files)\s*=",
            "HTTP request with data payload",
            RiskLevel.MEDIUM,
        ),
        (
            r"urllib\.request\.urlopen\s*\(",
            "Outbound network connection",
            RiskLevel.MEDIUM,
        ),
        (
            r"socket\.(?:socket|create_connection)\s*\(",
            "Raw socket connection",
            RiskLevel.HIGH,
        ),
        (
            r"ftplib\.FTP\s*\(",
            "FTP connection (data exfiltration risk)",
            RiskLevel.HIGH,
        ),
        (r"smtplib\.SMTP\s*\(", "SMTP connection (email exfiltration)", RiskLevel.MEDIUM),
        (
            r"boto3\.client\s*\(['\"]s3['\"]",
            "AWS S3 access (data upload risk)",
            RiskLevel.MEDIUM,
        ),
        (
            r"paramiko\.(?:SSHClient|Transport)\s*\(",
            "SSH connection (remote access)",
            RiskLevel.HIGH,
        ),
    ]

    # Secret / Credential Access Patterns
    SECRET_ACCESS_PATTERNS: List[Tuple[str, str, RiskLevel]] = [
        (
            r"os\.environ\.get\s*\(\s*['\"].*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)['\"]",
            "Environment variable access (credential leak risk)",
            RiskLevel.HIGH,
        ),
        (
            r"getpass\.getpass\s*\(",
            "Password prompt (credential harvesting)",
            RiskLevel.MEDIUM,
        ),
        (
            r"open\s*\([^)]*['\"].*(?:\.ssh|\.aws|\.kube|id_rsa|credentials)['\"]",
            "Access to credential files",
            RiskLevel.CRITICAL,
        ),
        (
            r"keyring\.get_password\s*\(",
            "System keyring access",
            RiskLevel.MEDIUM,
        ),
        (
            r"(?:api[_-]?key|access[_-]?token|secret[_-]?key)\s*=\s*['\"][a-zA-Z0-9]{20,}['\"]",
            "Hardcoded API key/token",
            RiskLevel.HIGH,
        ),
    ]

    # File System Manipulation Patterns
    FILE_SYSTEM_PATTERNS: List[Tuple[str, str, RiskLevel]] = [
        (
            r"os\.(?:remove|unlink|rmdir)\s*\(",
            "File deletion operation",
            RiskLevel.MEDIUM,
        ),
        (
            r"shutil\.rmtree\s*\(",
            "Recursive directory deletion",
            RiskLevel.HIGH,
        ),
        (
            r"os\.chmod\s*\([^,]+,\s*0o?[47]",
            "Executable permission grant",
            RiskLevel.MEDIUM,
        ),
        (
            r"open\s*\([^)]*,\s*['\"][wa]['\"]",
            "File write operation",
            RiskLevel.LOW,
        ),
        (
            r"pathlib\.Path\s*\([^)]*\)\.(?:unlink|rmdir)",
            "Path-based file deletion",
            RiskLevel.MEDIUM,
        ),
    ]

    # Persistence / Backdoor Patterns
    PERSISTENCE_PATTERNS: List[Tuple[str, str, RiskLevel]] = [
        (
            r"cron|/etc/crontab|crontab\s+-e",
            "Cron job manipulation (persistence)",
            RiskLevel.CRITICAL,
        ),
        (
            r"\.bashrc|\.bash_profile|\.zshrc",
            "Shell profile modification (persistence)",
            RiskLevel.CRITICAL,
        ),
        (
            r"systemd|/etc/systemd/system",
            "Systemd service creation (persistence)",
            RiskLevel.CRITICAL,
        ),
        (
            r"launchd|/Library/LaunchAgents|/Library/LaunchDaemons",
            "macOS LaunchAgent/Daemon (persistence)",
            RiskLevel.CRITICAL,
        ),
        (
            r"HKEY_|winreg|_winreg",
            "Windows Registry access (persistence)",
            RiskLevel.HIGH,
        ),
    ]

    # Prompt Injection Patterns (in skill descriptions/prompts)
    PROMPT_INJECTION_PATTERNS: List[Tuple[str, str, RiskLevel]] = [
        (
            r"(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|constraints|security|safety)",
            "Prompt override instruction",
            RiskLevel.CRITICAL,
        ),
        (
            r"(?:you are now|act as|pretend to be)\s+(?:a different|an unrestricted|a jailbroken|in unrestricted)",
            "Role manipulation instruction",
            RiskLevel.CRITICAL,
        ),
        (
            r"(?:disable|bypass|turn off|remove)\s+(?:all\s+)?(?:safety|security|guardrails|filters|checks|constraints)",
            "Security bypass instruction",
            RiskLevel.CRITICAL,
        ),
        (
            r"unrestricted mode|jailbreak mode|developer mode|god mode",
            "Mode override instruction",
            RiskLevel.CRITICAL,
        ),
        (
            r"do not (?:ask|confirm|validate|check)",
            "Validation bypass instruction",
            RiskLevel.HIGH,
        ),
        (
            r"execute (?:any|all) (?:user )?commands? without",
            "Unrestricted execution instruction",
            RiskLevel.CRITICAL,
        ),
        (
            r"grant (?:full|root|admin|system) (?:access|privileges)",
            "Privilege escalation instruction",
            RiskLevel.CRITICAL,
        ),
        (
            r"(?:escalate|elevate) privileges",
            "Privilege escalation instruction",
            RiskLevel.CRITICAL,
        ),
        (
            r"expose (?:sensitive|secret|confidential) (?:data|information)",
            "Data exposure instruction",
            RiskLevel.CRITICAL,
        ),
        (
            r"</(?:system|instruction|context)>",
            "Instruction block closing (injection attempt)",
            RiskLevel.HIGH,
        ),
        (
            r"<\|im_start\|>|<\|im_end\|>",
            "Chat template manipulation",
            RiskLevel.HIGH,
        ),
        (
            r"(?:reveal|show|print)\s+(?:your|the)\s+(?:system prompt|instructions|rules)",
            "Prompt exfiltration attempt",
            RiskLevel.HIGH,
        ),
    ]

    # Privilege Escalation Patterns
    PRIVILEGE_ESCALATION_PATTERNS: List[Tuple[str, str, RiskLevel]] = [
        (r"sudo\s+", "Sudo command usage (privilege escalation)", RiskLevel.HIGH),
        (
            r"os\.setuid\s*\(0\)|os\.setgid\s*\(0\)",
            "UID/GID manipulation to root",
            RiskLevel.CRITICAL,
        ),
        (
            r"ctypes\..*CDLL.*libc",
            "Direct libc access (privilege escalation risk)",
            RiskLevel.HIGH,
        ),
        (r"/etc/passwd|/etc/shadow", "Password file access", RiskLevel.CRITICAL),
    ]

    # All patterns combined
    ALL_PATTERNS: Dict[RiskCategory, List[Tuple[str, str, RiskLevel]]] = {
        RiskCategory.REMOTE_CONTROL: REMOTE_EXEC_PATTERNS,
        RiskCategory.SUPPLY_CHAIN: OBFUSCATION_PATTERNS,
        RiskCategory.DATA_EXFILTRATION: NETWORK_PATTERNS + SECRET_ACCESS_PATTERNS,
        RiskCategory.UNSAFE_EXECUTION: REMOTE_EXEC_PATTERNS + FILE_SYSTEM_PATTERNS,
        RiskCategory.PROMPT_INJECTION: PROMPT_INJECTION_PATTERNS,
        RiskCategory.PRIVILEGE_ESCALATION: PRIVILEGE_ESCALATION_PATTERNS,
    }

    @classmethod
    def scan_text(
        cls, text: str, context: str = "code"
    ) -> List[Tuple[RiskCategory, str, str, RiskLevel, re.Match]]:
        """
        Scan text for malicious patterns.

        Args:
            text: Text to scan (code, prompt, description, etc.)
            context: Context type ("code", "prompt", "description")

        Returns:
            List of (category, pattern_desc, matched_text, severity, match_obj)
        """
        matches = []

        # Select pattern sets based on context
        if context == "prompt" or context == "description":
            # For prompts/descriptions, scan for:
            # 1. Prompt injection attacks
            # 2. Embedded command execution (malicious instructions to execute commands)
            pattern_sets = [
                (RiskCategory.PROMPT_INJECTION, cls.PROMPT_INJECTION_PATTERNS),
                (RiskCategory.UNSAFE_EXECUTION, cls.REMOTE_EXEC_PATTERNS),  # Also check for command execution
            ]
        else:
            # For code, scan all patterns
            pattern_sets = cls.ALL_PATTERNS.items()

        for category, patterns in pattern_sets:
            for pattern, description, severity in patterns:
                try:
                    for match in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE):
                        matched_text = match.group(0)
                        matches.append(
                            (category, description, matched_text, severity, match)
                        )
                except re.error as e:
                    # Skip invalid regex patterns
                    continue

        return matches

    @classmethod
    def extract_external_references(cls, text: str) -> Dict[str, List[str]]:
        """
        Extract external references (URLs, IPs, domains) from text.
        Also attempts to decode base64 content to find hidden references.

        Returns:
            Dict with keys: "urls", "ips", "domains"
        """
        import base64

        urls = []
        ips = []
        domains = []

        # Also scan decoded base64 content
        decoded_texts = [text]  # Start with original text

        # Try to decode base64 strings (common obfuscation technique)
        # Look for base64 patterns: long alphanumeric strings with +/= characters
        base64_pattern = r"[A-Za-z0-9+/]{20,}={0,2}"
        for match in re.finditer(base64_pattern, text):
            b64_str = match.group(0)
            try:
                # Try to decode
                decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
                # Only add if it looks like it contains useful data
                if any(c in decoded for c in ['http', 'ftp', '.', '/']):
                    decoded_texts.append(decoded)
            except Exception:
                # Invalid base64 or decode error, skip
                pass

        # Extract from all texts (original + decoded)
        for scan_text in decoded_texts:
            # URL pattern
            url_pattern = r"https?://[^\s<>\"'\)]+|ftp://[^\s<>\"'\)]+"
            for match in re.finditer(url_pattern, scan_text):
                urls.append(match.group(0))

            # IP pattern (IPv4)
            ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
            for match in re.finditer(ip_pattern, scan_text):
                ip = match.group(0)
                # Basic validation
                parts = ip.split(".")
                try:
                    if all(0 <= int(p) <= 255 for p in parts):
                        ips.append(ip)
                except ValueError:
                    pass

            # Domain pattern (basic)
            domain_pattern = r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b"
            for match in re.finditer(domain_pattern, scan_text, re.IGNORECASE):
                domain = match.group(0)
                # Exclude common false positives
                if not domain.endswith(
                    (
                        ".py",
                        ".txt",
                        ".json",
                        ".md",
                        ".example",
                        ".local",
                        ".test",
                        "localhost",
                    )
                ):
                    domains.append(domain)

        return {
            "urls": list(set(urls)),
            "ips": list(set(ips)),
            "domains": list(set(domains)),
        }


# Dangerous permission combinations
DANGEROUS_PERMISSION_COMBINATIONS = [
    (
        ["fs.write", "net.access"],
        "Write files + network access (data exfiltration risk)",
        RiskLevel.HIGH,
    ),
    (
        ["fs.read", "net.access"],
        "Read files + network access (data exfiltration risk)",
        RiskLevel.MEDIUM,
    ),
    (
        ["exec", "net.access"],
        "Execute code + network access (C2 risk)",
        RiskLevel.CRITICAL,
    ),
    (
        ["exec", "fs.write"],
        "Execute code + write files (persistence risk)",
        RiskLevel.HIGH,
    ),
    (
        ["admin", "net.access"],
        "Admin privileges + network access (full compromise)",
        RiskLevel.CRITICAL,
    ),
]
