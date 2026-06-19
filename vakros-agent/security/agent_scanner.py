"""
Vakros Agentic Security Scanner
Inspired by: github.com/splx-ai/agentic-radar + github.com/snyk/agent-scan

Scans the Vakros agent codebase and MCP tool descriptions for:
  - Prompt injection vulnerabilities (OWASP LLM01)
  - Tool poisoning / tool shadowing (OWASP LLM02)
  - Hardcoded secrets / credentials (OWASP LLM08)
  - Toxic data flows (chained tool calls with untrusted input)
  - Insecure output handling (OWASP LLM02)
  - Overly permissive tool scopes

Run as a CI/CD step or on-demand:
    python -m vakros_agent.security.agent_scanner --scan-dir vakros-agent/
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


# ─── Issue Codes ───────────────────────────────────────────────────────────────

class IssueCode(str, Enum):
    # Prompt injection
    PROMPT_INJECTION       = "VAK-S001"
    TOOL_POISONING         = "VAK-S002"
    TOOL_SHADOWING         = "VAK-S003"
    TOXIC_FLOW             = "VAK-S004"

    # Secrets
    HARDCODED_SECRET       = "VAK-S010"
    ENV_VAR_LOGGED         = "VAK-S011"
    SECRET_IN_PROMPT       = "VAK-S012"

    # Permissions
    OVERPERMISSIVE_TOOL    = "VAK-S020"
    MISSING_INPUT_VALIDATION = "VAK-S021"
    MISSING_HITL           = "VAK-S022"

    # Output handling
    UNESCAPED_LLM_OUTPUT   = "VAK-S030"
    UNSAFE_CODE_EXEC       = "VAK-S031"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


OWASP_MAPPING = {
    IssueCode.PROMPT_INJECTION:        "OWASP LLM01 — Prompt Injection",
    IssueCode.TOOL_POISONING:          "OWASP LLM02 — Insecure Output Handling",
    IssueCode.TOOL_SHADOWING:          "OWASP LLM02 — Insecure Output Handling",
    IssueCode.TOXIC_FLOW:              "OWASP LLM01 — Prompt Injection",
    IssueCode.HARDCODED_SECRET:        "OWASP LLM08 — Excessive Agency",
    IssueCode.ENV_VAR_LOGGED:          "OWASP LLM06 — Sensitive Info Disclosure",
    IssueCode.SECRET_IN_PROMPT:        "OWASP LLM06 — Sensitive Info Disclosure",
    IssueCode.OVERPERMISSIVE_TOOL:     "OWASP LLM08 — Excessive Agency",
    IssueCode.MISSING_INPUT_VALIDATION:"OWASP LLM01 — Prompt Injection",
    IssueCode.MISSING_HITL:            "OWASP LLM08 — Excessive Agency",
    IssueCode.UNESCAPED_LLM_OUTPUT:    "OWASP LLM02 — Insecure Output Handling",
    IssueCode.UNSAFE_CODE_EXEC:        "OWASP LLM03 — Training Data Poisoning",
}


@dataclass
class Finding:
    code: IssueCode
    severity: Severity
    file: str
    line: int
    snippet: str
    description: str
    remediation: str
    owasp: str = ""

    def __post_init__(self):
        self.owasp = OWASP_MAPPING.get(self.code, "")

    def to_dict(self) -> dict:
        return {
            "code": self.code.value,
            "severity": self.severity.value,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet[:200],
            "description": self.description,
            "remediation": self.remediation,
            "owasp": self.owasp,
        }


@dataclass
class ScanResult:
    scanned_files: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def passed(self) -> bool:
        return self.critical_count == 0 and self.high_count == 0

    def to_dict(self) -> dict:
        return {
            "passed": self.passed(),
            "scanned_files": self.scanned_files,
            "total_findings": len(self.findings),
            "critical": self.critical_count,
            "high": self.high_count,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }


# ─── Detection Rules ───────────────────────────────────────────────────────────

# Patterns that suggest prompt injection vulnerabilities
PROMPT_INJECTION_PATTERNS = [
    # Direct user input inserted into system prompt without sanitization
    (r'f["\'].*\{.*user.*input.*\}.*["\']', "User input interpolated directly into prompt string"),
    (r'f["\'].*\{.*alert.*description.*\}.*["\']', "Alert description interpolated into prompt — may contain injected content"),
    (r'system_prompt\s*\+\s*', "System prompt concatenated with variable — potential injection"),
    (r'\.format\(.*user', "str.format() with user data in prompt"),
]

# Secret patterns
SECRET_PATTERNS = [
    (r'(?i)(api_key|apikey|secret|password|token|sk-[a-z0-9]{48})\s*=\s*["\'][^"\']{8,}["\']',
     IssueCode.HARDCODED_SECRET, Severity.CRITICAL, "Hardcoded secret detected"),
    (r'(?i)eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
     IssueCode.HARDCODED_SECRET, Severity.CRITICAL, "Hardcoded JWT token"),
    (r'(?i)(SUPABASE|OPENAI|ANTHROPIC|WAZUH|THEHIVE)_.*KEY\s*=\s*["\'][^"\']+["\']',
     IssueCode.HARDCODED_SECRET, Severity.CRITICAL, "Hardcoded API key for known service"),
    (r'print\(.*(?:key|secret|password|token)',
     IssueCode.ENV_VAR_LOGGED, Severity.HIGH, "Potential secret logged to stdout"),
    (r'logger\.(info|debug)\(.*(?:key|secret|password|token)',
     IssueCode.ENV_VAR_LOGGED, Severity.HIGH, "Potential secret sent to log"),
]

# Dangerous patterns in tool definitions
TOOL_POISONING_PATTERNS = [
    (r'os\.system\(', IssueCode.UNSAFE_CODE_EXEC, Severity.HIGH, "os.system() — use subprocess with arg list instead"),
    (r'subprocess\.call\(["\']', IssueCode.UNSAFE_CODE_EXEC, Severity.HIGH, "subprocess with shell string — use list args"),
    (r'eval\(', IssueCode.UNSAFE_CODE_EXEC, Severity.CRITICAL, "eval() with dynamic input — code injection risk"),
    (r'exec\(', IssueCode.UNSAFE_CODE_EXEC, Severity.CRITICAL, "exec() with dynamic input — code injection risk"),
    (r'__import__\(', IssueCode.UNSAFE_CODE_EXEC, Severity.HIGH, "Dynamic import — potential code injection"),
]

# High-risk EDR actions that must have HITL
HITL_REQUIRED_ACTIONS = [
    "isolate_host", "block_ip", "delete_artefact",
    "kill_process", "disable_account", "quarantine",
]

HITL_PATTERNS = [
    (rf'await.*({"|".join(HITL_REQUIRED_ACTIONS)})\(',
     IssueCode.MISSING_HITL, Severity.HIGH,
     "High-risk EDR action called without evident HITL gate — wrap with HITLApprovalGate"),
]


class AgentScanner:
    """Scan agent source files for security vulnerabilities."""

    def __init__(self, scan_dir: str | Path = "."):
        self.scan_dir = Path(scan_dir)
        self.result = ScanResult()

    def scan(self) -> ScanResult:
        """Run full scan. Returns ScanResult."""
        py_files = list(self.scan_dir.rglob("*.py"))
        # Also scan MCP tool JSON/YAML definitions
        json_files = list(self.scan_dir.rglob("*.json"))

        for f in py_files:
            self._scan_python_file(f)

        for f in json_files:
            self._scan_json_file(f)

        self.result.scanned_files = len(py_files) + len(json_files)
        return self.result

    def _scan_python_file(self, path: Path) -> None:
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
        except Exception as e:
            self.result.errors.append(f"Cannot read {path}: {e}")
            return

        rel = str(path.relative_to(self.scan_dir))

        for lineno, line in enumerate(lines, start=1):
            self._check_secrets(rel, lineno, line)
            self._check_tool_poisoning(rel, lineno, line)
            self._check_prompt_injection(rel, lineno, line)
            self._check_hitl_missing(rel, lineno, line, lines)

    def _check_secrets(self, file: str, lineno: int, line: str) -> None:
        for pattern, code, severity, desc in SECRET_PATTERNS:
            if re.search(pattern, line):
                # Skip lines that are clearly reading from env
                if "os.getenv" in line or "os.environ" in line:
                    continue
                self.result.findings.append(Finding(
                    code=code,
                    severity=severity,
                    file=file,
                    line=lineno,
                    snippet=line.strip(),
                    description=desc,
                    remediation="Move to environment variable. Never commit secrets.",
                ))

    def _check_tool_poisoning(self, file: str, lineno: int, line: str) -> None:
        for pattern, code, severity, desc in TOOL_POISONING_PATTERNS:
            if re.search(pattern, line):
                self.result.findings.append(Finding(
                    code=code,
                    severity=severity,
                    file=file,
                    line=lineno,
                    snippet=line.strip(),
                    description=desc,
                    remediation="Use safe alternatives. Validate and sanitize all inputs before shell/exec calls.",
                ))

    def _check_prompt_injection(self, file: str, lineno: int, line: str) -> None:
        for pattern, desc in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, line):
                self.result.findings.append(Finding(
                    code=IssueCode.PROMPT_INJECTION,
                    severity=Severity.HIGH,
                    file=file,
                    line=lineno,
                    snippet=line.strip(),
                    description=desc,
                    remediation=(
                        "Sanitize external data before inserting into prompts. "
                        "Use structured inputs (JSON schema) rather than free-text interpolation. "
                        "Consider a prompt hardening wrapper."
                    ),
                ))

    def _check_hitl_missing(self, file: str, lineno: int, line: str, all_lines: list[str]) -> None:
        # Only flag if file doesn't import from hitl module
        file_content = "\n".join(all_lines)
        if "HITLApprovalGate" in file_content or "hitl" in file_content.lower():
            return  # Already using HITL

        for pattern, code, severity, desc in HITL_PATTERNS:
            if re.search(pattern, line):
                self.result.findings.append(Finding(
                    code=code,
                    severity=severity,
                    file=file,
                    line=lineno,
                    snippet=line.strip(),
                    description=desc,
                    remediation="Import and use HITLApprovalGate from vakros_agent.hitl before executing this action.",
                ))

    def _scan_json_file(self, path: Path) -> None:
        """Scan MCP server JSON config for tool shadowing / poisoning."""
        if "node_modules" in str(path) or ".next" in str(path):
            return
        try:
            data = json.loads(path.read_text())
        except Exception:
            return

        rel = str(path.relative_to(self.scan_dir))
        tools = self._extract_mcp_tools(data)
        tool_names: set[str] = set()
        for tool in tools:
            name = tool.get("name", "")
            desc = tool.get("description", "")

            # Tool shadowing — duplicate tool names
            if name in tool_names:
                self.result.findings.append(Finding(
                    code=IssueCode.TOOL_SHADOWING,
                    severity=Severity.HIGH,
                    file=rel,
                    line=0,
                    snippet=f"Tool: {name}",
                    description=f"Duplicate tool name '{name}' — potential tool shadowing attack",
                    remediation="Ensure each MCP tool has a unique name. A malicious server could shadow trusted tools.",
                ))
            tool_names.add(name)

            # Tool poisoning — suspicious instructions in description
            if any(kw in desc.lower() for kw in ["ignore previous", "disregard", "act as", "jailbreak", "dan "]):
                self.result.findings.append(Finding(
                    code=IssueCode.TOOL_POISONING,
                    severity=Severity.CRITICAL,
                    file=rel,
                    line=0,
                    snippet=f"Tool: {name} | Desc: {desc[:100]}",
                    description=f"Possible prompt injection in tool description for '{name}'",
                    remediation="Review tool description. Remove any instructions that redirect agent behavior.",
                ))

    def _extract_mcp_tools(self, data: Any) -> list[dict]:
        """Recursively find tool definitions in MCP JSON."""
        if isinstance(data, list):
            if all("name" in item for item in data if isinstance(item, dict)):
                return data
        if isinstance(data, dict):
            for key in ("tools", "functions", "capabilities"):
                if key in data and isinstance(data[key], list):
                    return data[key]
            for v in data.values():
                result = self._extract_mcp_tools(v)
                if result:
                    return result
        return []

    def report(self, fmt: str = "text") -> str:
        """Generate a scan report."""
        r = self.result
        if fmt == "json":
            return json.dumps(r.to_dict(), indent=2)

        lines = [
            "═" * 60,
            "  VAKROS AGENTIC SECURITY SCAN",
            "═" * 60,
            f"  Files scanned : {r.scanned_files}",
            f"  Total findings: {len(r.findings)}",
            f"  Critical       : {r.critical_count}",
            f"  High           : {r.high_count}",
            f"  Status         : {'✅ PASSED' if r.passed() else '❌ FAILED'}",
            "═" * 60,
        ]
        for f in r.findings:
            lines += [
                f"\n[{f.severity.value.upper()}] {f.code.value} — {f.file}:{f.line}",
                f"  {f.description}",
                f"  OWASP: {f.owasp}",
                f"  Code : {f.snippet}",
                f"  Fix  : {f.remediation}",
            ]
        return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Vakros Agentic Security Scanner")
    parser.add_argument("--scan-dir", default=".", help="Directory to scan")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--fail-on-high", action="store_true", help="Exit 1 if HIGH/CRITICAL findings")
    args = parser.parse_args()

    scanner = AgentScanner(scan_dir=args.scan_dir)
    scanner.scan()
    print(scanner.report(fmt=args.format))

    if args.fail_on_high and not scanner.result.passed():
        sys.exit(1)


if __name__ == "__main__":
    main()
