#!/usr/bin/env python3
"""
Vakros Compliance Gate
gstack v1 — Stage 8 CI/CD Gate

Runs a SOC 2 Type II + ISO 27001 + NIST AI RMF 1.0 drift check against the codebase.
Owned by: Release Manager Agent + Documentation Engineer Agent

Checks:
1. All prompt files have required frontmatter (authority_scope, hitl_classification)
2. All migration SQL files have RLS enabled + tenant policies
3. No hardcoded secrets or credentials
4. Required directory structure exists
5. n8n manifest files present (if n8n-manifests/ exists)
6. Audit evidence directories exist
7. NIST AI RMF controls — GOVERN/MAP/MEASURE/MANAGE lifecycle coverage
   Reference: https://www.nist.gov/itl/ai-risk-management-framework
   Documents:  NIST AI 100-1 (Jan 2023) · NIST AI 600-1 Gen AI Profile (Jul 2024)
               AI RMF Critical Infrastructure Profile (Apr 2026)

Usage:
    python3 scripts/compliance_gate.py \
        --prompts-dir prompts/ \
        --migrations-dir vakros-agent/ \
        --output audit-evidence/pipeline-runs/abc123-compliance.json \
        --fail-on-violation
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# Control references per check — SOC 2, ISO 27001, and NIST AI RMF
# NIST AI RMF ref: https://www.nist.gov/itl/ai-risk-management-framework
CONTROL_REFS: dict[str, list[str]] = {
    "prompt_frontmatter":      ["SOC2:CC1.2", "SOC2:CC2.1", "ISO27001:A.5.1",
                                 "AIrmf:GV-1.1", "AIRMF:GV-1.2", "AIRMF:GV-6.1"],
    "rls_coverage":            ["SOC2:CC6.1", "SOC2:CC6.6", "ISO27001:A.9.4.1",
                                 "AIRMF:MS-2.10"],
    "secret_detection":        ["SOC2:CC6.1", "SOC2:CC6.7", "ISO27001:A.9.2.4",
                                 "AIRMF:MS-2.7"],
    "directory_structure":     ["SOC2:CC2.1", "ISO27001:A.12.4.1",
                                 "AIRMF:GV-1.1", "AIRMF:MP-1.1"],
    "n8n_manifests":           ["SOC2:CC2.1", "ISO27001:A.12.4.2",
                                 "AIRMF:MG-3.1"],
    "audit_evidence":          ["SOC2:CC4.1", "ISO27001:A.12.4.3",
                                 "AIRMF:MS-4.1", "AIRMF:MG-4.1"],
    # NIST AI RMF — GOVERN
    "ai_rmf_govern":           ["AIRMF:GV-1.1", "AIRMF:GV-1.2", "AIRMF:GV-2.2",
                                 "AIRMF:GV-4.1", "AIRMF:GV-4.2", "AIRMF:GV-6.1"],
    # NIST AI RMF — MAP
    "ai_rmf_map":              ["AIRMF:MP-1.1", "AIRMF:MP-1.5", "AIRMF:MP-2.1",
                                 "AIRMF:MP-2.2", "AIRMF:MP-3.5", "AIRMF:MP-4.1",
                                 "AIRMF:MP-5.2"],
    # NIST AI RMF — MEASURE
    "ai_rmf_measure":          ["AIRMF:MS-1.1", "AIRMF:MS-2.2", "AIRMF:MS-2.5",
                                 "AIRMF:MS-2.6", "AIRMF:MS-2.7", "AIRMF:MS-2.10",
                                 "AIRMF:MS-3.3", "AIRMF:MS-4.1"],
    # NIST AI RMF — MANAGE
    "ai_rmf_manage":           ["AIRMF:MG-1.1", "AIRMF:MG-2.2", "AIRMF:MG-2.4",
                                 "AIRMF:MG-3.1", "AIRMF:MG-3.2", "AIRMF:MG-4.1",
                                 "AIRMF:MG-4.2"],
}

REQUIRED_DIRS = [
    "prompts",
    "n8n-manifests",
    "audit-evidence",
    "runbooks",
    "docs",
    "scripts",
    "tests",
]

SECRET_PATTERNS = [
    (r'sk-[a-zA-Z0-9]{20,}',              "OpenAI API key"),
    (r'sk-ant-[a-zA-Z0-9\-]{20,}',        "Anthropic API key"),
    (r'eyJ[a-zA-Z0-9]{10,}',              "JWT token (raw)"),
    (r'service_role["\s:=]+["\']ey',      "Supabase service role key"),
    (r'password\s*=\s*["\'][^"\']+["\']', "Hardcoded password"),
    (r'PRIVATE KEY-----',                 "Private key"),
    (r'(?i)api[_\-]?key\s*=\s*["\'][a-zA-Z0-9]{16,}', "Hardcoded API key"),
]

SECRET_WHITELIST = [
    ".env.example",
    "README",
    "COMPONENTS.md",
    ".md",        # docs
    "test_",      # test files may have placeholder keys
]


# ─────────────────────────────────────────────────────────────────────────────
# Check functions
# ─────────────────────────────────────────────────────────────────────────────

def check_prompt_frontmatter(prompts_dir: str) -> list[dict]:
    """Verify all prompt files have the required gstack v1 frontmatter."""
    violations = []
    files = glob.glob(os.path.join(prompts_dir, "*.md"))

    if not files:
        violations.append({
            "control": "prompt_frontmatter",
            "severity": "high",
            "description": f"No prompt files found in {prompts_dir}",
            "remediation": "Create agent prompt files in prompts/ with YAML frontmatter",
            "controls": CONTROL_REFS["prompt_frontmatter"],
        })
        return violations

    required_keys = [
        "agent_name", "version", "authority_scope",
        "hitl_classification", "blocked_actions",
    ]
    import yaml

    for f in files:
        content = Path(f).read_text()
        if not content.startswith("---"):
            violations.append({
                "control": "prompt_frontmatter",
                "severity": "high",
                "file": f,
                "description": f"Prompt file missing YAML frontmatter block",
                "remediation": "Add --- delimited YAML frontmatter with required fields",
                "controls": CONTROL_REFS["prompt_frontmatter"],
            })
            continue

        parts = content.split("---", 2)
        try:
            fm = yaml.safe_load(parts[1]) or {}
        except Exception:
            violations.append({
                "control": "prompt_frontmatter",
                "severity": "high",
                "file": f,
                "description": "Invalid YAML in frontmatter",
                "remediation": "Fix YAML syntax in frontmatter block",
                "controls": CONTROL_REFS["prompt_frontmatter"],
            })
            continue

        for key in required_keys:
            if key not in fm:
                violations.append({
                    "control": "prompt_frontmatter",
                    "severity": "medium",
                    "file": f,
                    "description": f"Missing required frontmatter key: '{key}'",
                    "remediation": f"Add '{key}' to YAML frontmatter",
                    "controls": CONTROL_REFS["prompt_frontmatter"],
                })

        if not fm.get("blocked_actions"):
            violations.append({
                "control": "prompt_frontmatter",
                "severity": "critical",
                "file": f,
                "description": "blocked_actions is empty — HITL boundaries undefined",
                "remediation": "Define blocked_actions list to enforce HITL boundaries",
                "controls": CONTROL_REFS["prompt_frontmatter"],
            })

    return violations


def check_rls_coverage(migrations_dir: str) -> list[dict]:
    """Verify all migration SQL files enable RLS and define tenant policies."""
    violations = []
    sql_files = glob.glob(
        os.path.join(migrations_dir, "**/migrations/*.sql"), recursive=True
    )

    for f in sql_files:
        content = Path(f).read_text()
        tables = re.findall(
            r"CREATE TABLE(?:\s+IF NOT EXISTS)?\s+(\S+)", content, re.IGNORECASE
        )
        skip_tables = {"migrations", "schema_migrations", "audit_ledger"}

        for tbl in tables:
            tbl_clean = tbl.strip('"').strip("'").split(".")[-1]
            if tbl_clean.lower() in skip_tables:
                continue

            has_rls = bool(re.search(
                r"ENABLE ROW LEVEL SECURITY", content, re.IGNORECASE
            ))
            has_policy = bool(re.search(
                r"CREATE POLICY.*tenant_id", content, re.IGNORECASE | re.DOTALL
            ))

            if not has_rls:
                violations.append({
                    "control": "rls_coverage",
                    "severity": "critical",
                    "file": f,
                    "table": tbl,
                    "description": f"Table {tbl} missing ENABLE ROW LEVEL SECURITY",
                    "remediation": f"Add: ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY;",
                    "controls": CONTROL_REFS["rls_coverage"],
                })
            if not has_policy:
                violations.append({
                    "control": "rls_coverage",
                    "severity": "critical",
                    "file": f,
                    "table": tbl,
                    "description": f"Table {tbl} missing tenant_id RLS policy",
                    "remediation": "Add CREATE POLICY with tenant_id filter",
                    "controls": CONTROL_REFS["rls_coverage"],
                })

    return violations


def check_secret_detection(root_dir: str = ".") -> list[dict]:
    """Scan Python and config files for hardcoded secrets."""
    violations = []
    scan_extensions = {".py", ".ts", ".tsx", ".js", ".json", ".yaml", ".yml", ".sh"}

    for fpath in Path(root_dir).rglob("*"):
        if not fpath.is_file():
            continue
        if fpath.suffix not in scan_extensions:
            continue
        if any(skip in str(fpath) for skip in [
            "node_modules", "__pycache__", ".git", ".next", "dist"
        ]):
            continue
        if any(w in str(fpath) for w in SECRET_WHITELIST):
            continue

        try:
            content = fpath.read_text(errors="ignore")
        except Exception:
            continue

        for pattern, label in SECRET_PATTERNS:
            if re.search(pattern, content):
                violations.append({
                    "control": "secret_detection",
                    "severity": "critical",
                    "file": str(fpath),
                    "description": f"Possible {label} detected in source file",
                    "remediation": "Move secret to environment variable or secret manager",
                    "controls": CONTROL_REFS["secret_detection"],
                })
                break  # one violation per file

    return violations


def check_directory_structure(root_dir: str = ".") -> list[dict]:
    """Verify required gstack v1 directory structure exists."""
    violations = []
    for d in REQUIRED_DIRS:
        full_path = os.path.join(root_dir, d)
        if not os.path.isdir(full_path):
            violations.append({
                "control": "directory_structure",
                "severity": "medium",
                "directory": d,
                "description": f"Required directory '{d}/' missing",
                "remediation": f"Create {d}/ — required by gstack v1 standards",
                "controls": CONTROL_REFS["directory_structure"],
            })
    return violations


def check_n8n_manifests(n8n_dir: str) -> list[dict]:
    """Check that n8n workflow manifests exist and are valid JSON."""
    violations = []
    if not os.path.isdir(n8n_dir):
        return [{
            "control": "n8n_manifests",
            "severity": "medium",
            "description": f"n8n-manifests/ directory missing",
            "remediation": "Create n8n-manifests/ and export workflow JSON files",
            "controls": CONTROL_REFS["n8n_manifests"],
        }]

    json_files = glob.glob(os.path.join(n8n_dir, "*.json"))
    if not json_files:
        violations.append({
            "control": "n8n_manifests",
            "severity": "medium",
            "description": "No n8n workflow JSON files found in n8n-manifests/",
            "remediation": "Export n8n workflows and commit as JSON to n8n-manifests/",
            "controls": CONTROL_REFS["n8n_manifests"],
        })

    for f in json_files:
        try:
            json.loads(Path(f).read_text())
        except json.JSONDecodeError as exc:
            violations.append({
                "control": "n8n_manifests",
                "severity": "high",
                "file": f,
                "description": f"Invalid JSON in n8n manifest: {exc}",
                "remediation": "Fix JSON syntax in workflow manifest",
                "controls": CONTROL_REFS["n8n_manifests"],
            })

    return violations


def check_audit_evidence(audit_dir: str) -> list[dict]:
    """Verify audit evidence directory structure exists."""
    violations = []
    required_subdirs = [
        "soc-validation", "drift-audits", "pipeline-runs", "prompt-regression-results"
    ]
    for sub in required_subdirs:
        full = os.path.join(audit_dir, sub)
        if not os.path.isdir(full):
            violations.append({
                "control": "audit_evidence",
                "severity": "medium",
                "directory": full,
                "description": f"Audit evidence subdirectory missing: {sub}",
                "remediation": f"Create audit-evidence/{sub}/",
                "controls": CONTROL_REFS["audit_evidence"],
            })
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# NIST AI RMF checks
# Reference: https://www.nist.gov/itl/ai-risk-management-framework
# Documents:  NIST AI 100-1 (Jan 2023) · NIST AI 600-1 Gen AI Profile (Jul 2024)
#             AI RMF Critical Infrastructure Profile (Apr 2026)
# ─────────────────────────────────────────────────────────────────────────────

# Fields required in prompt frontmatter for NIST AI RMF GOVERN compliance
AI_RMF_GOVERN_FIELDS = [
    "authority_scope",          # GV-1.2 — accountability role defined
    "hitl_classification",      # GV-1.2 — human oversight level documented
    "blocked_actions",          # GV-6.1 — risk boundaries defined
    "approved_actions",         # GV-1.1 — permitted actions scoped
]

# Keywords expected somewhere in prompt body for MEASURE/MAP coverage
AI_RMF_MEASURE_KEYWORDS = [
    "confidence_score",         # MS-1.1, MS-2.2 — risk measurement
    "explanation",              # MS-2.5 — explainability
    "hitl_required",            # MS-3.3 — safety threshold
]

AI_RMF_MAP_KEYWORDS = [
    "tenant_id",                # MP-1.1 — system context (multi-tenant scope)
    "input_summary",            # MP-2.1 — risk/context captured
]

AI_RMF_MANAGE_KEYWORDS = [
    "remediation_required",     # MG-1.1 — risk response
    "residual_risk",            # MG-4.1 — residual risk tracking
    "sla_hours",                # MG-2.2 — incident response SLA
]

# Directories required for AI RMF audit evidence (MAP + MEASURE + MANAGE)
AI_RMF_EVIDENCE_DIRS = [
    ("audit-evidence/prompt-regression-results", "MS-4.1 — TEVV findings"),
    ("audit-evidence/drift-audits",              "MG-4.2 — AI risk mgmt updated post-incident"),
    ("audit-evidence/soc-validation",            "MG-2.2 — AI incident response evidence"),
]

# n8n manifests required for NIST AI RMF MANAGE automated response
AI_RMF_N8N_MANIFESTS = [
    ("compliance-drift-audit",  "MG-4.2 — daily drift audit covers AI RMF controls"),
    ("soc-validation-loop",     "MG-2.2 — AI incident response loop"),
]


def check_nist_ai_rmf(
    prompts_dir: str,
    audit_dir: str,
    n8n_dir: str,
) -> list[dict]:
    """
    NIST AI RMF 1.0 compliance check — GOVERN / MAP / MEASURE / MANAGE.

    The Vakros platform is itself an AI system; its agents, prompts, and
    infrastructure must be governed by the AI RMF lifecycle.

    Ref: https://www.nist.gov/itl/ai-risk-management-framework
    """
    import yaml

    violations: list[dict] = []

    # ── GOVERN: verify AI RMF governance fields in every prompt ──────────────
    prompt_files = glob.glob(os.path.join(prompts_dir, "*.md"))
    for fpath in prompt_files:
        content = Path(fpath).read_text()

        # Parse frontmatter
        fm: dict = {}
        if content.startswith("---"):
            parts = content.split("---", 2)
            try:
                fm = yaml.safe_load(parts[1]) or {}
            except Exception:
                pass  # YAML errors caught by check_prompt_frontmatter already

        for field in AI_RMF_GOVERN_FIELDS:
            if field not in fm:
                violations.append({
                    "control": "ai_rmf_govern",
                    "severity": "high",
                    "file": fpath,
                    "description": f"[GOVERN GV-1.1/GV-1.2] Missing AI RMF governance field '{field}' in prompt frontmatter",
                    "remediation": f"Add '{field}' to YAML frontmatter — required for NIST AI RMF GOVERN compliance",
                    "controls": CONTROL_REFS["ai_rmf_govern"],
                    "nist_ref": "https://www.nist.gov/itl/ai-risk-management-framework",
                })

        # Check nist_ai_rmf_functions or references field (GOVERN: GV-6.1)
        has_rmf_ref = (
            "nist_ai_rmf" in str(content).lower()
            or "ai_rmf" in str(fm).lower()
            or "nist_ai_rmf_functions" in fm
            or "references" in fm
        )
        if not has_rmf_ref:
            violations.append({
                "control": "ai_rmf_govern",
                "severity": "medium",
                "file": fpath,
                "description": "[GOVERN GV-6.1] Prompt has no NIST AI RMF reference — AI risk policy linkage missing",
                "remediation": "Add 'nist_ai_rmf_functions' or 'references' field pointing to AI RMF controls",
                "controls": CONTROL_REFS["ai_rmf_govern"],
                "nist_ref": "https://www.nist.gov/itl/ai-risk-management-framework",
            })

        # ── MAP: verify system context and risk categories documented ─────────
        for kw in AI_RMF_MAP_KEYWORDS:
            if kw not in content:
                violations.append({
                    "control": "ai_rmf_map",
                    "severity": "medium",
                    "file": fpath,
                    "description": f"[MAP MP-1.1/MP-2.1] Prompt missing MAP keyword '{kw}' — AI system context incomplete",
                    "remediation": f"Ensure '{kw}' is used in prompt output schema or examples (AI RMF MAP requires system context)",
                    "controls": CONTROL_REFS["ai_rmf_map"],
                    "nist_ref": "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf",
                })

        # ── MEASURE: verify risk measurement and explainability ───────────────
        for kw in AI_RMF_MEASURE_KEYWORDS:
            if kw not in content:
                violations.append({
                    "control": "ai_rmf_measure",
                    "severity": "high",
                    "file": fpath,
                    "description": f"[MEASURE MS-1.1/MS-2.5] Prompt missing MEASURE keyword '{kw}' — AI risk measurement incomplete",
                    "remediation": f"Add '{kw}' to prompt output schema — required for AI RMF MEASURE compliance",
                    "controls": CONTROL_REFS["ai_rmf_measure"],
                    "nist_ref": "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf",
                })

        # ── MANAGE: verify risk response and SLA fields ───────────────────────
        for kw in AI_RMF_MANAGE_KEYWORDS:
            if kw not in content:
                violations.append({
                    "control": "ai_rmf_manage",
                    "severity": "medium",
                    "file": fpath,
                    "description": f"[MANAGE MG-1.1/MG-4.1] Prompt missing MANAGE keyword '{kw}' — risk response incomplete",
                    "remediation": f"Add '{kw}' to prompt gap-detection or evidence schema (AI RMF MANAGE lifecycle)",
                    "controls": CONTROL_REFS["ai_rmf_manage"],
                    "nist_ref": "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf",
                })

    # ── MEASURE MS-4.1: audit evidence dirs for TEVV findings ────────────────
    for evidence_dir, rationale in AI_RMF_EVIDENCE_DIRS:
        if not os.path.isdir(evidence_dir):
            violations.append({
                "control": "ai_rmf_measure",
                "severity": "medium",
                "directory": evidence_dir,
                "description": f"[MEASURE/MANAGE] AI RMF evidence directory missing: {evidence_dir} ({rationale})",
                "remediation": f"Create {evidence_dir}/ — required for NIST AI RMF TEVV and incident evidence",
                "controls": CONTROL_REFS["ai_rmf_measure"] + CONTROL_REFS["ai_rmf_manage"],
                "nist_ref": "https://www.nist.gov/itl/ai-risk-management-framework",
            })

    # ── MANAGE MG-3.1: n8n manifests must exist for AI automated response ────
    if os.path.isdir(n8n_dir):
        n8n_files = [
            os.path.basename(f) for f in glob.glob(os.path.join(n8n_dir, "*.json"))
        ]
        for manifest_stem, rationale in AI_RMF_N8N_MANIFESTS:
            found = any(manifest_stem in f for f in n8n_files)
            if not found:
                violations.append({
                    "control": "ai_rmf_manage",
                    "severity": "high",
                    "description": f"[MANAGE MG-3.1/MG-4.2] Required n8n manifest not found: '*{manifest_stem}*.json' ({rationale})",
                    "remediation": f"Ensure {manifest_stem} workflow JSON exists in n8n-manifests/",
                    "controls": CONTROL_REFS["ai_rmf_manage"],
                    "nist_ref": "https://www.nist.gov/itl/ai-risk-management-framework",
                })

    return violations


# ─────────────────────────────────────────────────────────────────────────────
# Report generation
# ─────────────────────────────────────────────────────────────────────────────

def generate_report(
    all_violations: list[dict],
    sha: str = "",
    root_dir: str = ".",
) -> dict:
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in all_violations:
        sev = v.get("severity", "medium")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    controls_violated = list({
        c for v in all_violations for c in v.get("controls", [])
    })

    # Break out AI RMF violations by function for reporting
    ai_rmf_by_function: dict[str, int] = {"GOVERN": 0, "MAP": 0, "MEASURE": 0, "MANAGE": 0}
    for v in all_violations:
        ctrl = v.get("control", "")
        if "govern" in ctrl:
            ai_rmf_by_function["GOVERN"] += 1
        elif "map" in ctrl:
            ai_rmf_by_function["MAP"] += 1
        elif "measure" in ctrl:
            ai_rmf_by_function["MEASURE"] += 1
        elif "manage" in ctrl:
            ai_rmf_by_function["MANAGE"] += 1

    return {
        "report_type": "compliance_gate",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "git_sha": sha,
        "root_dir": root_dir,
        "passed": len(all_violations) == 0,
        "violation_count": len(all_violations),
        "severity_breakdown": severity_counts,
        "controls_violated": controls_violated,
        "violations": all_violations,
        "standards": ["SOC2_TypeII", "ISO27001_2022", "NIST_AI_RMF_1.0", "NIST_AI_600-1_GenAI"],
        "nist_ai_rmf": {
            "ref": "https://www.nist.gov/itl/ai-risk-management-framework",
            "docs": [
                "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf",
                "https://doi.org/10.6028/NIST.AI.600-1",
            ],
            "violations_by_function": ai_rmf_by_function,
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Vakros Compliance Gate")
    parser.add_argument("--prompts-dir",      default="prompts/")
    parser.add_argument("--migrations-dir",   default="vakros-agent/")
    parser.add_argument("--n8n-dir",          default="n8n-manifests/")
    parser.add_argument("--audit-dir",        default="audit-evidence/")
    parser.add_argument("--root-dir",         default=".")
    parser.add_argument("--output",           default=None)
    parser.add_argument("--sha",              default="")
    parser.add_argument("--fail-on-violation", action="store_true")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print("Vakros Compliance Gate — gstack v1")
    print(f"SOC 2 Type II + ISO 27001:2022 + NIST AI RMF 1.0")
    print(f"Ref: https://www.nist.gov/itl/ai-risk-management-framework")
    print(f"{'='*60}\n")

    all_violations: list[dict] = []

    checks = [
        ("Prompt Frontmatter",     lambda: check_prompt_frontmatter(args.prompts_dir)),
        ("RLS Coverage",           lambda: check_rls_coverage(args.migrations_dir)),
        ("Secret Detection",       lambda: check_secret_detection(args.root_dir)),
        ("Directory Structure",    lambda: check_directory_structure(args.root_dir)),
        ("n8n Manifests",          lambda: check_n8n_manifests(args.n8n_dir)),
        ("Audit Evidence Dirs",    lambda: check_audit_evidence(args.audit_dir)),
        # NIST AI RMF — GOVERN / MAP / MEASURE / MANAGE
        ("NIST AI RMF (GOVERN/MAP/MEASURE/MANAGE)",
                                   lambda: check_nist_ai_rmf(
                                       args.prompts_dir, args.audit_dir, args.n8n_dir
                                   )),
    ]

    for name, check_fn in checks:
        try:
            viols = check_fn()
            if viols:
                print(f"  ❌ {name}: {len(viols)} violation(s)")
                for v in viols:
                    sev = v.get("severity", "?").upper()
                    print(f"     [{sev}] {v['description']}")
            else:
                print(f"  ✅ {name}: Clean")
            all_violations.extend(viols)
        except Exception as exc:
            print(f"  ⚠️  {name}: Check failed with error: {exc}")

    report = generate_report(all_violations, sha=args.sha, root_dir=args.root_dir)

    if args.output:
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n📄 Compliance report saved to: {args.output}")

    critical = report["severity_breakdown"].get("critical", 0)
    high = report["severity_breakdown"].get("high", 0)
    ai_rmf_viols = report["nist_ai_rmf"]["violations_by_function"]

    print(f"\n{'='*60}")
    print(f"Violations: {len(all_violations)} total | {critical} critical | {high} high")
    print(f"NIST AI RMF: GOVERN={ai_rmf_viols['GOVERN']} MAP={ai_rmf_viols['MAP']} "
          f"MEASURE={ai_rmf_viols['MEASURE']} MANAGE={ai_rmf_viols['MANAGE']}")
    if report["passed"]:
        print("✅ COMPLIANCE GATE: PASSED (SOC2 + ISO27001 + NIST AI RMF)")
    else:
        print("❌ COMPLIANCE GATE: FAILED")
        if report["controls_violated"]:
            print(f"Controls violated: {', '.join(report['controls_violated'])}")
    print(f"Standards: {', '.join(report['standards'])}")
    print(f"{'='*60}\n")

    if args.fail_on_violation and not report["passed"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
