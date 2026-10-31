"""
pipeline.py - Multi-Agent Code Review & Security Scanner Pipeline
Powered by Google GenAI SDK (gemini-2.5-flash)

Agents:
  1. Ingestion Agent: Reads target code and prepares simulated Pull Request metadata.
  2. Security & Bug Scanner Agent: Analyzes source code for vulnerabilities and logic bugs via Gemini 2.5 Flash.
  3. Summarizer & Reporter Agent: Synthesizes findings into a standard GitHub PR Review template (pull_request_review.md).
"""

import os
import sys
import ast
import json
import time
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()


# ============================================================================
# Domain Models & Data Contracts
# ============================================================================

@dataclass
class IngestedPayload:
    """Data contract produced by Agent 1 (The Ingestion Agent)."""
    file_path: str
    file_name: str
    source_code: str
    total_lines: int
    char_count: int
    is_valid_syntax: bool
    syntax_error: Optional[str] = None
    pr_id: str = "PR-#104"
    branch_name: str = "feature/user-auth-and-diagnostics"
    commit_sha: str = "a3f89c2"
    timestamp: str = field(default_factory=lambda: datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ"))


@dataclass
class ScanResult:
    """Data contract produced by Agent 2 (The Security Scanner Agent)."""
    raw_response: str
    summary_counts: Dict[str, int]
    findings: List[Dict[str, Any]]
    model_name: str = "gemini-2.5-flash"


# ============================================================================
# Agent 1: The Ingestion Agent
# ============================================================================

class IngestionAgent:
    """
    Agent 1: Ingestion Agent
    Simulates checking out a Pull Request diff or local code artifact.
    Reads target file, checks syntax integrity, and extracts structural metadata.
    """

    def __init__(self, target_file_path: str = "sample_code.py"):
        self.target_path = Path(target_file_path)

    def run(self) -> IngestedPayload:
        print(f"\n[Agent 1: Ingestion Agent] 🔍 Inspecting target file: '{self.target_path}'...")
        
        if not self.target_path.exists():
            raise FileNotFoundError(
                f"Target file not found at '{self.target_path.resolve()}'. "
                "Ensure sample_code.py exists in the working directory."
            )

        with open(self.target_path, "r", encoding="utf-8") as f:
            code = f.read()

        lines = code.splitlines()
        total_lines = len(lines)
        char_count = len(code)

        # Basic AST Syntax Validation
        is_valid = True
        syntax_err = None
        try:
            ast.parse(code)
        except SyntaxError as e:
            is_valid = False
            syntax_err = f"Syntax error at line {e.lineno}: {e.msg}"

        print(f"[Agent 1: Ingestion Agent] ✅ Successfully ingested {total_lines} lines ({char_count} bytes).")
        print(f"[Agent 1: Ingestion Agent] 📦 Context: Branch='feature/user-auth-and-diagnostics' | Commit='a3f89c2'")

        return IngestedPayload(
            file_path=str(self.target_path.resolve()),
            file_name=self.target_path.name,
            source_code=code,
            total_lines=total_lines,
            char_count=char_count,
            is_valid_syntax=is_valid,
            syntax_error=syntax_err,
        )


# ============================================================================
# Agent 2: The Security & Bug Scanner Agent
# ============================================================================

class SecurityScannerAgent:
    """
    Agent 2: Security & Bug Scanner Agent
    Interacts with the Google GenAI SDK (gemini-2.5-flash) to perform deep
    Static Application Security Testing (SAST) and logic flaw detection.
    """

    def __init__(self, model_name: str = "gemini-2.5-flash"):
        self.model_name = model_name
        self.api_key = os.getenv("GEMINI_API_KEY")
        
        if not self.api_key:
            raise ValueError(
                "Missing GEMINI_API_KEY. Please set GEMINI_API_KEY in your environment or in a .env file.\n"
                "You can get an API key at https://aistudio.google.com/app/apikey"
            )

        # Initialize the official Google GenAI Client
        try:
            from google import genai
            self.client = genai.Client(api_key=self.api_key)
        except ImportError:
            raise ImportError(
                "The 'google-genai' package is required. Install it using:\n"
                "  pip install google-genai"
            )

    def _build_analysis_prompt(self, payload: IngestedPayload) -> str:
        prompt = f"""You are an elite Senior Staff Security Engineer and Automated SAST Reviewer.
Analyze the following Python source code submitted in Pull Request {payload.pr_id} ({payload.file_name}).

### TARGET SOURCE CODE ({payload.file_name}):
```python
{payload.source_code}
```

### INSTRUCTIONS:
1. Conduct an exhaustive security review scanning for:
   - Injection attacks (SQL injection, Command injection, OS injection)
   - Hardcoded credentials, secrets, tokens, or API keys
   - Broken Authentication, access control, and logic flaws
   - Cryptographic vulnerabilities (weak hashing, broken algorithms)
   - Reliability bugs (unhandled exceptions, division by zero, resource leaks)
2. Categorize every finding strictly into one of four severities:
   - CRITICAL: Immediate remote code execution, SQLi, exposed production keys, authentication bypass.
   - HIGH: Broken access control, weak cryptography in auth, privilege escalation.
   - MEDIUM: Unhandled exceptions causing crash/DoS, logic errors under edge cases.
   - LOW: Resource leaks (unclosed files), minor best-practice deviations.
3. For each finding, provide:
   - Title / Vulnerability Name
   - Severity (CRITICAL, HIGH, MEDIUM, LOW)
   - Approximate Line Numbers
   - Description & Exploitation Impact
   - Vulnerable Code Snippet
   - Recommended Secure Fix Snippet

Return your response as a valid JSON object matching the following structure:
{{
  "overall_verdict": "CHANGES_REQUESTED" | "NEEDS_DISCUSSION" | "APPROVED",
  "summary": "High-level summary of security posture and main risks.",
  "counts": {{
    "CRITICAL": 0,
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0
  }},
  "findings": [
    {{
      "id": "SEC-001",
      "title": "SQL Injection in User Lookup",
      "severity": "CRITICAL",
      "lines": "25-28",
      "category": "CWE-89: SQL Injection",
      "description": "Detailed explanation of vulnerability and impact.",
      "vulnerable_code": "cursor.execute(f'...{{username}}...')",
      "remediation": "Use parameterized queries: cursor.execute('... WHERE username = ?', (username,))"
    }}
  ]
}}
IMPORTANT: Output raw JSON only. Do not wrap in markdown backticks or commentary outside the JSON.
"""
        return prompt

    def run(self, payload: IngestedPayload) -> ScanResult:
        print(f"\n[Agent 2: Security & Bug Scanner Agent] 🛡️  Invoking Gemini model '{self.model_name}'...")
        print(f"[Agent 2: Security & Bug Scanner Agent] 📡 Performing Static Application Security Testing (SAST)...")

        prompt = self._build_analysis_prompt(payload)

        try:
            from google.genai import types

            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.1,
                    response_mime_type="application/json",
                ),
            )
            raw_text = response.text.strip()

        except Exception as e:
            # Fallback for SDK variants or network issues
            print(f"[Agent 2] ⚠️  Warning: direct JSON call encounter: {e}. Retrying without mime config...")
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
            )
            raw_text = response.text.strip()

        # Parse JSON output safely
        findings_data = {"summary": "Completed SAST review", "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, "findings": []}
        try:
            # Strip accidental markdown ticks if present
            clean_json = raw_text
            if clean_json.startswith("```json"):
                clean_json = clean_json[7:]
            if clean_json.startswith("```"):
                clean_json = clean_json[3:]
            if clean_json.endswith("```"):
                clean_json = clean_json[:-3]
            
            parsed = json.loads(clean_json.strip())
            findings_data = parsed
        except Exception as parse_err:
            print(f"[Agent 2] ⚠️  Note: Could not parse pure JSON ({parse_err}). Falling back to text wrapper.")
            findings_data["summary"] = raw_text

        counts = findings_data.get("counts", {})
        print(f"[Agent 2: Security & Bug Scanner Agent] ✅ Scan finished: "
              f"Critical: {counts.get('CRITICAL', 0)} | High: {counts.get('HIGH', 0)} | "
              f"Medium: {counts.get('MEDIUM', 0)} | Low: {counts.get('LOW', 0)}")

        return ScanResult(
            raw_response=raw_text,
            summary_counts=counts,
            findings=findings_data.get("findings", []),
            model_name=self.model_name,
        )


# ============================================================================
# Agent 3: The Summarizer & Reporter Agent
# ============================================================================

class ReporterAgent:
    """
    Agent 3: Summarizer & Reporter Agent
    Formats the security findings and PR metadata into a production-grade
    GitHub Pull Request review markdown document (pull_request_review.md).
    """

    def __init__(self, output_file: str = "pull_request_review.md"):
        self.output_path = Path(output_file)

    def _determine_verdict(self, counts: Dict[str, int]) -> tuple[str, str]:
        critical = counts.get("CRITICAL", 0)
        high = counts.get("HIGH", 0)
        medium = counts.get("MEDIUM", 0)

        if critical > 0 or high > 0:
            return "❌ CHANGES REQUESTED", "DO NOT MERGE: Critical or High severity security vulnerabilities detected."
        elif medium > 0:
            return "⚠️ COMMENT / NEEDS REVIEW", "Merge blocked pending resolution of medium severity issues."
        else:
            return "✅ APPROVED", "Code passed automated security scanner checks."

    def _format_markdown_report(self, payload: IngestedPayload, scan: ScanResult) -> str:
        counts = scan.summary_counts
        badge, verdict_msg = self._determine_verdict(counts)

        # Markdown Document Generation
        md = []
        md.append(f"# 🛡️ Automated Code Review & Security Report\n")
        md.append(f"> **Status:** {badge}  ")
        md.append(f"> **Verdict Message:** {verdict_msg}  ")
        md.append(f"> **Engine:** `{scan.model_name}` via Google GenAI SDK | **Generated:** `{payload.timestamp}`\n")
        
        md.append("---\n")
        md.append("## 📋 Pull Request Context")
        md.append("| Attribute | Details |")
        md.append("| :--- | :--- |")
        md.append(f"| **Target File** | `{payload.file_name}` |")
        md.append(f"| **Pull Request** | `{payload.pr_id}` |")
        md.append(f"| **Branch** | `{payload.branch_name}` |")
        md.append(f"| **Commit** | `{payload.commit_sha}` |")
        md.append(f"| **Lines Analyzed** | `{payload.total_lines}` lines ({payload.char_count} bytes) |")
        md.append(f"| **Syntax Status** | `{'Valid' if payload.is_valid_syntax else 'Syntax Error: ' + str(payload.syntax_error)}` |\n")

        md.append("## 📊 Vulnerability Severity Breakdown")
        md.append("| Severity | Count | Threshold Action |")
        md.append("| :--- | :---: | :--- |")
        md.append(f"| 🔴 **CRITICAL** | **{counts.get('CRITICAL', 0)}** | Blocks CI/CD pipeline immediately |")
        md.append(f"| 🟠 **HIGH** | **{counts.get('HIGH', 0)}** | Must be remediated prior to merge |")
        md.append(f"| 🟡 **MEDIUM** | **{counts.get('MEDIUM', 0)}** | Strongly recommended before deployment |")
        md.append(f"| 🔵 **LOW** | **{counts.get('LOW', 0)}** | Code hygiene / best practice |")
        md.append(f"| **Total Issues** | **{sum(counts.values())}** | |\n")

        md.append("---\n")
        md.append("## 🔍 Detailed Security Findings & Remediation Guide\n")

        if not scan.findings:
            md.append("No structured findings returned or all security checks passed.\n")
            md.append("### Raw Model Analysis\n")
            md.append(f"```text\n{scan.raw_response}\n```\n")
        else:
            for idx, item in enumerate(scan.findings, 1):
                severity = item.get("severity", "UNKNOWN").upper()
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(severity, "⚪")
                title = item.get("title", f"Issue #{idx}")
                lines = item.get("lines", "N/A")
                category = item.get("category", "General Vulnerability")
                desc = item.get("description", "No description provided.")
                vuln_code = item.get("vulnerable_code", "")
                remediation = item.get("remediation", "")

                md.append(f"### {icon} [{severity}] #{idx}: {title}")
                md.append(f"- **Lines Affected:** `L{lines}`")
                md.append(f"- **Category:** `{category}`")
                md.append(f"- **Impact / Description:** {desc}\n")
                
                if vuln_code:
                    md.append("**Vulnerable Code:**")
                    md.append(f"```python\n{vuln_code.strip()}\n```\n")

                if remediation:
                    md.append("**Recommended Fix:**")
                    md.append(f"```python\n{remediation.strip()}\n```\n")
                
                md.append("---\n")

        md.append("## 📝 Reviewer Action Checklist for Author")
        md.append("- [ ] Remove all hardcoded API tokens and move them to `.env` or a Secret Vault.")
        md.append("- [ ] Replace any raw string concatenation in SQL queries with parameterized queries.")
        md.append("- [ ] Replace `subprocess.run(..., shell=True)` with parameter arrays (`shell=False`).")
        md.append("- [ ] Upgrade password hashing from `MD5` to `bcrypt`, `argon2`, or `pbkdf2`.")
        md.append("- [ ] Correct inverted authorization checks to enforce strict role-based access.")
        md.append("- [ ] Use context managers (`with open(...)`) for resource management.\n")

        md.append("> *Report generated automatically by Antigravity Multi-Agent Code Review Pipeline.*")

        return "\n".join(md)

    def run(self, payload: IngestedPayload, scan: ScanResult) -> Path:
        print(f"\n[Agent 3: Summarizer & Reporter Agent] 📝 Formatting GitHub PR Review markdown...")
        report_content = self._format_markdown_report(payload, scan)

        with open(self.output_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        print(f"[Agent 3: Summarizer & Reporter Agent] 💾 Report successfully saved to: '{self.output_path.resolve()}'")
        return self.output_path


# ============================================================================
# Pipeline Orchestrator
# ============================================================================

class CodeReviewPipeline:
    """
    Main Orchestrator tying Agent 1, Agent 2, and Agent 3 together.
    """

    def __init__(self, target_file: str = "sample_code.py", output_file: str = "pull_request_review.md"):
        self.target_file = target_file
        self.output_file = output_file

    def execute(self):
        print("=" * 70)
        print("🚀 STARTING MULTI-AGENT CODE REVIEW & SECURITY SCANNER PIPELINE")
        print("=" * 70)
        start_time = time.time()

        try:
            # Stage 1: Ingestion
            ingestion_agent = IngestionAgent(target_file_path=self.target_file)
            payload = ingestion_agent.run()

            # Stage 2: Security & Bug Scanning via Gemini 2.5 Flash
            scanner_agent = SecurityScannerAgent(model_name="gemini-2.5-flash")
            scan_result = scanner_agent.run(payload)

            # Stage 3: Summarization & PR Markdown Reporting
            reporter_agent = ReporterAgent(output_file=self.output_file)
            report_file = reporter_agent.run(payload, scan_result)

            elapsed = time.time() - start_time
            print("\n" + "=" * 70)
            print(f"🎉 PIPELINE COMPLETED SUCCESSFULLY IN {elapsed:.2f}s!")
            print(f"📄 View full review report at: {report_file.resolve()}")
            print("=" * 70)

        except Exception as err:
            print(f"\n❌ Pipeline failed: {err}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    # Target can be customized via command-line argument if desired
    target = sys.argv[1] if len(sys.argv) > 1 else "sample_code.py"
    output = sys.argv[2] if len(sys.argv) > 2 else "pull_request_review.md"

    pipeline = CodeReviewPipeline(target_file=target, output_file=output)
    pipeline.execute()
