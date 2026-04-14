import re
import os
import sys
import ast
from datetime import datetime
from pathlib import Path

# ── ANSI colour helpers ────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def red(s):    return f"{RED}{s}{RESET}"
def yellow(s): return f"{YELLOW}{s}{RESET}"
def green(s):  return f"{GREEN}{s}{RESET}"
def cyan(s):   return f"{CYAN}{s}{RESET}"
def bold(s):   return f"{BOLD}{s}{RESET}"

# ─────────────────────────────────────────────────────────
# Rule definitions
# Each rule is a dict with:
#   id        – short identifier
#   severity  – HIGH / MEDIUM / LOW
#   title     – human-readable name
#   pattern   – compiled regex to search in source lines
#   tip       – remediation advice shown in the report
# ─────────────────────────────────────────────────────────
RULES = [
    # ── SQL Injection ─────────────────────────────────
    {
        "id": "SQL-01",
        "severity": "HIGH",
        "title": "Potential SQL Injection (string formatting in query)",
        "pattern": re.compile(
            r'(execute|cursor\.execute)\s*\(\s*[f"\'].*(%s|%d|\{|\+)',
            re.IGNORECASE,
        ),
        "tip": (
            "Never build SQL queries with string formatting or concatenation.\n"
            "         Use parameterised queries:\n"
            "           cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
        ),
    },
    # ── Hardcoded passwords / secrets ─────────────────
    {
        "id": "SEC-01",
        "severity": "HIGH",
        "title": "Hardcoded password / secret detected",
        "pattern": re.compile(
            r'(password|passwd|secret|api_key|token|auth)\s*=\s*["\'][^"\']{4,}["\']',
            re.IGNORECASE,
        ),
        "tip": (
            "Never hardcode credentials in source code.\n"
            "         Store secrets in environment variables or a secrets manager:\n"
            "           import os\n"
            "           password = os.environ['DB_PASSWORD']"
        ),
    },
    # ── eval / exec ───────────────────────────────────
    {
        "id": "INJ-01",
        "severity": "HIGH",
        "title": "Use of eval() or exec() with dynamic input",
        "pattern": re.compile(r'\b(eval|exec)\s*\(', re.IGNORECASE),
        "tip": (
            "eval() and exec() execute arbitrary code — never pass user\n"
            "         input to them.  Use ast.literal_eval() for safe data parsing."
        ),
    },
    # ── Shell injection ───────────────────────────────
    {
        "id": "INJ-02",
        "severity": "HIGH",
        "title": "Shell injection risk (os.system / subprocess with shell=True)",
        "pattern": re.compile(
            r'(os\.system|subprocess\.(call|run|Popen))\s*\(.*shell\s*=\s*True',
            re.IGNORECASE,
        ),
        "tip": (
            "Avoid shell=True with user-controlled data.\n"
            "         Pass a list of arguments instead:\n"
            "           subprocess.run(['ls', '-la'], shell=False)"
        ),
    },
    # ── Insecure random ───────────────────────────────
    {
        "id": "CRY-01",
        "severity": "MEDIUM",
        "title": "Insecure random number generator (random module)",
        "pattern": re.compile(
            r'\brandom\.(random|randint|choice|shuffle)\b', re.IGNORECASE
        ),
        "tip": (
            "The 'random' module is NOT cryptographically secure.\n"
            "         For tokens, passwords, or security-sensitive values use:\n"
            "           import secrets\n"
            "           token = secrets.token_hex(32)"
        ),
    },
    # ── Weak hashing ──────────────────────────────────
    {
        "id": "CRY-02",
        "severity": "HIGH",
        "title": "Weak hashing algorithm (MD5 / SHA1)",
        "pattern": re.compile(
            r'hashlib\.(md5|sha1)\s*\(', re.IGNORECASE
        ),
        "tip": (
            "MD5 and SHA-1 are cryptographically broken.\n"
            "         For passwords use bcrypt / argon2.\n"
            "         For integrity checks use SHA-256 or SHA-3:\n"
            "           hashlib.sha256(data).hexdigest()"
        ),
    },
    # ── Debug mode enabled ────────────────────────────
    {
        "id": "CFG-01",
        "severity": "MEDIUM",
        "title": "Debug mode enabled (Flask / Django)",
        "pattern": re.compile(
            r'(DEBUG\s*=\s*True|app\.run\s*\(.*debug\s*=\s*True)',
            re.IGNORECASE,
        ),
        "tip": (
            "Debug mode exposes stack traces and internal details.\n"
            "         Set DEBUG = False (or use an environment variable) in production."
        ),
    },
    # ── Pickle deserialization ────────────────────────
    {
        "id": "DSR-01",
        "severity": "HIGH",
        "title": "Unsafe deserialization (pickle.loads)",
        "pattern": re.compile(r'pickle\.(loads?|Unpickler)', re.IGNORECASE),
        "tip": (
            "pickle.load() can execute arbitrary code during deserialization.\n"
            "         Never unpickle data from untrusted sources.\n"
            "         Prefer JSON or a schema-validated format."
        ),
    },
    # ── Open redirect ─────────────────────────────────
    {
        "id": "WEB-01",
        "severity": "MEDIUM",
        "title": "Potential open redirect",
        "pattern": re.compile(
            r'redirect\s*\(\s*(request\.(args|form|values|GET|POST))',
            re.IGNORECASE,
        ),
        "tip": (
            "Redirecting to a URL from user input enables open-redirect attacks.\n"
            "         Validate the URL against an allowlist of trusted domains."
        ),
    },
    # ── SSL verification disabled ─────────────────────
    {
        "id": "TLS-01",
        "severity": "HIGH",
        "title": "SSL/TLS verification disabled (verify=False)",
        "pattern": re.compile(r'verify\s*=\s*False', re.IGNORECASE),
        "tip": (
            "Disabling SSL verification exposes you to man-in-the-middle attacks.\n"
            "         Remove verify=False and ensure certificates are valid."
        ),
    },
    # ── Broad exception suppression ───────────────────
    {
        "id": "ERR-01",
        "severity": "LOW",
        "title": "Broad exception suppressed (bare except / except Exception)",
        "pattern": re.compile(r'except\s*(Exception|:)', re.IGNORECASE),
        "tip": (
            "Catching all exceptions hides bugs and security errors.\n"
            "         Catch specific exception types and log them properly."
        ),
    },
]

# ─────────────────────────────────────────────────────────
SEVERITY_COLOR = {
    "HIGH":   red,
    "MEDIUM": yellow,
    "LOW":    green,
}

findings = []   # global list – populated by scan_file()

# ─────────────────────────────────────────────────────────
def scan_file(filepath: Path):
    """Read a Python file line-by-line and apply every rule."""
    try:
        lines = filepath.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as e:
        print(f"  [!] Could not read {filepath}: {e}")
        return

    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):   # skip pure comment lines
            continue
        for rule in RULES:
            if rule["pattern"].search(line):
                findings.append({
                    "file":     str(filepath),
                    "line":     lineno,
                    "code":     line.rstrip(),
                    "rule":     rule,
                })


# ─────────────────────────────────────────────────────────
def collect_python_files(target: str) -> list:
    """Return a list of Path objects for all .py files under target."""
    p = Path(target)
    if p.is_file() and p.suffix == ".py":
        return [p]
    elif p.is_dir():
        return sorted(p.rglob("*.py"))
    else:
        print(red(f"[ERROR] '{target}' is not a .py file or directory."))
        sys.exit(1)


# ─────────────────────────────────────────────────────────
def print_report(files_scanned: int):
    """Pretty-print the findings grouped by severity."""
    print()
    print(bold("=" * 65))
    print(bold("  SECURE CODING REVIEW REPORT — CodeAlpha Internship"))
    print(bold("=" * 65))
    print(f"  Date         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Files scanned: {files_scanned}")
    print(f"  Issues found : {len(findings)}")
    print()

    if not findings:
        print(green("  ✅  No issues detected. Great job!"))
        return

    # Count by severity
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["rule"]["severity"]] += 1

    print(f"  {red('HIGH')}   : {counts['HIGH']}")
    print(f"  {yellow('MEDIUM')} : {counts['MEDIUM']}")
    print(f"  {green('LOW')}    : {counts['LOW']}")
    print()

    # Print each finding
    for i, finding in enumerate(findings, start=1):
        sev   = finding["rule"]["severity"]
        color = SEVERITY_COLOR[sev]
        rule  = finding["rule"]

        print(f"  {'─'*61}")
        print(f"  {bold(f'Issue #{i}')}  [{color(sev)}]  {rule['id']}")
        print(f"  {bold('Title')}    : {rule['title']}")
        print(f"  {bold('File')}     : {finding['file']}  (line {finding['line']})")
        print(f"  {bold('Code')}     : {cyan(finding['code'].strip())}")
        print(f"  {bold('Fix')}      : {rule['tip']}")
        print()

    print(bold("=" * 65))
    print(bold("  END OF REPORT"))
    print(bold("=" * 65))


# ─────────────────────────────────────────────────────────
def save_report(output_path: str = "security_report.txt"):
    """Save a plain-text version of the report (no ANSI colours)."""
    lines = [
        "SECURE CODING REVIEW REPORT — CodeAlpha Internship",
        "=" * 65,
        f"Date         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Issues found : {len(findings)}",
        "",
    ]
    for i, finding in enumerate(findings, start=1):
        rule = finding["rule"]
        lines += [
            f"Issue #{i}  [{rule['severity']}]  {rule['id']}",
            f"  Title : {rule['title']}",
            f"  File  : {finding['file']}  (line {finding['line']})",
            f"  Code  : {finding['code'].strip()}",
            f"  Fix   : {rule['tip']}",
            "",
        ]
    Path(output_path).write_text("\n".join(lines), encoding="utf-8")
    print(f"\n  Report saved to: {output_path}")


# ─────────────────────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <file_or_folder>")
        print(f"  Example: python3 {sys.argv[0]} my_app.py")
        sys.exit(0)

    target = sys.argv[1]
    py_files = collect_python_files(target)

    print(bold("\n  CodeAlpha — Secure Coding Review Scanner"))
    print(f"  Scanning {len(py_files)} file(s) in '{target}' …\n")

    for f in py_files:
        print(f"  → {f}")
        scan_file(f)

    print_report(len(py_files))

    # Auto-save plain-text report
    save_report("security_report.txt")


# ── Entry point ───────────────────────────────────────────
if __name__ == "__main__":
    main()
