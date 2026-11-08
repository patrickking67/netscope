from html.parser import HTMLParser
import json
import re
from pathlib import Path
import subprocess
import sys


root = Path(__file__).resolve().parents[1]
html_files = [root / "index.html", *sorted((root / "pages").glob("*.html"))]
errors = []


class AssetParser(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.source = source

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        for key in ("href", "src"):
            value = values.get(key, "")
            if not value or value.startswith(("http:", "https:", "mailto:", "#", "data:")):
                continue
            path = (self.source.parent / value.split("?", 1)[0].split("#", 1)[0]).resolve()
            if not path.exists():
                errors.append(f"{self.source.relative_to(root)}: missing {value}")


for html_file in html_files:
    parser = AssetParser(html_file)
    parser.feed(html_file.read_text())

for script in sorted((root / "assets" / "js").glob("*.js")):
    result = subprocess.run(["node", "--check", str(script)], capture_output=True, text=True)
    if result.returncode:
        errors.append(f"{script.relative_to(root)}: {result.stderr.strip()}")

for required_file in (root / "manifest.webmanifest", root / "sw.js", root / "assets" / "js" / "pwa.js"):
    if not required_file.exists():
        errors.append(f"missing PWA asset: {required_file.relative_to(root)}")

service_worker = subprocess.run(["node", "--check", str(root / "sw.js")], capture_output=True, text=True)
if service_worker.returncode:
    errors.append(f"sw.js: {service_worker.stderr.strip()}")

claude = (root / "CLAUDE.md").read_text().strip()
if claude != "@AGENTS.md":
    errors.append("CLAUDE.md must contain only @AGENTS.md")

# Docs and agent files that must exist at the repository (and published) root.
for doc in ("README.md", "AGENTS.md", "CLAUDE.md", "CONTRIBUTING.md", "CHANGELOG.md", "SECURITY.md", "LICENSE", "llms.txt"):
    if not (root / doc).is_file():
        errors.append(f"missing {doc}")

# llms.txt (https://llmstxt.org): H1, a > summary, then ## sections of absolute links.
llms_path = root / "llms.txt"
if llms_path.is_file():
    llms = llms_path.read_text().splitlines()
    if not llms or not llms[0].startswith("# "):
        errors.append("llms.txt: first line must be an H1 title")
    if not any(line.startswith("> ") for line in llms[:4]):
        errors.append("llms.txt: needs a '> ' summary right after the title")
    if not any(line.startswith("## ") for line in llms):
        errors.append("llms.txt: needs at least one ## section")
    for number, line in enumerate(llms, 1):
        for link in re.findall(r"\]\(([^)]+)\)", line):
            if not link.startswith("https://"):
                errors.append(f"llms.txt:{number}: link must be an absolute https URL: {link}")

# .claude/launch.json drives the local preview; keep it valid and on the documented port.
launch_path = root / ".claude" / "launch.json"
try:
    launch = json.loads(launch_path.read_text())
    configs = launch.get("configurations") or []
    if not configs:
        errors.append(".claude/launch.json: no configurations")
    for config in configs:
        args = [str(a) for a in config.get("runtimeArgs", [])]
        if config.get("port") != 4102 or "4102" not in args:
            errors.append(f".claude/launch.json: {config.get('name')} must serve on port 4102")
except (OSError, ValueError) as exc:
    errors.append(f".claude/launch.json: {exc}")

# Text lint: committed text uses no em dashes and no emoji.
text_suffixes = {".html", ".css", ".js", ".json", ".md", ".txt", ".yml", ".yaml", ".py", ".svg", ".webmanifest", ".toml"}
skip_dirs = {".git", ".worktrees", "node_modules"}
forbidden = re.compile("[\u2014\U0001F300-\U0001FAFF\u2600-\u27BF\uFE0F]")
for path in sorted(root.rglob("*")):
    if not path.is_file() or path.suffix not in text_suffixes:
        continue
    if any(part in skip_dirs for part in path.relative_to(root).parts):
        continue
    for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if forbidden.search(line):
            errors.append(f"{path.relative_to(root)}:{number}: em dash or emoji in committed text")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print(f"Validated {len(html_files)} HTML files, JavaScript syntax, docs, llms.txt, launch.json and the text lint.")
