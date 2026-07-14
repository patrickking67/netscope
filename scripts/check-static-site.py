from html.parser import HTMLParser
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

claude = (root / "CLAUDE.md").read_text().strip()
if claude != "@AGENTS.md":
    errors.append("CLAUDE.md must contain only @AGENTS.md")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print(f"Validated {len(html_files)} HTML files and static JavaScript syntax.")
