"""Write the README badge from a completed macOS Go unit test profile."""

import argparse
from pathlib import Path
import re
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path)
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("the README badge uses the macOS test suite")
    result = subprocess.run(
        ["go", "tool", "cover", f"-func={args.profile.resolve()}"],
        cwd=root, check=True, stdout=subprocess.PIPE, text=True,
    )
    functions = [line for line in result.stdout.splitlines() if not line.startswith("total:")]
    if not functions or any(not line.startswith("peertty/") for line in functions):
        parser.error("measure the project with -coverpkg=peertty/...")
    match = re.search(r"^total:\s+\(statements\)\s+(\d+(?:\.\d+)?%)$", result.stdout, re.MULTILINE)
    if not match:
        parser.error("go tool cover did not report a statement total")
    percent = match.group(1)
    title = f"Go unit test coverage on macOS: {percent}"
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="220" height="22" role="img" aria-label="{title}">
  <title>{title}</title>
  <clipPath id="badge"><rect width="220" height="22" rx="5"/></clipPath>
  <g clip-path="url(#badge)">
    <path fill="#242a2e" d="M0 0h164v22H0z"/>
    <path fill="#5cf3c6" d="M164 0h56v22h-56z"/>
  </g>
  <path fill="#5cf3c6" d="M8 12h3v4H8zm5-3h3v7h-3zm5-3h3v10h-3z"/>
  <g font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">
    <text x="27" y="15" fill="#fff">unit coverage · macOS</text>
    <text x="192" y="15" fill="#11231e" text-anchor="middle" font-weight="bold">{percent}</text>
  </g>
</svg>
'''
    (root / "assets" / "coverage.svg").write_text(svg, encoding="utf-8")
    print(title)


if __name__ == "__main__":
    main()
