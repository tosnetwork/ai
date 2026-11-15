"""Prefix substitution of the former module paths, called by rewrite-imports.sh.

Only tracked files inside the component directories are considered. In Go
files only import declarations are rewritten: a module path in a string
literal is data (for example a repository named in emitted evidence), not an
import, and a pure move must not change it. The rewritten Go files are then
formatted with gofmt, which restores canonical import order.
Hash-pinned data (frozen test vectors, golden files, fixtures, conformance
corpora, release manifests and evidence records) is never rewritten, and
neither are generated protobuf files, whose raw descriptors carry
length-prefixed strings; those are regenerated with the generator instead.
Absolute web links (preceded by "/", as in https://github.com/...) are left
for the link conversion and are not module paths.
"""

import re
import subprocess
import sys
from pathlib import Path

SUBSTITUTIONS = {
    "github.com/tosnetwork/tos-service-protocol": "github.com/tosnetwork/ai/protocol",
    "github.com/tosnetwork/tos-service-gateway": "github.com/tosnetwork/ai/gateway",
    "github.com/tosnetwork/tos-ai": "github.com/tosnetwork/ai/execution",
    "github.com/tosnetwork/tos-messenger": "github.com/tosnetwork/ai/messenger",
}

COMPONENTS = ("spec/", "protocol/", "gateway/", "execution/", "messenger/")

# Hash-pinned or generated paths, by prefix or by path segment.
SKIPPED_PREFIXES = (
    "spec/test-vectors/",
    "spec/deployments/",
    "spec/manifests/",
    "protocol/tests/conformance/",
    "messenger/docs/evidence/",
)
SKIPPED_SEGMENTS = ("testdata", "fixtures", "golden")
SKIPPED_SUFFIXES = (".golden", ".pb.go")

SUFFIXES = (".go", ".proto", ".md", ".yml", ".yaml", ".mk")
NAMES = ("go.mod", "Makefile")

# A module path starts at a boundary that is not part of a URL or a longer
# name and ends at a path boundary, so tos-ai never matches tos-ai-<suffix>.
PATTERN = re.compile(
    r"(?<![\w./-])("
    + "|".join(re.escape(old) for old in sorted(SUBSTITUTIONS, key=len, reverse=True))
    + r")(?=$|[/\"'`\s@);:,\]>])",
    re.MULTILINE,
)
GO_PACKAGE = re.compile(r"^option\s+go_package\s*=", re.MULTILINE)
# One import spec per line: in an import block, or a single import declaration.
GO_IMPORT = re.compile(r'^\s*(?:import\s+)?(?:[A-Za-z_.][A-Za-z0-9_]*\s+)?"[^"]+"\s*(?://.*)?$')


def skipped(path):
    if path.startswith(SKIPPED_PREFIXES) or path.endswith(SKIPPED_SUFFIXES):
        return True
    return any(segment in SKIPPED_SEGMENTS for segment in path.split("/")[:-1])


def selected(path):
    name = path.rsplit("/", 1)[-1]
    return name in NAMES or name.endswith(SUFFIXES)


def rewrite_proto(text):
    lines = text.splitlines(keepends=True)
    count = 0
    for index, line in enumerate(lines):
        if GO_PACKAGE.match(line):
            lines[index], replaced = PATTERN.subn(lambda m: SUBSTITUTIONS[m.group(1)], line)
            count += replaced
    return "".join(lines), count


def rewrite_go(text):
    lines = text.splitlines(keepends=True)
    count = 0
    for index, line in enumerate(lines):
        if GO_IMPORT.match(line):
            lines[index], replaced = PATTERN.subn(lambda m: SUBSTITUTIONS[m.group(1)], line)
            count += replaced
    return "".join(lines), count


def main():
    repo = Path(sys.argv[1])
    listed = subprocess.run(["git", "-C", str(repo), "ls-files", "-z", "--", *COMPONENTS],
                            check=True, stdout=subprocess.PIPE).stdout.decode("utf-8")
    total = 0
    go_files = []
    for path in sorted(filter(None, listed.split("\0"))):
        file = repo / path
        if file.is_symlink() or not file.is_file():
            continue
        if skipped(path):
            content = file.read_bytes()
            if any(old.encode() in content for old in SUBSTITUTIONS):
                print(f"skipped (hash-pinned or generated): {path}")
            continue
        if not selected(path):
            continue
        original = file.read_bytes().decode("utf-8")
        if path.endswith(".proto"):
            rewritten, count = rewrite_proto(original)
        elif path.endswith(".go"):
            rewritten, count = rewrite_go(original)
            if count:
                go_files.append(str(file))
        else:
            rewritten, count = PATTERN.subn(lambda m: SUBSTITUTIONS[m.group(1)], original)
        if count:
            file.write_bytes(rewritten.encode("utf-8"))
            total += count
            print(f"{count:4d} {path}")
    if go_files:
        subprocess.run(["gofmt", "-w", *go_files], check=True)
    left = [line for path in go_files for line in Path(path).read_text(encoding="utf-8").splitlines()
            if PATTERN.search(line) and GO_IMPORT.match(line)]
    if left:
        sys.exit("rewrite left former module paths in import lines:\n" + "\n".join(left))
    print(f"{total} substitutions")


if __name__ == "__main__":
    main()
