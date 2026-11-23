"""The import graph of src/ must have no cycles and respect the layers,
and the storage layer must stay ignorant of the application above it."""

import ast
import re
from collections.abc import Iterator
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src"
VAULT_DIRS = (SRC / "vault", REPO / "test" / "vault")
# A word boundary so that "syntax" passes while "tax", ".tax" and
# "taxtool" are caught.
APPLICATION_WORD = re.compile(r"\btax", re.IGNORECASE)


def module_name(path: Path) -> str:
    rel = path.relative_to(SRC).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def local_imports(path: Path, modules: set[str]) -> Iterator[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
            names += [f"{node.module}.{a.name}" for a in node.names]
        for name in names:
            if name in modules:
                yield name


def import_graph() -> dict[str, set[str]]:
    paths = sorted(SRC.rglob("*.py"))
    modules = {module_name(p) for p in paths}
    graph: dict[str, set[str]] = {}
    for path in paths:
        name = module_name(path)
        deps = set(local_imports(path, modules))
        deps.discard(name)
        graph[name] = deps
    return graph


def find_cycle(graph: dict[str, set[str]]) -> list[str] | None:
    done: set[str] = set()
    stack: list[str] = []

    def visit(node: str) -> list[str] | None:
        if node in stack:
            return stack[stack.index(node) :] + [node]
        if node in done:
            return None
        stack.append(node)
        for dep in sorted(graph.get(node, ())):
            cycle = visit(dep)
            if cycle:
                return cycle
        stack.pop()
        done.add(node)
        return None

    for node in sorted(graph):
        cycle = visit(node)
        if cycle:
            return cycle
    return None


def test_no_import_cycles() -> None:
    cycle = find_cycle(import_graph())
    assert cycle is None, " -> ".join(cycle or [])


def test_vault_does_not_import_taxtool() -> None:
    for name, deps in import_graph().items():
        if name.startswith("vault"):
            bad = {d for d in deps if d.startswith("taxtool")}
            assert not bad, f"{name} imports {sorted(bad)}"


def test_vault_never_mentions_the_application() -> None:
    """The vault could be its own repository: not even the name of the
    directory it lives in may appear in its code or tests."""
    hits: list[str] = []
    for directory in VAULT_DIRS:
        for path in sorted(directory.rglob("*.py")):
            for number, line in enumerate(path.read_text().splitlines(), 1):
                if APPLICATION_WORD.search(line):
                    hits.append(f"{path.relative_to(REPO)}:{number}")
    assert not hits, hits
