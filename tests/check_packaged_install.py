import ast
import importlib.metadata
import os
import tempfile
from pathlib import Path


def read_source_version() -> str:
    source = Path(__file__).resolve().parents[1] / "lib" / "core" / "settings.py"
    module = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    for node in module.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "VERSION":
                    value = ast.literal_eval(node.value)
                    if isinstance(value, str):
                        return value
    raise RuntimeError("Unable to locate VERSION in lib/core/settings.py")


def main() -> None:
    os.chdir(tempfile.mkdtemp(prefix="dirsearch-install-check-"))

    from dirsearch.lib.core import settings

    expected_version = read_source_version()
    installed_version = importlib.metadata.version("dirsearch")
    assert installed_version == expected_version, (installed_version, expected_version)

    package_root = Path(settings.__file__).resolve().parents[2]
    assert (package_root / "config.ini").is_file()
    assert (package_root / "db" / "categories" / "common.txt").is_file()


if __name__ == "__main__":
    main()
